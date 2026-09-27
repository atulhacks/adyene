from flask import Flask, request, jsonify
import re
import json
import base64
import secrets
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM
from cryptography.hazmat.backends import default_backend

import requests

app = Flask(__name__)

CSE_PREFIX = "adyenjs_0_1_25"


# ────────────────────────────────────────────────────────────────────────────
#  Base helpers
# ────────────────────────────────────────────────────────────────────────────
def base64url_encode(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def parse_adyen_public_key(key_string):
    """Parse an Adyen public key (exp|mod hex) into a PEM string."""
    exponent_hex, modulus_hex = key_string.split("|")
    exponent = int(exponent_hex, 16)
    modulus = int(modulus_hex, 16)
    public_numbers = rsa.RSAPublicNumbers(exponent, modulus)
    public_key = public_numbers.public_key(backend=default_backend())
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_pub(pem):
    return serialization.load_pem_public_key(pem, backend=default_backend())


def detect_brand(number):
    """Map a card number to its scheme brand."""
    cn = str(number).strip()
    if cn.startswith("4"):
        return "visa"
    if cn.startswith(("51", "52", "53", "54", "55", "22", "23", "24", "25", "26", "27")):
        return "mc"
    if cn.startswith(("34", "37")):
        return "amex"
    if cn.startswith(("6011", "65", "644", "645")):
        return "discover"
    if len(cn) >= 4 and "3528" <= cn[:4] <= "3589":
        return "jcb"
    return "scheme"


# ────────────────────────────────────────────────────────────────────────────
#  Encryption: JWE v6 (RSA-OAEP-256 + A256GCM) and legacy CSE (RSA PKCS#1 v1.5 + AES-CCM)
# ────────────────────────────────────────────────────────────────────────────
def jwe_header_b64():
    header = {"cty": "application/json", "alg": "RSA-OAEP-256", "enc": "A256GCM", "version": "1"}
    return base64url_encode(json.dumps(header, separators=(",", ":")).encode())


def encrypt_field_jwe(field_name, field_value, pub, header_b64):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    payload = json.dumps({field_name: field_value, "generationtime": ts}, separators=(",", ":")).encode()

    cek = secrets.token_bytes(32)
    enc_cek = pub.encrypt(
        cek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    iv = secrets.token_bytes(12)
    ct_tag = AESGCM(cek).encrypt(iv, payload, header_b64.encode())
    ct, tag = ct_tag[:-16], ct_tag[-16:]

    return ".".join([
        header_b64,
        base64url_encode(enc_cek),
        base64url_encode(iv),
        base64url_encode(ct),
        base64url_encode(tag),
    ])


def encrypt_field_cse(field_name, field_value, pub):
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    plain = f"{field_name}:{field_value}\ngenerationtime:{gen}".encode()

    aes_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    ct_tag = AESCCM(aes_key, tag_length=8).encrypt(nonce, plain, None)
    enc_key = pub.encrypt(aes_key, padding.PKCS1v15())

    blob = enc_key + nonce + ct_tag
    return f"{CSE_PREFIX}${base64.b64encode(blob).decode()}"


# ────────────────────────────────────────────────────────────────────────────
#  Config extraction + public key fetch
# ────────────────────────────────────────────────────────────────────────────
_CK = [
    r"clientKey[\"'\s:=]+[\"']?(live_[A-Za-z0-9_]+|test_[A-Za-z0-9_]+)",
    r"data-client-key=[\"']?(live_[A-Za-z0-9_]+|test_[A-Za-z0-9_]+)",
]
_SI = [
    r'"sessionId"\s*:\s*"([A-Za-z0-9_-]{15,})"',
    r"'sessionId'\s*:\s*'([A-Za-z0-9_-]{15,})'",
    r"sessionId[\"'\s:=]+[\"']?([A-Za-z0-9_-]{15,})",
]
_SD = [
    r'"sessionData"\s*:\s*"([^"]{40,})"',
    r"'sessionData'\s*:\s*'([^']{40,})'",
    r"sessionData[\"'\s:=]+[\"']?([^\"'\s,}{]+)",
]
_PK = [
    r'"publicKey"\s*:\s*"([0-9a-fA-F]+\|[0-9a-fA-F]+)"',
    r"'publicKey'\s*:\s*'([0-9a-fA-F]+\|[0-9a-fA-F]+)'",
    r"publicKey[\"'\s:=]+[\"']?([0-9a-fA-F]+\|[0-9a-fA-F]+)",
]
_LI = [
    r'"linkId"\s*:\s*"([A-Za-z0-9]+)"',
    r"'linkId'\s*:\s*'([A-Za-z0-9]+)'",
    r"linkId[\"\s:'=]+[\"']?([A-Za-z0-9]{20,})",
    r"adyen\.link/([A-Za-z0-9]{20,})",
]
_LC = [
    r'"loadingContext"\s*:\s*"([^"]+)"',
    r"'loadingContext'\s*:\s*'([^']+)'",
]
_ADYEN_SIGNALS = [
    "adyen.com", "adyen.link", "AdyenCheckout", "adyen-checkout", "adyenjs",
    "checkoutshopper", "adyen.encrypt", "adyen-encrypted", "paybylink",
]


def _first_match(patterns, text):
    for p in patterns:
        m = re.search(p, text)
        if m:
            return m.group(1)
    return None


def extract_config(html):
    cfg = {
        "adyen": False, "clientKey": None, "sessionId": None, "sessionData": None,
        "publicKey": None, "environment": None, "linkId": None, "loadingContext": None,
    }
    low = html.lower()
    for sig in _ADYEN_SIGNALS:
        if sig.lower() in low:
            cfg["adyen"] = True
            break
    cfg["clientKey"] = _first_match(_CK, html)
    cfg["sessionId"] = _first_match(_SI, html)
    sd = _first_match(_SD, html)
    if sd:
        cfg["sessionData"] = sd.replace(r"\/", "/").replace("\\/", "/")
    cfg["publicKey"] = _first_match(_PK, html)
    cfg["linkId"] = _first_match(_LI, html)
    cfg["loadingContext"] = _first_match(_LC, html)
    if cfg["clientKey"]:
        cfg["environment"] = "live" if cfg["clientKey"].startswith("live_") else "test"
    return cfg


def _adyen_base(env):
    return f"https://checkoutshopper-{env or 'live'}.adyen.com/checkoutshopper"


def fetch_pubkey(client_key, env):
    for ver in ("v1", "v2"):
        url = f"{_adyen_base(env)}/{ver}/clientKeys/{client_key}"
        try:
            r = requests.get(url, timeout=10)
            if r.ok:
                d = r.json()
                if isinstance(d, dict) and d.get("publicKey"):
                    return d["publicKey"]
        except Exception:
            continue
    return None


# ────────────────────────────────────────────────────────────────────────────
#  Decline-code mapping
# ────────────────────────────────────────────────────────────────────────────
DECLINE_MAP = {
    "Refused": "refused",
    "Declined": "declined",
    "Not enough balance": "insufficient_funds",
    "Insufficient Funds": "insufficient_funds",
    "Expired Card": "expired_card",
    "Invalid Card Number": "invalid_number",
    "CVC Declined": "incorrect_cvc",
    "Invalid CVC": "incorrect_cvc",
    "Restricted Card": "restricted_card",
    "3d-secure": "3ds_required",
    "Blocked Card": "blocked_card",
    "Acquirer Fraud": "fraud",
    "Issuer Suspected Fraud": "fraud_suspected",
    "Not Permitted": "not_permitted",
    "Revocation Of Auth": "revoked",
    "Pin validation not possible": "pin_error",
    "Referral": "referral",
    "Shopper Cancelled": "cancelled",
    "Invalid Pin": "invalid_pin",
    "Pin tries exceeded": "pin_exceeded",
    "Withdrawal amount exceeded": "limit_exceeded",
    "Issuer Unavailable": "issuer_unavailable",
    "Not Submitted": "not_submitted",
}
REFUSAL_CODE_MAP = {
    "2": "insufficient_funds",
    "3": "referral",
    "5": "blocked_card",
    "6": "expired_card",
    "8": "invalid_number",
    "10": "incorrect_cvc",
    "12": "not_permitted",
    "14": "invalid_expiry",
    "15": "revoked",
    "17": "declined",
    "18": "fraud",
    "21": "issuer_unavailable",
}
LIVE_DECLINE = {
    "insufficient_funds", "incorrect_cvc", "3ds_required", "challenge_required",
    "pin_error", "invalid_pin", "pin_exceeded", "limit_exceeded", "not_permitted",
    "restricted_card", "referral", "issuer_unavailable",
}


def parse_adyen_response(data):
    if not isinstance(data, dict):
        return {"error": "Non-dict response", "decline_code": "parse_error"}

    result = {"success": False, "decline_code": None, "error": None}
    if data.get("pspReference"):
        result["psp"] = data["pspReference"]

    rc = data.get("resultCode", "")
    if not rc and data.get("status"):
        rc = str(data.get("status"))
    if not rc and ("refusalReason" in data or "refusalReasonCode" in data):
        rc = "Refused"

    if rc == "Authorised":
        result["success"] = True
        result["decline_code"] = "authorised"
        result["error"] = "Authorised"
        return result

    if rc in ("Received", "Pending", "AuthenticationFinished"):
        result["decline_code"] = "pending"
        result["error"] = f"Payment {rc}"
        return result

    if rc in ("RedirectShopper", "IdentifyShopper", "ChallengeShopper"):
        result["decline_code"] = "3ds_required"
        result["error"] = f"3DS ({rc})"
        result["is_live"] = True
        return result

    if rc == "Refused" or "refusalReason" in data or "refusalReasonCode" in data:
        reason = data.get("refusalReason", "Refused")
        rcode = str(data.get("refusalReasonCode", ""))
        mapped = REFUSAL_CODE_MAP.get(rcode) or DECLINE_MAP.get(reason, reason.lower().replace(" ", "_"))
        result["decline_code"] = mapped
        result["error"] = f"{reason} ({rcode})" if rcode else reason
        result["is_live"] = mapped in LIVE_DECLINE
        return result

    if "errorCode" in data or "message" in data:
        msg = data.get("message") or data.get("errorCode") or "error"
        err_code = str(data.get("errorCode", "error"))
        result["decline_code"] = err_code
        result["error"] = f"{msg} ({err_code})"
        return result

    result["decline_code"] = rc.lower() if rc else "unknown"
    result["error"] = f"Adyen: {rc or 'Unknown'}"
    return result


# ────────────────────────────────────────────────────────────────────────────
#  Endpoints
# ────────────────────────────────────────────────────────────────────────────
@app.route("/encode", methods=["GET", "POST"])
def encode():
    try:
        if request.method == "GET":
            adyen_key = request.args.get("key")
            card_data = request.args.get("card")
            mode = (request.args.get("mode") or "jwe").lower()
        else:
            data = request.get_json()
            if not data:
                return jsonify({"error": "Invalid JSON body"}), 400
            adyen_key = data.get("key")
            card_data = data.get("card")
            mode = (data.get("mode") or "jwe").lower()

        if not adyen_key:
            return jsonify({"error": "Missing required parameter: key"}), 400
        if not card_data:
            return jsonify({"error": "Missing required parameter: card"}), 400
        if mode not in ("jwe", "cse"):
            return jsonify({"error": "Invalid mode", "message": "mode must be 'jwe' or 'cse'"}), 400

        parts = card_data.split("|")
        if len(parts) != 4:
            return jsonify({"error": "Invalid card format", "message": "Expected CC|MM|YY|CVV or CC|MM|YYYY|CVV"}), 400

        card_number, month, year, cvc = parts
        clean_number = re.sub(r"\s+", "", card_number)
        year_clean = re.sub(r"\s+", "", year)
        month_clean = month.strip().zfill(2)

        if not re.match(r"^\d{13,19}$", clean_number):
            return jsonify({"error": "Invalid card number", "message": "13-19 digits"}), 400
        if not re.match(r"^(0[1-9]|1[0-2])$", month_clean):
            return jsonify({"error": "Invalid month", "message": "01-12"}), 400
        if not re.match(r"^\d{2}$|^\d{4}$", year_clean):
            return jsonify({"error": "Invalid year", "message": "2 or 4 digits"}), 400
        if not re.match(r"^\d{3,4}$", str(cvc).strip()):
            return jsonify({"error": "Invalid CVC", "message": "3-4 digits"}), 400

        try:
            pub = load_pub(parse_adyen_public_key(adyen_key))
        except ValueError as e:
            return jsonify({"error": "Invalid Adyen key", "message": str(e)}), 400

        full_year = f"20{year_clean}" if len(year_clean) == 2 else year_clean

        if mode == "cse":
            enc = {
                "encryptedCardNumber": encrypt_field_cse("number", clean_number, pub),
                "encryptedExpiryMonth": encrypt_field_cse("expiryMonth", month_clean, pub),
                "encryptedExpiryYear": encrypt_field_cse("expiryYear", full_year, pub),
                "encryptedSecurityCode": encrypt_field_cse("cvc", cvc.strip(), pub),
            }
        else:
            hb = jwe_header_b64()
            enc = {
                "encryptedCardNumber": encrypt_field_jwe("number", clean_number, pub, hb),
                "encryptedExpiryMonth": encrypt_field_jwe("expiryMonth", month_clean, pub, hb),
                "encryptedExpiryYear": encrypt_field_jwe("expiryYear", full_year, pub, hb),
                "encryptedSecurityCode": encrypt_field_jwe("cvc", cvc.strip(), pub, hb),
            }

        return jsonify({
            "success": True,
            "mode": mode,
            "brand": detect_brand(clean_number),
            "data": enc,
        }), 200

    except Exception as e:
        return jsonify({"error": "Encryption failed", "message": str(e)}), 500


@app.route("/extract", methods=["POST"])
def extract():
    data = request.get_json(silent=True) or {}
    html = data.get("html") or ""
    url = data.get("url") or ""

    if not html and url:
        try:
            html = requests.get(url, timeout=12).text
        except Exception as e:
            return jsonify({"error": "Failed to fetch URL", "message": str(e)}), 400

    if not html:
        return jsonify({"error": "Missing 'html' or 'url'"}), 400

    return jsonify({"success": True, "data": extract_config(html)}), 200


@app.route("/pubkey", methods=["GET"])
def pubkey():
    client_key = request.args.get("clientKey") or request.args.get("client_key")
    env = (request.args.get("env") or "live").lower()
    if not client_key:
        return jsonify({"error": "Missing clientKey"}), 400
    if not re.match(r"^(live|test)_[A-Za-z0-9_]+$", client_key):
        return jsonify({"error": "Invalid clientKey"}), 400
    pk = fetch_pubkey(client_key, env)
    if not pk:
        return jsonify({"error": "publicKey not found", "message": "clientKey may be invalid or env wrong"}), 404
    return jsonify({"success": True, "clientKey": client_key, "environment": env, "publicKey": pk}), 200


@app.route("/parse", methods=["POST"])
def parse():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON body"}), 400
    return jsonify({"success": True, "data": parse_adyen_response(data)}), 200


@app.route("/brand", methods=["GET"])
def brand():
    number = request.args.get("number") or request.args.get("card") or ""
    number = re.sub(r"\s+", "", number)
    if not re.match(r"^\d{13,19}$", number):
        return jsonify({"error": "Invalid card number", "message": "13-19 digits"}), 400
    return jsonify({"success": True, "number": number, "brand": detect_brand(number)}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "Adyen Encryption API",
        "modes": ["jwe", "cse"],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }), 200


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "Adyen Encryption API",
        "version": "2.0.0",
        "endpoints": {
            "/encode": "encrypt card data (mode=jwe|cse)",
            "/extract": "extract clientKey/session/publicKey from checkout HTML",
            "/pubkey": "fetch publicKey from a clientKey",
            "/parse": "map an Adyen payment response to a decline code",
            "/brand": "detect card brand from a number",
            "/health": "health check",
        },
    }), 200


# For VERCEL serverless
def handler(request, context):
    return app(request.environ, context)


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
