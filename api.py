from flask import Flask, request, jsonify
import re
import json
from datetime import datetime
import secrets
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

def base64url_encode(data):
    """Encode bytes to base64url format"""
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

def parse_adyen_public_key(key_string):
    """Parse Adyen public key from hex format to PEM"""
    try:
        exponent_hex, modulus_hex = key_string.split('|')
        exponent = int(exponent_hex, 16)
        modulus = int(modulus_hex, 16)
        
        # Create RSA public key from numbers
        public_numbers = rsa.RSAPublicNumbers(exponent, modulus)
        public_key = public_numbers.public_key(backend=default_backend())
        
        # Convert to PEM
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem
    except Exception as e:
        raise ValueError(f"Invalid Adyen public key format: {str(e)}")

def encrypt_card_field(field_data, public_key_pem, encoded_header):
    """Encrypt a single card field using Adyen CSE V2"""
    cek = secrets.token_bytes(32)
    
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    
    # Encrypt CEK with RSA-OAEP-256
    encrypted_key = public_key.encrypt(
        cek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encoded_encrypted_key = base64url_encode(encrypted_key)
    
    # Generate IV
    iv = secrets.token_bytes(12)
    encoded_iv = base64url_encode(iv)
    
    # Encrypt data with AES-256-GCM
    aesgcm = AESGCM(cek)
    plaintext = json.dumps(field_data).encode('utf-8')
    header_bytes = encoded_header.encode('ascii')
    
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, header_bytes)
    tag = ciphertext_with_tag[-16:]
    ciphertext = ciphertext_with_tag[:-16]
    
    return f"{encoded_header}.{encoded_encrypted_key}.{encoded_iv}.{base64url_encode(ciphertext)}.{base64url_encode(tag)}"

@app.route('/encode', methods=['GET', 'POST'])
def encode():
    """API endpoint to encrypt card data"""
    try:
        # Get parameters
        if request.method == 'GET':
            adyen_key = request.args.get('key')
            card_data = request.args.get('card')
        else:
            data = request.get_json()
            if not data:
                return jsonify({
                    'error': 'Invalid JSON body',
                    'message': 'Request body must be valid JSON'
                }), 400
            adyen_key = data.get('key')
            card_data = data.get('card')
        
        # Validate required parameters
        if not adyen_key:
            return jsonify({
                'error': 'Missing required parameter: key',
                'message': 'Adyen public key is required'
            }), 400
        
        if not card_data:
            return jsonify({
                'error': 'Missing required parameter: card',
                'message': 'Card data in format: CC|MM|YY|CVV or CC|MM|YYYY|CVV'
            }), 400
        
        # Parse card data
        parts = card_data.split('|')
        if len(parts) != 4:
            return jsonify({
                'error': 'Invalid card format',
                'message': 'Expected format: CC|MM|YY|CVV or CC|MM|YYYY|CVV'
            }), 400
        
        card_number, month, year, cvc = parts
        
        # Clean and validate inputs
        clean_number = re.sub(r'\s+', '', card_number)
        year_clean = re.sub(r'\s+', '', year)
        month_clean = month.strip().zfill(2)
        
        # Validate card number
        if not re.match(r'^\d{13,19}$', clean_number):
            return jsonify({
                'error': 'Invalid card number',
                'message': 'Card number must be 13-19 digits'
            }), 400
        
        # Validate month
        if not re.match(r'^(0[1-9]|1[0-2])$', month_clean):
            return jsonify({
                'error': 'Invalid month',
                'message': 'Month must be 01-12'
            }), 400
        
        # Validate year
        if not re.match(r'^\d{2}$|^\d{4}$', year_clean):
            return jsonify({
                'error': 'Invalid year',
                'message': 'Year must be 2 or 4 digits'
            }), 400
        
        # Validate CVC
        if not re.match(r'^\d{3,4}$', str(cvc).strip()):
            return jsonify({
                'error': 'Invalid CVC',
                'message': 'CVC must be 3-4 digits'
            }), 400
        
        # Parse Adyen key
        try:
            public_key_pem = parse_adyen_public_key(adyen_key)
        except ValueError as e:
            return jsonify({
                'error': 'Invalid Adyen key',
                'message': str(e)
            }), 400
        
        # Format data
        full_year = f"20{year_clean}" if len(year_clean) == 2 else year_clean
        gen_time = datetime.utcnow().isoformat() + 'Z'
        
        # Create header
        header = {"alg": "RSA-OAEP-256", "enc": "A256GCM", "version": "1"}
        encoded_header = base64url_encode(json.dumps(header).encode('utf-8'))
        
        # Encrypt all fields
        result = {
            "number": encrypt_card_field(
                {"number": clean_number, "generationtime": gen_time},
                public_key_pem,
                encoded_header
            ),
            "month": encrypt_card_field(
                {"expiryMonth": month_clean, "generationtime": gen_time},
                public_key_pem,
                encoded_header
            ),
            "year": encrypt_card_field(
                {"expiryYear": full_year, "generationtime": gen_time},
                public_key_pem,
                encoded_header
            ),
            "cvc": encrypt_card_field(
                {"cvc": cvc.strip(), "generationtime": gen_time},
                public_key_pem,
                encoded_header
            ),
            "generationtime": gen_time
        }
        
        return jsonify({
            'success': True,
            'data': result
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': 'Encryption failed',
            'message': str(e)
        }), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Adyen Encryption API',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }), 200

@app.route('/', methods=['GET'])
def index():
    """Root endpoint with usage instructions"""
    return jsonify({
        'service': 'Adyen Encryption API',
        'version': '1.0.0',
        'endpoints': {
            '/encode': {
                'method': 'GET or POST',
                'params': {
                    'key': 'Adyen public key (format: exponent|modulus)',
                    'card': 'Card data in format: CC|MM|YY|CVV or CC|MM|YYYY|CVV'
                },
                'example_get': '/encode?key=10001|DBF7...&card=4111111111111111|12|26|123',
                'example_post': 'POST /encode with JSON body: {"key": "10001|DBF7...", "card": "4111111111111111|12|26|123"}'
            },
            '/health': {
                'method': 'GET',
                'description': 'Health check endpoint'
            }
        }
    }), 200

# For VERCEL serverless
def handler(request, context):
    return app(request.environ, context)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
