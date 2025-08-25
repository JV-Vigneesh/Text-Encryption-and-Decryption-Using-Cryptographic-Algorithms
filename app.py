from flask import Flask, render_template, request, jsonify, send_file
import os
import base64
import secrets
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import json
import io

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

class EncryptionService:
    @staticmethod
    def caesar_cipher(text, shift, decrypt=False):
        if decrypt:
            shift = -shift
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                shifted = (ord(char) - ascii_offset + shift) % 26
                result += chr(shifted + ascii_offset)
            else:
                result += char
        return result

    @staticmethod
    def vigenere_cipher(text, key, decrypt=False):
        key = key.upper()
        result = ""
        key_index = 0
        
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - 65
                if decrypt:
                    shift = -shift
                
                ascii_offset = 65 if char.isupper() else 97
                shifted = (ord(char) - ascii_offset + shift) % 26
                result += chr(shifted + ascii_offset)
                key_index += 1
            else:
                result += char
        return result

    @staticmethod
    def base64_encode(text):
        return base64.b64encode(text.encode()).decode()

    @staticmethod
    def base64_decode(text):
        try:
            return base64.b64decode(text.encode()).decode()
        except:
            return "Invalid Base64 input"

    @staticmethod
    def generate_aes_key():
        return Fernet.generate_key().decode()

    @staticmethod
    def aes_encrypt(text, key):
        try:
            f = Fernet(key.encode())
            encrypted = f.encrypt(text.encode())
            return encrypted.decode()
        except:
            return "Invalid key or encryption failed"

    @staticmethod
    def aes_decrypt(text, key):
        try:
            f = Fernet(key.encode())
            decrypted = f.decrypt(text.encode())
            return decrypted.decode()
        except:
            return "Invalid key or decryption failed"

    @staticmethod
    def chacha20_encrypt(text, key=None):
        try:
            if key:
                key_bytes = base64.b64decode(key.encode())
            else:
                key_bytes = get_random_bytes(32)
            
            cipher = ChaCha20.new(key=key_bytes)
            ciphertext = cipher.encrypt(text.encode())
            
            # Return nonce + ciphertext, encoded in base64
            result = base64.b64encode(cipher.nonce + ciphertext).decode()
            if not key:
                key_b64 = base64.b64encode(key_bytes).decode()
                return result, key_b64
            return result
        except Exception as e:
            return f"ChaCha20 encryption failed: {str(e)}"

    @staticmethod
    def chacha20_decrypt(text, key):
        try:
            key_bytes = base64.b64decode(key.encode())
            data = base64.b64decode(text.encode())
            
            nonce = data[:8]  # ChaCha20 nonce is 8 bytes
            ciphertext = data[8:]
            
            cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
            return plaintext.decode()
        except Exception as e:
            return f"ChaCha20 decryption failed: {str(e)}"

    @staticmethod
    def generate_chacha20_key():
        key = get_random_bytes(32)
        return base64.b64encode(key).decode()

    @staticmethod
    def generate_rsa_keypair():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        return {"private_key": private_pem, "public_key": public_pem}

    @staticmethod
    def rsa_encrypt(text, public_key_pem):
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            
            # RSA can only encrypt small amounts of data, so we'll use chunks
            max_chunk_size = 190  # Safe size for 2048-bit RSA key
            chunks = [text[i:i+max_chunk_size] for i in range(0, len(text), max_chunk_size)]
            
            encrypted_chunks = []
            for chunk in chunks:
                encrypted_chunk = public_key.encrypt(
                    chunk.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                encrypted_chunks.append(base64.b64encode(encrypted_chunk).decode())
            
            return json.dumps(encrypted_chunks)
        except Exception as e:
            return f"RSA encryption failed: {str(e)}"

    @staticmethod
    def rsa_decrypt(encrypted_text, private_key_pem):
        try:
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
            
            encrypted_chunks = json.loads(encrypted_text)
            decrypted_chunks = []
            
            for encrypted_chunk in encrypted_chunks:
                encrypted_data = base64.b64decode(encrypted_chunk.encode())
                decrypted_chunk = private_key.decrypt(
                    encrypted_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decrypted_chunks.append(decrypted_chunk.decode())
            
            return ''.join(decrypted_chunks)
        except Exception as e:
            return f"RSA decryption failed: {str(e)}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    algorithm = data.get('algorithm')
    text = data.get('text')
    key = data.get('key', '')
    
    try:
        if algorithm == 'caesar':
            shift = int(key) if key else 3
            result = EncryptionService.caesar_cipher(text, shift)
        elif algorithm == 'vigenere':
            if not key:
                return jsonify({'error': 'Vigenère cipher requires a key'})
            result = EncryptionService.vigenere_cipher(text, key)
        elif algorithm == 'base64':
            result = EncryptionService.base64_encode(text)
        elif algorithm == 'aes':
            if not key:
                return jsonify({'error': 'AES encryption requires a key'})
            result = EncryptionService.aes_encrypt(text, key)
        elif algorithm == 'chacha20':
            if key:
                result = EncryptionService.chacha20_encrypt(text, key)
            else:
                result, generated_key = EncryptionService.chacha20_encrypt(text)
                return jsonify({'result': result, 'generated_key': generated_key})
        elif algorithm == 'rsa':
            if not key:
                return jsonify({'error': 'RSA encryption requires a public key'})
            result = EncryptionService.rsa_encrypt(text, key)
        else:
            return jsonify({'error': 'Invalid algorithm'})
        
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    algorithm = data.get('algorithm')
    text = data.get('text')
    key = data.get('key', '')
    
    try:
        if algorithm == 'caesar':
            shift = int(key) if key else 3
            result = EncryptionService.caesar_cipher(text, shift, decrypt=True)
        elif algorithm == 'vigenere':
            if not key:
                return jsonify({'error': 'Vigenère cipher requires a key'})
            result = EncryptionService.vigenere_cipher(text, key, decrypt=True)
        elif algorithm == 'base64':
            result = EncryptionService.base64_decode(text)
        elif algorithm == 'aes':
            if not key:
                return jsonify({'error': 'AES decryption requires a key'})
            result = EncryptionService.aes_decrypt(text, key)
        elif algorithm == 'chacha20':
            if not key:
                return jsonify({'error': 'ChaCha20 decryption requires a key'})
            result = EncryptionService.chacha20_decrypt(text, key)
        elif algorithm == 'rsa':
            if not key:
                return jsonify({'error': 'RSA decryption requires a private key'})
            result = EncryptionService.rsa_decrypt(text, key)
        else:
            return jsonify({'error': 'Invalid algorithm'})
        
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/generate-key', methods=['POST'])
def generate_key():
    data = request.json
    algorithm = data.get('algorithm')
    
    try:
        if algorithm == 'caesar':
            key = str(secrets.randbelow(25) + 1)
        elif algorithm == 'vigenere':
            length = secrets.randbelow(10) + 5
            key = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(length))
        elif algorithm == 'aes':
            key = EncryptionService.generate_aes_key()
        elif algorithm == 'chacha20':
            key = EncryptionService.generate_chacha20_key()
        elif algorithm == 'rsa':
            keypair = EncryptionService.generate_rsa_keypair()
            return jsonify({'keypair': keypair})
        else:
            return jsonify({'error': 'Key generation not supported for this algorithm'})
        
        return jsonify({'key': key})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/download', methods=['POST'])
def download():
    data = request.json
    content = data.get('content')
    filename = data.get('filename', 'encrypted_text.txt')
    
    buffer = io.BytesIO()
    buffer.write(content.encode())
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype='text/plain'
    )

if __name__ == '__main__':
    app.run(debug=True)