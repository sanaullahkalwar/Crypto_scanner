"""
Cryptographic implementation detector
"""

import re
from pathlib import Path
from typing import List, Dict

class CryptoDetector:
    """Detects cryptographic usage in source code"""
    
    def __init__(self):
        # Cryptographic libraries and functions to detect
        self.crypto_patterns = {
            'python': {
                'hashlib': ['md5', 'sha1', 'sha256', 'sha512', 'pbkdf2_hmac', 'scrypt'],
                'cryptography': ['fernet', 'hazmat', 'x509', 'rsa', 'ec', 'dsa'],
                'hmac': ['new', 'digest'],
                'base64': ['b64encode', 'b64decode'],
                'secrets': ['token_bytes', 'token_hex', 'token_urlsafe', 'compare_digest'],
                'os.urandom': ['urandom'],
                'Crypto.Cipher': ['AES', 'DES', 'Blowfish', 'ARC4', 'PKCS1_v1_5', 'ChaCha20'],
                'Crypto.Hash': ['MD5', 'SHA1', 'SHA256', 'SHA512', 'SHA3_256', 'BLAKE2'],
                'Crypto.PublicKey': ['RSA', 'DSA', 'ECC', 'Curve25519'],
                'Crypto.Protocol': ['KDF'],
                'pqcrypto': ['kyber', 'dilithium', 'sphincs', 'ntru', 'mceliece'],
            },
            'javascript': {
                'crypto.subtle': ['encrypt', 'decrypt', 'digest', 'generateKey', 'deriveKey'],
                'crypto.createHash': ['md5', 'sha1', 'sha256', 'sha512'],
                'crypto.createCipher': ['aes', 'des', 'rc4'],
                'bcrypt': ['hash', 'compare', 'genSalt'],
                'jsonwebtoken': ['sign', 'verify'],
                'node-forge': ['pki', 'cipher', 'md', 'random'],
                'libsodium': ['crypto_box', 'crypto_secretbox', 'crypto_sign'],
            },
            'java': {
                'javax.crypto': ['Cipher', 'KeyGenerator', 'Mac', 'SecretKey'],
                'java.security': ['MessageDigest', 'Signature', 'KeyPairGenerator', 'SecureRandom'],
                'org.bouncycastle': ['crypto', 'openssl', 'pqc'],
            },
            'rust': {
                'ring': ['digest', 'hmac', 'pbkdf2', 'aead'],
                'sodiumoxide': ['crypto', 'box', 'secretbox'],
                'rust-crypto': ['aes', 'sha2', 'ed25519'],
            },
            'generic': {
                'weak_algorithms': ['MD4', 'MD5', 'SHA-1', 'SHA1', 'RC4', 'DES', '3DES'],
                'quantum_safe': ['kyber', 'dilithium', 'sphincs', 'ntru', 'mceliece', 
                               'frodo', 'sike', 'bike', 'hqc', 'classic mceliece'],
                'deprecated_functions': ['RSA_generate_key', 'DH_generate_parameters'],
            }
        }
        
        # File extensions by language
        self.file_extensions = {
            'python': ['.py', '.pyw'],
            'javascript': ['.js', '.jsx', '.ts', '.tsx', '.mjs'],
            'java': ['.java', '.kt', '.kts'],
            'rust': ['.rs'],
            'crypto_config': ['.pem', '.crt', '.key', '.cert', '.p12', '.pfx', '.jks']
        }
    
    def detect_crypto_in_file(self, file_path: Path) -> List[Dict]:
        """Detect cryptographic patterns in a file"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return findings
        
        # Determine language based on extension
        file_ext = file_path.suffix.lower()
        language = self.get_language(file_ext)
        
        # Generic pattern matching
        generic_findings = self.scan_generic_patterns(content, file_path)
        findings.extend(generic_findings)
        
        # Language-specific scanning
        if language in self.crypto_patterns:
            lang_findings = self.scan_language_patterns(content, file_path, language)
            findings.extend(lang_findings)
        
        # Check for cryptographic configuration files
        if file_ext in ['.pem', '.crt', '.key']:
            findings.append({
                'type': 'crypto_key_file',
                'file': str(file_path),
                'severity': 'high',
                'message': 'Cryptographic key or certificate file found'
            })
        
        return findings
    
    def get_language(self, extension: str) -> str:
        """Determine programming language from file extension"""
        for lang, extensions in self.file_extensions.items():
            if extension in extensions:
                return lang
        return 'unknown'
    
    def scan_generic_patterns(self, content: str, file_path: Path) -> List[Dict]:
        """Scan for generic cryptographic patterns"""
        findings = []
        
        # Check for weak algorithms
        for algo in self.crypto_patterns['generic']['weak_algorithms']:
            pattern = re.compile(r'\b' + algo + r'\b', re.IGNORECASE)
            matches = pattern.finditer(content)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                findings.append({
                    'type': 'weak_algorithm',
                    'file': str(file_path),
                    'line': line_no,
                    'algorithm': algo,
                    'severity': 'high',
                    'message': f'Weak cryptographic algorithm detected: {algo}'
                })
        
        # Check for quantum-safe algorithms
        for algo in self.crypto_patterns['generic']['quantum_safe']:
            pattern = re.compile(r'\b' + algo + r'\b', re.IGNORECASE)
            matches = pattern.finditer(content)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                findings.append({
                    'type': 'quantum_safe_algorithm',
                    'file': str(file_path),
                    'line': line_no,
                    'algorithm': algo,
                    'severity': 'info',
                    'message': f'Post-quantum cryptographic algorithm detected: {algo}'
                })
        
        # Check for hardcoded keys
        key_patterns = [
            (r'(password|passwd|pwd|secret|key|token|api_key)\s*=\s*["\'][^"\']+["\']', 'credential'),
            (r'-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----', 'private_key'),
        ]
        
        for pattern, key_type in key_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                findings.append({
                    'type': f'hardcoded_{key_type}',
                    'file': str(file_path),
                    'line': line_no,
                    'severity': 'critical' if key_type == 'private_key' else 'high',
                    'message': f'Hardcoded {key_type} found'
                })
        
        # Check for insecure random
        insecure_random = re.finditer(r'\b(random\.(randint|random|choice|shuffle))\b', content)
        for match in insecure_random:
            line_no = content[:match.start()].count('\n') + 1
            findings.append({
                'type': 'insecure_random',
                'file': str(file_path),
                'line': line_no,
                'severity': 'medium',
                'message': 'Insecure random number generator used. Use secrets module instead.'
            })
        
        return findings
    
    def scan_language_patterns(self, content: str, file_path: Path, language: str) -> List[Dict]:
        """Scan for language-specific cryptographic patterns"""
        findings = []
        
        for library, functions in self.crypto_patterns[language].items():
            for func in functions:
                pattern = re.compile(r'\b' + re.escape(library) + r'\.' + re.escape(func) + r'\b')
                matches = pattern.finditer(content)
                for match in matches:
                    line_no = content[:match.start()].count('\n') + 1
                    findings.append({
                        'type': 'crypto_usage',
                        'file': str(file_path),
                        'line': line_no,
                        'library': library,
                        'function': func,
                        'language': language,
                        'message': f'Cryptographic function used: {library}.{func}'
                    })
        
        return findings