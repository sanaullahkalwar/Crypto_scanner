"""
Advanced Cryptographic Implementation Detector
Real-time pattern matching with context awareness
"""

import re
import ast
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple
from datetime import datetime

class CryptoDetector:
    """Advanced detection of cryptographic usage in source code"""
    
    def __init__(self):
        # Comprehensive crypto patterns with context
        self.crypto_patterns = {
            'python': {
                'hashlib': {
                    'functions': ['md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'blake2b', 'pbkdf2_hmac', 'scrypt'],
                    'severity_map': {
                        'md5': 'critical',
                        'sha1': 'high',
                        'sha256': 'safe',
                        'sha512': 'safe',
                        'sha3_256': 'safe',
                        'blake2b': 'safe',
                        'pbkdf2_hmac': 'safe',
                        'scrypt': 'safe'
                    }
                },
                'cryptography.hazmat': {
                    'functions': ['primitives', 'backends', 'ciphers', 'hashes', 'kdf'],
                    'severity': 'info'
                },
                'cryptography.fernet': {
                    'functions': ['Fernet', 'MultiFernet'],
                    'severity': 'safe'
                },
                'Crypto.Cipher': {
                    'functions': ['AES', 'DES', 'DES3', 'Blowfish', 'ARC4', 'ChaCha20', 'Salsa20'],
                    'severity_map': {
                        'AES': 'safe',
                        'DES': 'critical',
                        'DES3': 'medium',
                        'Blowfish': 'medium',
                        'ARC4': 'critical',
                        'ChaCha20': 'safe',
                        'Salsa20': 'safe'
                    }
                },
                'Crypto.PublicKey': {
                    'functions': ['RSA', 'DSA', 'ECC', 'Ed25519', 'Curve25519'],
                    'severity_map': {
                        'RSA': 'info',
                        'DSA': 'medium',
                        'ECC': 'safe',
                        'Ed25519': 'safe',
                        'Curve25519': 'safe'
                    }
                },
                'pqcrypto': {
                    'functions': ['Kyber512', 'Kyber768', 'Kyber1024', 'Dilithium2', 'Dilithium3', 'Dilithium5', 'SPHINCS+', 'Falcon'],
                    'severity': 'quantum_safe'
                }
            },
            'javascript': {
                'crypto': {
                    'functions': ['createHash', 'createCipher', 'createDecipher', 'createSign', 'createVerify', 'randomBytes', 'pbkdf2', 'scrypt'],
                    'severity_map': {
                        'createHash': 'info',
                        'createCipher': 'info',
                        'pbkdf2': 'safe',
                        'scrypt': 'safe',
                        'randomBytes': 'safe'
                    }
                },
                'crypto.subtle': {
                    'functions': ['encrypt', 'decrypt', 'digest', 'generateKey', 'deriveKey', 'importKey', 'exportKey'],
                    'severity': 'safe'
                }
            }
        }
        
        # Patterns for hardcoded secrets
        self.secret_patterns = [
            (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,}["\']', 'critical', 'API key exposed'),
            (r'(?:secret[_-]?key|secretkey)\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,}["\']', 'critical', 'Secret key exposed'),
            (r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{3,}["\']', 'high', 'Hardcoded password'),
            (r'(?:private[_-]?key|privatekey)\s*[:=]\s*["\']-----BEGIN', 'critical', 'Private key in source code'),
            (r'(?:jwt[_-]?secret|jwtsecret)\s*[:=]\s*["\'][^"\']+["\']', 'high', 'JWT secret exposed'),
            (r'(?:aws[_-]?secret|awssecret)\s*[:=]\s*["\'][^"\']+["\']', 'critical', 'AWS secret exposed'),
            (r'(?:token|auth[_-]?token)\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{20,}["\']', 'high', 'Authentication token exposed'),
        ]
        
        # Insecure practices
        self.insecure_patterns = [
            (r'\bMath\.random\b', 'medium', 'Math.random() is not cryptographically secure'),
            (r'\brandom\.(?:randint|random|choice|shuffle)\b', 'medium', 'Use secrets module for cryptographic operations'),
            (r'\bECB\b', 'high', 'ECB mode is insecure - use CBC or GCM'),
            (r'\bCBC\b(?!.*hmac)', 'low', 'CBC mode without HMAC may be vulnerable to padding oracle attacks'),
            (r'key\s*=\s*b["\'][^"\']{1,16}["\']', 'critical', 'Encryption key too short (less than 16 bytes)'),
            (r'RSA\.generate\s*\(\s*1024\s*\)', 'high', 'RSA-1024 is weak - use at least 2048 bits'),
        ]

    def detect_crypto_in_file(self, file_path: Path) -> List[Dict]:
        """Detect cryptographic patterns with context"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return findings
        
        file_ext = file_path.suffix.lower()
        language = self._get_language(file_ext)
        
        # Get file hash for tracking
        file_hash = hashlib.sha256(content.encode()).hexdigest()[:8]
        
        # 1. Check for cryptographic library usage
        if language in self.crypto_patterns:
            lang_findings = self._scan_language_patterns(content, lines, file_path, language, file_hash)
            findings.extend(lang_findings)
        
        # 2. Check for hardcoded secrets
        secret_findings = self._scan_secrets(content, lines, file_path, file_hash)
        findings.extend(secret_findings)
        
        # 3. Check for insecure practices
        practice_findings = self._scan_insecure_practices(content, lines, file_path, file_hash)
        findings.extend(practice_findings)
        
        # 4. Analyze code structure for Python files
        if language == 'python':
            ast_findings = self._analyze_python_ast(content, file_path, file_hash)
            findings.extend(ast_findings)
        
        # 5. Check for crypto configuration files
        if file_ext in ['.pem', '.crt', '.key', '.cert', '.p12', '.pfx', '.jks']:
            findings.append({
                'type': 'crypto_key_file',
                'file': str(file_path),
                'file_hash': file_hash,
                'severity': 'high',
                'message': f'Cryptographic key/certificate file found: {file_path.name}',
                'recommendation': 'Ensure proper access controls and encryption for key files'
            })
        
        return findings
    
    def _get_language(self, extension: str) -> str:
        """Determine programming language"""
        lang_map = {
            '.py': 'python', '.pyw': 'python',
            '.js': 'javascript', '.jsx': 'javascript', '.ts': 'javascript', '.tsx': 'javascript',
            '.java': 'java', '.kt': 'java',
            '.rs': 'rust',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php'
        }
        return lang_map.get(extension, 'unknown')
    
    def _scan_language_patterns(self, content: str, lines: List[str], file_path: Path, language: str, file_hash: str) -> List[Dict]:
        """Scan for language-specific cryptographic patterns"""
        findings = []
        
        for library, lib_data in self.crypto_patterns[language].items():
            functions = lib_data.get('functions', [])
            severity_map = lib_data.get('severity_map', {})
            default_severity = lib_data.get('severity', 'info')
            
            for func in functions:
                # Multiple pattern variations
                patterns = [
                    rf'\b{re.escape(library)}\.{re.escape(func)}\b',
                    rf'from\s+{re.escape(library)}\s+import\s+.*\b{re.escape(func)}\b',
                    rf'import\s+{re.escape(library)}\.?\b{re.escape(func)}\b',
                ]
                
                for pattern in patterns:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        line_no = content[:match.start()].count('\n') + 1
                        context = self._get_context(lines, line_no)
                        
                        severity = severity_map.get(func, default_severity)
                        
                        findings.append({
                            'type': 'crypto_usage',
                            'file': str(file_path),
                            'file_hash': file_hash,
                            'line': line_no,
                            'library': library,
                            'function': func,
                            'language': language,
                            'severity': severity,
                            'context': context,
                            'message': self._get_crypto_message(library, func, severity),
                            'recommendation': self._get_recommendation(func, severity)
                        })
        
        return findings
    
    def _scan_secrets(self, content: str, lines: List[str], file_path: Path, file_hash: str) -> List[Dict]:
        """Scan for hardcoded secrets"""
        findings = []
        
        for pattern, severity, message in self.secret_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_no)
                
                # Mask the actual secret in the context
                masked_context = re.sub(r'["\'][^"\']+["\']', '"***MASKED***"', context) if context else ''
                
                findings.append({
                    'type': 'hardcoded_secret',
                    'file': str(file_path),
                    'file_hash': file_hash,
                    'line': line_no,
                    'severity': severity,
                    'context': masked_context,
                    'message': message,
                    'recommendation': 'Use environment variables or a secure vault (HashiCorp Vault, AWS Secrets Manager)'
                })
        
        return findings
    
    def _scan_insecure_practices(self, content: str, lines: List[str], file_path: Path, file_hash: str) -> List[Dict]:
        """Scan for insecure cryptographic practices"""
        findings = []
        
        for pattern, severity, message in self.insecure_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_no)
                
                findings.append({
                    'type': 'insecure_practice',
                    'file': str(file_path),
                    'file_hash': file_hash,
                    'line': line_no,
                    'severity': severity,
                    'context': context,
                    'message': message,
                    'recommendation': self._get_practice_recommendation(message)
                })
        
        return findings
    
    def _analyze_python_ast(self, content: str, file_path: Path, file_hash: str) -> List[Dict]:
        """Analyze Python code using AST for deeper insights"""
        findings = []
        
        try:
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                # Check for insecure hash usage
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        if hasattr(node.func.value, 'id'):
                            if node.func.value.id == 'hashlib':
                                if node.func.attr in ['md5', 'sha1']:
                                    findings.append({
                                        'type': 'ast_analysis',
                                        'file': str(file_path),
                                        'file_hash': file_hash,
                                        'line': node.lineno,
                                        'severity': 'critical' if node.func.attr == 'md5' else 'high',
                                        'message': f'AST Analysis: Detected insecure {node.func.attr}() usage',
                                        'recommendation': f'Replace {node.func.attr}() with SHA-256 or SHA-3'
                                    })
        except:
            pass
        
        return findings
    
    def _get_context(self, lines: List[str], line_no: int, context_lines: int = 2) -> str:
        """Get surrounding context for a finding"""
        start = max(0, line_no - context_lines - 1)
        end = min(len(lines), line_no + context_lines)
        context = lines[start:end]
        return '\n'.join(context)
    
    def _get_crypto_message(self, library: str, function: str, severity: str) -> str:
        """Generate descriptive message based on crypto usage"""
        messages = {
            'md5': 'MD5 hash detected - cryptographically broken since 2004',
            'sha1': 'SHA-1 detected - vulnerable to collision attacks (SHAttered)',
            'sha256': 'SHA-256 detected - currently secure',
            'sha512': 'SHA-512 detected - currently secure',
            'sha3_256': 'SHA-3 detected - modern and secure',
            'AES': 'AES encryption detected - secure if properly implemented',
            'DES': 'DES detected - insecure 56-bit key, brute-forceable',
            'RC4': 'RC4 detected - multiple vulnerabilities, forbidden by RFC 7465',
        }
        return messages.get(function, f'Cryptographic function detected: {library}.{function}')
    
    def _get_recommendation(self, function: str, severity: str) -> str:
        """Get specific recommendations based on finding"""
        recommendations = {
            'md5': 'Replace MD5 with SHA-256, SHA-3, or BLAKE2. MD5 is vulnerable to collision attacks.',
            'sha1': 'Upgrade to SHA-256 or SHA-3. SHA-1 is deprecated for security applications.',
            'DES': 'Migrate to AES-256-GCM. DES can be cracked in hours.',
            'RC4': 'Use AES-GCM or ChaCha20-Poly1305 instead.',
            'sha256': 'SHA-256 is secure. Consider SHA-3 for new implementations.',
            'Kyber512': 'Post-quantum algorithm detected. Ensure proper implementation and NIST compliance.',
        }
        return recommendations.get(function, 'Review implementation for security best practices')
    
    def _get_practice_recommendation(self, issue: str) -> str:
        """Get recommendations for insecure practices"""
        if 'Math.random' in issue:
            return 'Use crypto.getRandomValues() in browser or crypto.randomBytes() in Node.js'
        elif 'random.randint' in issue:
            return 'Use secrets.randbelow() or secrets.SystemRandom() for cryptographic operations'
        elif 'ECB' in issue:
            return 'Use AES-GCM (authenticated encryption) or AES-CBC with HMAC'
        elif 'CBC' in issue:
            return 'Add HMAC authentication or use AES-GCM for authenticated encryption'
        return 'Review and follow cryptographic best practices'