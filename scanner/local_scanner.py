"""
Local directory scanner - Advanced Edition
"""

from pathlib import Path
from typing import Dict, List
from scanner.crypto_detector import CryptoDetector
from scanner.vulnerability_checker import VulnerabilityChecker

class LocalScanner:
    """Scans local directories for cryptographic vulnerabilities"""
    
    def __init__(self, directory_path: str, verbose: bool = False):
        self.directory_path = Path(directory_path)
        if not self.directory_path.exists():
            raise ValueError(f"Directory not found: {directory_path}")
        
        self.verbose = verbose
        self.detector = CryptoDetector()
        self.vuln_checker = VulnerabilityChecker()
        
        # Comprehensive ignore list
        self.ignore_dirs = {
            # JavaScript/Node
            'node_modules', '.npm', '.yarn',
            # Angular
            '.angular', 'dist', 'out', 'build', 'target',
            # Python
            '__pycache__', '.pytest_cache', '.tox', 'venv', '.venv', 'env', '.env',
            '*.egg-info', '.eggs', 'build', 'dist', 'develop-eggs',
            # IDEs
            '.idea', '.vscode', '.vs', '.eclipse', '.settings',
            # Version Control
            '.git', '.svn', '.hg', '.bzr',
            # OS files
            '.DS_Store', 'Thumbs.db', '.Spotlight-V100', '.Trashes',
            # Docker & Virtualization
            '.docker', 'docker-compose.override.yml',
            # Cache
            '.cache', '.parcel-cache', '.next', '.nuxt',
            # Test coverage
            'coverage', '.nyc_output', '.coverage',
            # Logs
            'logs', '*.log',
            # Temporary
            'tmp', 'temp', '.tmp',
        }
        
        self.ignore_files = {
            # Package manager files
            'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
            'requirements.txt', 'Pipfile', 'Pipfile.lock', 'poetry.lock',
            'Cargo.toml', 'Cargo.lock', 'go.mod', 'go.sum',
            # Config files
            '.gitignore', '.gitattributes', '.editorconfig',
            '.prettierrc', '.eslintrc', '.babelrc', '.browserslistrc',
            'tsconfig.json', 'jsconfig.json',
            # Environment
            '.env', '.env.*',
            # Docker
            'Dockerfile', 'docker-compose.yml',
            # CI/CD
            '.gitlab-ci.yml', '.travis.yml', 'Jenkinsfile',
            # README & Documentation
            'README.md', 'README', 'CHANGELOG.md', 'CONTRIBUTING.md',
            'LICENSE', 'LICENSE.md',
            # Lock files
            '*.lock',
            # Binary/Compiled files
            '*.pyc', '*.pyo', '*.class', '*.o', '*.obj', '*.so', '*.dll',
            '*.exe', '*.bin', '*.dylib', '*.wasm',
            # Media files
            '*.jpg', '*.jpeg', '*.png', '*.gif', '*.ico', '*.svg',
            '*.mp3', '*.mp4', '*.wav', '*.avi', '*.mov',
            '*.pdf', '*.doc', '*.docx', '*.xls', '*.xlsx',
            # Archive files
            '*.zip', '*.tar', '*.gz', '*.rar', '*.7z',
            # Font files
            '*.ttf', '*.woff', '*.woff2', '*.eot',
            # Map files
            '*.map', '*.js.map', '*.css.map',
        }
        
    def scan(self) -> Dict:
        """Scan the local directory"""
        print(f"[*] Scanning directory: {self.directory_path}")
        print(f"[*] Ignoring: node_modules, .angular, dist, venv, and other common dirs")
        
        all_findings = []
        total_files = 0
        skipped_files = 0
        file_type_stats = {}
        scanned_files_list = []
        
        for file_path in self.directory_path.rglob('*'):
            if file_path.is_file():
                if self.should_ignore(file_path):
                    skipped_files += 1
                    continue
                    
                total_files += 1
                scanned_files_list.append(str(file_path))
                
                # Track file types
                ext = file_path.suffix.lower() or 'no_extension'
                file_type_stats[ext] = file_type_stats.get(ext, 0) + 1
                
                # Detect crypto usage
                findings = self.detector.detect_crypto_in_file(file_path)
                all_findings.extend(findings)
                
                if findings and self.verbose:
                    print(f"  [✓] Found {len(findings)} crypto patterns in: {file_path.name}")
                elif findings:
                    print(f"  [✓] Found crypto patterns in: {file_path.name}")
        
        print(f"\n[*] Scanned {total_files} files, skipped {skipped_files} files")
        print(f"[*] Found {len(all_findings)} cryptographic patterns")
        
        # Check for vulnerabilities with advanced analysis
        print(f"[*] Analyzing vulnerabilities and checking CVEs...")
        vulnerability_results = self.vuln_checker.analyze_findings(all_findings)
        
        print(f"[*] Checking compliance standards...")
        
        return {
            'target': str(self.directory_path),
            'scan_date': str(Path.cwd()),
            'total_files': total_files,
            'skipped_files': skipped_files,
            'total_findings': len(all_findings),
            'findings': all_findings,
            'file_type_stats': file_type_stats,
            'scanned_files': scanned_files_list,
            'vulnerabilities': vulnerability_results['vulnerabilities'],
            'critical': vulnerability_results['critical'],
            'high': vulnerability_results['high'],
            'medium': vulnerability_results['medium'],
            'low': vulnerability_results['low'],
            'info': vulnerability_results.get('info', 0),
            'risk_score': vulnerability_results['risk_score'],
            'top_threats': vulnerability_results['top_threats'],
            'compliance': vulnerability_results['compliance'],
            'statistics': vulnerability_results['statistics'],
            'remediation_plan': vulnerability_results['remediation_plan']
        }
    
    def should_ignore(self, file_path: Path) -> bool:
        """Check if file should be ignored"""
        path_str = str(file_path)
        path_parts = file_path.parts
        
        # Check if any parent directory should be ignored
        for part in path_parts:
            if part in self.ignore_dirs:
                return True
        
        # Check if the file name matches any ignore patterns
        file_name = file_path.name
        
        # Exact file name matches
        if file_name in self.ignore_files:
            return True
        
        # Pattern matching for files (like *.log, *.lock)
        for pattern in self.ignore_files:
            if pattern.startswith('*.'):
                extension = pattern[1:]  # Get .extension
                if file_name.endswith(extension):
                    return True
            elif pattern.endswith('.*'):
                base = pattern[:-2]  # Get base name
                if file_name.startswith(base + '.'):
                    return True
        
        # Skip hidden files (starting with .) except specific ones we want to scan
        if file_name.startswith('.'):
            # Allow certain hidden config files that might contain crypto
            allowed_hidden = ['.travis.yml', '.gitlab-ci.yml']
            if file_name not in allowed_hidden:
                return True
        
        # Skip very large files (> 10MB) as they're likely not source code
        try:
            if file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB
                return True
        except:
            pass
        
        return False