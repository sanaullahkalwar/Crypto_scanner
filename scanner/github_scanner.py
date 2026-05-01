"""
GitHub repository scanner
"""

import os
import tempfile
import shutil
from pathlib import Path
from git import Repo
from github import Github
from scanner.crypto_detector import CryptoDetector
from scanner.vulnerability_checker import VulnerabilityChecker

class GitHubScanner:
    """Scans GitHub repositories for cryptographic vulnerabilities"""
    
    def __init__(self, repo_url: str, branch: str = 'main'):
        self.repo_url = repo_url
        self.branch = branch
        self.temp_dir = tempfile.mkdtemp()
        self.detector = CryptoDetector()
        self.vuln_checker = VulnerabilityChecker()
        
        # Initialize GitHub client (optional, for API access)
        github_token = os.environ.get('GITHUB_TOKEN')
        self.github_client = Github(github_token) if github_token else None
    
    def scan(self) -> Dict:
        """Clone and scan the repository"""
        try:
            print(f"[*] Cloning repository: {self.repo_url}")
            
            # Clone the repository
            repo = Repo.clone_from(
                self.repo_url, 
                self.temp_dir,
                branch=self.branch
            )
            
            print(f"[*] Scanning repository files...")
            
            # Scan all files
            all_findings = []
            total_files = 0
            
            for file_path in Path(self.temp_dir).rglob('*'):
                if file_path.is_file() and not self.should_ignore(file_path):
                    total_files += 1
                    findings = self.detector.detect_crypto_in_file(file_path)
                    all_findings.extend(findings)
            
            # Check for vulnerabilities
            vulnerability_results = self.vuln_checker.check_findings(all_findings)
            
            # Clean up
            shutil.rmtree(self.temp_dir)
            
            # Get repo metadata if available
            repo_metadata = self.get_repo_metadata() if self.github_client else {}
            
            return {
                'repo_url': self.repo_url,
                'branch': self.branch,
                'scan_date': str(Path.cwd()),
                'total_files': total_files,
                'total_findings': len(all_findings),
                'findings': all_findings,
                'vulnerabilities': vulnerability_results['vulnerabilities'],
                'critical': vulnerability_results['critical'],
                'high': vulnerability_results['high'],
                'medium': vulnerability_results['medium'],
                'low': vulnerability_results['low'],
                'compliance': vulnerability_results['compliance'],
                'repo_metadata': repo_metadata
            }
            
        except Exception as e:
            # Clean up on error
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
            raise e
    
    def should_ignore(self, file_path: Path) -> bool:
        """Check if file should be ignored"""
        ignore_patterns = [
            '.git', 'node_modules', '__pycache__', 
            'venv', '.env', '.idea', '.vscode',
            'dist', 'build', 'target'
        ]
        
        return any(pattern in str(file_path) for pattern in ignore_patterns)
    
    def get_repo_metadata(self) -> Dict:
        """Get repository metadata from GitHub API"""
        try:
            # Extract owner/repo from URL
            parts = self.repo_url.rstrip('/').split('/')
            repo_name = '/'.join(parts[-2:])
            
            repo = self.github_client.get_repo(repo_name)
            
            return {
                'stars': repo.stargazers_count,
                'forks': repo.forks_count,
                'last_updated': str(repo.updated_at),
                'language': repo.language,
                'open_issues': repo.open_issues_count
            }
        except:
            return {}