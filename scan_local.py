#!/usr/bin/env python3
"""
Standalone Local Directory Scanner
"""
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, '.')

from scanner.crypto_detector import CryptoDetector
from scanner.vulnerability_checker import VulnerabilityChecker
from scanner.report_generator import ReportGenerator
from scanner.local_scanner import LocalScanner

def main():
    target_path = "/home/sanaullah/Desktop/MS-Cyber-Security/Ethical-Hacking/Research-Work/March-progress/Quantum-safe-messenger"
    
    print(f"🔍 Scanning: {target_path}")
    print("="*60)
    
    try:
        scanner = LocalScanner(target_path)
        results = scanner.scan()
        
        # Generate reports in all formats
        report = ReportGenerator(results)
        report.generate("quantum_safe_report.html", "html")
        report.generate("quantum_safe_results.json", "json")
        report.generate("quantum_safe_scan.txt", "text")
        
        print("\n" + "="*60)
        print("✅ SCAN COMPLETE!")
        print("="*60)
        print(f"📊 Files scanned: {results['total_files']}")
        print(f"🔐 Crypto findings: {results['total_findings']}")
        print(f"⚠️  Vulnerabilities: {len(results['vulnerabilities'])}")
        print(f"🔴 Critical: {results['critical']}")
        print(f"🟠 High: {results['high']}")
        print(f"🟡 Medium: {results['medium']}")
        print(f"🟢 Low: {results['low']}")
        print("\n📁 Reports generated:")
        print("  - quantum_safe_report.html (open in browser)")
        print("  - quantum_safe_results.json (machine readable)")
        print("  - quantum_safe_scan.txt (plain text)")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
