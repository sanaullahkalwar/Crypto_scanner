#!/usr/bin/env python3
"""
Crypto Vulnerability Scanner - Local Projects Only
Scans local directories for cryptographic implementations and vulnerabilities
"""

import argparse
import sys
from pathlib import Path
from scanner.local_scanner import LocalScanner
from scanner.report_generator import ReportGenerator

def main():
    parser = argparse.ArgumentParser(
        description='Scan local projects for cryptographic vulnerabilities'
    )
    
    parser.add_argument('--local', '-l', type=str, required=True,
                       help='Local directory path to scan')
    parser.add_argument('--output', '-o', type=str, default='scan_report.html',
                       help='Output report file (default: scan_report.html)')
    parser.add_argument('--format', '-f', choices=['html', 'json', 'text'], 
                       default='html', help='Report format (default: html)')
    
    args = parser.parse_args()
    
    try:
        # Initialize local scanner
        scanner = LocalScanner(args.local)
        
        print(f"[*] Starting cryptographic vulnerability scan...")
        print(f"[*] Target: {args.local}")
        
        # Run scan
        results = scanner.scan()
        
        # Generate report
        report_gen = ReportGenerator(results)
        report_gen.generate(args.output, args.format)
        
        print(f"[✓] Scan completed successfully!")
        print(f"[✓] Report saved to: {args.output}")
        
        # Print summary
        print_summary(results)
        
    except Exception as e:
        print(f"[!] Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

def print_summary(results):
    """Print scan summary to console"""
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    print(f"Files scanned: {results['total_files']}")
    print(f"Crypto implementations found: {results['total_findings']}")
    print(f"Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
    print(f"Critical issues: {results['critical']}")
    print(f"High severity: {results['high']}")
    print(f"Medium severity: {results['medium']}")
    print(f"Low severity: {results['low']}")

if __name__ == "__main__":
    main()