#!/usr/bin/env python3
"""
Advanced Crypto Vulnerability Scanner
Professional-grade cryptographic security assessment tool
"""

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime
from scanner.local_scanner import LocalScanner
from scanner.report_generator import ReportGenerator

def main():
    parser = argparse.ArgumentParser(
        description='🔒 Advanced Cryptographic Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -l ./my-project
  %(prog)s -l /path/to/project -o report.html
  %(prog)s -l . -f json -o results.json
        """
    )
    
    parser.add_argument('--local', '-l', type=str, required=True,
                       help='Local directory path to scan')
    parser.add_argument('--output', '-o', type=str, default=None,
                       help='Output report file')
    parser.add_argument('--format', '-f', choices=['html', 'json', 'text'], 
                       default='html', help='Report format (default: html)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Generate default output name if not specified
    if args.output is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        extensions = {'html': '.html', 'json': '.json', 'text': '.txt'}
        args.output = f'crypto_scan_{timestamp}{extensions[args.format]}'
    
    try:
        print_banner()
        
        scanner = LocalScanner(args.local, verbose=args.verbose)
        
        print(f"\n[*] Target: {args.local}")
        print(f"[*] Report Format: {args.format}")
        print(f"[*] Output: {args.output}")
        print("\n" + "="*60)
        
        # Run scan
        results = scanner.scan()
        
        # Generate report
        report_gen = ReportGenerator(results)
        report_gen.generate(args.output, args.format)
        
        print("\n" + "="*60)
        print("✅ SCAN COMPLETED SUCCESSFULLY")
        print("="*60)
        print_summary(results)
        print(f"\n📄 Detailed report saved to: {args.output}")
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

def print_banner():
    """Print tool banner"""
    banner = """
╔══════════════════════════════════════════════════════════╗
║     🔒 ADVANCED CRYPTO VULNERABILITY SCANNER v2.0      ║
║     Professional Cryptographic Security Assessment     ║
╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_summary(results):
    """Print detailed scan summary"""
    print(f"\n📊 SCAN STATISTICS")
    print(f"   Files analyzed: {results['total_files']}")
    print(f"   Files skipped: {results.get('skipped_files', 0)}")
    print(f"   Total findings: {results['total_findings']}")
    
    print(f"\n🔴 VULNERABILITY SEVERITY")
    print(f"   Critical: {results['critical']} ⚠️")
    print(f"   High:     {results['high']}")
    print(f"   Medium:   {results['medium']}")
    print(f"   Low:      {results['low']}")
    
    if 'risk_score' in results:
        risk = results['risk_score']
        risk_emoji = '🔴' if risk > 70 else '🟠' if risk > 40 else '🟡' if risk > 20 else '🟢'
        print(f"\n🎯 OVERALL RISK SCORE: {risk}/100 {risk_emoji}")
    
    if results.get('top_threats'):
        print(f"\n🚨 TOP THREATS:")
        for i, threat in enumerate(results['top_threats'][:3], 1):
            print(f"   {i}. {threat.get('title', 'Unknown')}")
            print(f"      CVSS: {threat.get('cvss_score', 'N/A')}")
            print(f"      Fix: {threat.get('mitigation', 'N/A')[:80]}...")

if __name__ == "__main__":
    main()