#!/usr/bin/env python3
"""
Main execution script for TLS Security Analysis
"""

import argparse
import json
import os
from tls_scanner import TLSScanner
from tls_analyzer import TLSAnalyzer
from targets import TOP_100_SITES, GOV_EDU_SITES, BADSSL_SITES


def main():
    parser = argparse.ArgumentParser(description='TLS Security Scanner')
    parser.add_argument('--scan', choices=['top', 'gov', 'all', 'test'], 
                        default='test', help='What to scan')
    parser.add_argument('--output', default='scan_results.json',
                        help='Output file for results')
    parser.add_argument('--load', help='Load results from file instead of scanning')
    parser.add_argument('--port', type=int, default=443, help='Port to scan')
    
    args = parser.parse_args()
    
    # Create results directory if it doesn't exist
    os.makedirs('results', exist_ok=True)
    
    scanner = TLSScanner(timeout=15)
    
    # Load existing results if specified
    if args.load:
        print(f"Loading results from {args.load}...")
        results = scanner.load_results(args.load)
    else:
        # Determine which sites to scan
        sites = []
        scan_name = ""
        
        if args.scan == 'top':
            sites = TOP_100_SITES
            scan_name = "Top 100 Commercial Sites"
        elif args.scan == 'gov':
            sites = GOV_EDU_SITES
            scan_name = "Government/Education Sites"
        elif args.scan == 'test':
            sites = BADSSL_SITES
            scan_name = "BadSSL Test Sites"
        elif args.scan == 'all':
            sites = TOP_100_SITES + GOV_EDU_SITES
            scan_name = "All Sites"
        
        print(f"\n{'='*60}")
        print(f"Starting TLS Scan: {scan_name}")
        print(f"Total sites to scan: {len(sites)}")
        print(f"{'='*60}\n")
        
        # Perform scans
        results = scanner.scan_batch(sites, port=args.port)
        
        # Save results
        output_path = os.path.join('results', args.output)
        scanner.save_results(results, output_path)
    
    # Analyze results
    print("\nAnalyzing results...")
    analyzer = TLSAnalyzer(results)
    
    # Generate visualizations
    try:
        analyzer.plot_tls_version_support()
        analyzer.plot_certificate_analysis()
        analyzer.plot_vulnerabilities()
    except Exception as e:
        print(f"Warning: Could not generate plots: {e}")
    
    # Print summary
    analyzer.print_summary()
    
    # Get and save misconfigurations
    misconfigs = analyzer.get_misconfigurations()
    misconfig_path = os.path.join('results', 'misconfigurations.json')
    with open(misconfig_path, 'w') as f:
        json.dump(misconfigs, f, indent=2)
    
    print(f"\n Results saved to:")
    print(f"  • Scan results: results/{args.output}")
    print(f"  • Misconfigurations: results/misconfigurations.json")
    print(f"  • Plots: tls_version_support.png, certificate_analysis.png, vulnerabilities.png")


if __name__ == "__main__":
    main()