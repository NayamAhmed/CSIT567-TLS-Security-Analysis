#!/usr/bin/env python3
"""
FULL TLS SCAN - Complete Project Data Collection
Scans all commercial, government, and education sites
"""

import os
import json
import time
from datetime import datetime
from tls_scanner import TLSScanner
from tls_analyzer import TLSAnalyzer
from targets import TOP_100_SITES, GOV_EDU_SITES, BADSSL_SITES

def create_results_dir():
    """Create results directory with timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = f"results/full_scan_{timestamp}"
    os.makedirs(results_dir, exist_ok=True)
    return results_dir, timestamp

def run_validation_scan(scanner, results_dir):
    """First: Validate scanner with badssl.com"""
    print("\n" + "="*70)
    print("STEP 1: VALIDATION SCAN (badssl.com)")
    print("="*70)
    print(f"Testing {len(BADSSL_SITES)} validation sites...")
    
    results = scanner.scan_batch(BADSSL_SITES)
    scanner.save_results(results, f"{results_dir}/validation_results.json")
    
    valid = sum(1 for r in results if not r.error)
    print(f"✓ Validation complete: {valid}/{len(BADSSL_SITES)} successful")
    return results

def run_commercial_scan(scanner, results_dir):
    """Scan all commercial sites"""
    sites = TOP_100_SITES
    print("\n" + "="*70)
    print(f"STEP 2: COMMERCIAL SCAN ({len(sites)} sites)")
    print("="*70)
    
    all_results = []
    batch_size = 20
    
    for i in range(0, len(sites), batch_size):
        batch = sites[i:i+batch_size]
        batch_num = i//batch_size + 1
        total_batches = (len(sites) + batch_size - 1)//batch_size
        
        print(f"\n--- Batch {batch_num}/{total_batches}: {len(batch)} sites ---")
        results = scanner.scan_batch(batch)
        all_results.extend(results)
        
        # Save intermediate results
        scanner.save_results(results, f"{results_dir}/commercial_batch_{batch_num}.json")
        
        # Progress update
        successful = sum(1 for r in results if not r.error)
        print(f"  Batch complete: {successful}/{len(batch)} successful")
    
    # Save combined results
    scanner.save_results(all_results, f"{results_dir}/commercial_all.json")
    return all_results

def run_gov_edu_scan(scanner, results_dir):
    """Scan government and education sites"""
    print("\n" + "="*70)
    print(f"STEP 3: GOVERNMENT/EDUCATION SCAN ({len(GOV_EDU_SITES)} sites)")
    print("="*70)
    
    all_results = []
    batch_size = 20
    
    for i in range(0, len(GOV_EDU_SITES), batch_size):
        batch = GOV_EDU_SITES[i:i+batch_size]
        batch_num = i//batch_size + 1
        total_batches = (len(GOV_EDU_SITES) + batch_size - 1)//batch_size
        
        print(f"\n--- Batch {batch_num}/{total_batches}: {len(batch)} sites ---")
        results = scanner.scan_batch(batch)
        all_results.extend(results)
        
        scanner.save_results(results, f"{results_dir}/gov_edu_batch_{batch_num}.json")
        
        successful = sum(1 for r in results if not r.error)
        print(f"  Batch complete: {successful}/{len(batch)} successful")
    
    scanner.save_results(all_results, f"{results_dir}/gov_edu_all.json")
    return all_results

def main():
    """Main execution function"""
    print("\n" + "="*70)
    print("TLS SECURITY SCANNER - FULL DEPLOYMENT ANALYSIS")
    print("="*70)
    print("This will scan:")
    print(f"  • {len(TOP_100_SITES)} commercial sites")
    print(f"  • {len(GOV_EDU_SITES)} government/education sites")
    print(f"  • {len(BADSSL_SITES)} validation sites")
    print(f"  • TOTAL: {len(TOP_100_SITES) + len(GOV_EDU_SITES) + len(BADSSL_SITES)} sites")
    print("\nEstimated time: 20-30 minutes")
    
    confirm = input("\nProceed with full scan? (y/n): ")
    if confirm.lower() != 'y':
        print("Scan cancelled.")
        return
    
    # Create scanner
    scanner = TLSScanner(timeout=15)
    
    # Create results directory
    results_dir, timestamp = create_results_dir()
    print(f"\nResults will be saved to: {results_dir}")
    
    # Run scans
    start_time = time.time()
    
    validation_results = run_validation_scan(scanner, results_dir)
    commercial_results = run_commercial_scan(scanner, results_dir)
    gov_results = run_gov_edu_scan(scanner, results_dir)
    
    # Combine all results
    all_results = validation_results + commercial_results + gov_results
    
    # Save combined results
    scanner.save_results(all_results, f"{results_dir}/all_results_combined.json")
    
    # Print completion
    elapsed = time.time() - start_time
    print("\n" + "="*70)
    print("SCAN COMPLETE!")
    print("="*70)
    print(f"Time elapsed: {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")
    print(f"Results saved to: {results_dir}")
    print("\nFiles created:")
    print(f"  • {results_dir}/validation_results.json")
    print(f"  • {results_dir}/commercial_all.json")
    print(f"  • {results_dir}/gov_edu_all.json")
    print(f"  • {results_dir}/all_results_combined.json")

if __name__ == "__main__":
    main()