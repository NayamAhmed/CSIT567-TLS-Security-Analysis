#!/usr/bin/env python3
"""
Quick script to scan sites from targets.py
"""

from tls_scanner import TLSScanner
from targets import TOP_100_SITES, GOV_EDU_SITES, BADSSL_SITES
import os

# Create results directory
os.makedirs('results', exist_ok=True)

print("=" * 60)
print("TLS SCANNER - REAL DATA COLLECTION")
print("=" * 60)

# Create scanner
scanner = TLSScanner(timeout=15)

# 1. Scan BadSSL test sites first (validation)
print("\n 1. Validating scanner with BadSSL test sites...")
print(f"   Sites to scan: {len(BADSSL_SITES)}")
badssl_results = scanner.scan_batch(BADSSL_SITES)
scanner.save_results(badssl_results, 'results/badssl_results.json')
print(f"    Validation complete. Successful: {sum(1 for r in badssl_results if not r.error)}/{len(BADSSL_SITES)}")

# 2. Scan Top 10 commercial sites
print("\n 2. Scanning Top 10 Commercial Sites...")
print(f"   Sites to scan: 10 (from TOP_100_SITES)")
commercial_sites = TOP_100_SITES[:10]
commercial_results = scanner.scan_batch(commercial_sites)
scanner.save_results(commercial_results, 'results/commercial_10.json')
print(f"    Commercial scan complete. Successful: {sum(1 for r in commercial_results if not r.error)}/{len(commercial_sites)}")

# 3. Scan Government/Education sites
print("\n 3. Scanning Government/Education Sites...")
print(f"   Sites to scan: {len(GOV_EDU_SITES)}")
gov_results = scanner.scan_batch(GOV_EDU_SITES)
scanner.save_results(gov_results, 'results/gov_edu_results.json')
print(f"    Gov/Edu scan complete. Successful: {sum(1 for r in gov_results if not r.error)}/{len(GOV_EDU_SITES)}")

print("\n" + "=" * 60)
print(" ALL SCANS COMPLETE!")
print("=" * 60)
print("\nResults saved in 'results' folder:")
print("  • results/badssl_results.json")
print("  • results/commercial_10.json")
print("  • results/gov_edu_results.json")