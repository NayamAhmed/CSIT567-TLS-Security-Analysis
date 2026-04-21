#!/usr/bin/env python3
"""
Analyze scan results and generate statistics for FINAL REPORT
Updated to work with full_scan.py results
"""

from tls_scanner import TLSScanner
from tls_analyzer import TLSAnalyzer
import json
import glob
import os
import numpy as np

# Helper function to convert numpy types to Python native types
def convert_to_serializable(obj):
    """Convert numpy types to Python native types for JSON serialization"""
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_to_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_to_serializable(item) for item in obj]
    return obj

print("=" * 60)
print("TLS SCAN ANALYSIS - FINAL REPORT DATA")
print("=" * 60)

scanner = TLSScanner()

# Find the most recent full scan results
result_dirs = glob.glob("results/full_scan_*")
if result_dirs:
    latest_dir = max(result_dirs)  # Most recent
    print(f"\nFound latest scan results: {latest_dir}")
else:
    print("\nNo full_scan results found. Looking for individual files...")
    latest_dir = "results"

# Load all results from the full scan
print("\nLoading results...")

# Try to load from full scan directory first
commercial_path = f"{latest_dir}/commercial_all.json"
gov_path = f"{latest_dir}/gov_edu_all.json"
validation_path = f"{latest_dir}/validation_results.json"
combined_path = f"{latest_dir}/all_results_combined.json"

commercial = []
gov_edu = []
validation = []

# Load commercial results
try:
    commercial = scanner.load_results(commercial_path)
    print(f"  [OK] Commercial sites: {len(commercial)} results")
except:
    print(f"  [FAIL] Commercial results not found at {commercial_path}")
    
    # Try alternative path
    try:
        commercial = scanner.load_results('results/commercial_all.json')
        print(f"  [OK] Commercial sites (alt): {len(commercial)} results")
    except:
        print(f"  [FAIL] No commercial results found")

# Load gov/edu results
try:
    gov_edu = scanner.load_results(gov_path)
    print(f"  [OK] Gov/Edu sites: {len(gov_edu)} results")
except:
    try:
        gov_edu = scanner.load_results('results/gov_edu_all.json')
        print(f"  [OK] Gov/Edu sites (alt): {len(gov_edu)} results")
    except:
        print(f"  [FAIL] No gov/edu results found")

# Load validation results
try:
    validation = scanner.load_results(validation_path)
    print(f"  [OK] BadSSL validation: {len(validation)} results")
except:
    try:
        validation = scanner.load_results('results/validation_results.json')
        print(f"  [OK] BadSSL validation (alt): {len(validation)} results")
    except:
        print(f"  [FAIL] No validation results found")

# Combine all results
all_results = []

if commercial:
    all_results.extend(commercial)
if gov_edu:
    all_results.extend(gov_edu)
if validation:
    all_results.extend(validation)

if not all_results:
    print("\n[ERROR] No results to analyze. Please run full_scan.py first.")
    print("\nTo run full scan:")
    print("  python full_scan.py")
    exit()

# Count successful scans
successful = [r for r in all_results if not r.error]
print(f"\nTotal results loaded: {len(all_results)}")
print(f"   Successful scans: {len(successful)}")
print(f"   Failed scans: {len(all_results) - len(successful)}")

# Analyze
print("\nAnalyzing results...")
analyzer = TLSAnalyzer(all_results)

# Print summary
analyzer.print_summary()

# Generate plots
print("\nGenerating visualizations...")
analyzer.plot_tls_version_support()
analyzer.plot_certificate_analysis()
analyzer.plot_vulnerabilities()

# Save misconfigurations
misconfigs = analyzer.get_misconfigurations()
os.makedirs('results', exist_ok=True)
with open('results/misconfigurations.json', 'w') as f:
    json.dump(misconfigs, f, indent=2)

print("\n" + "=" * 60)
print("ANALYSIS COMPLETE")
print("=" * 60)
print("\nFiles created:")
print("  - tls_version_support.png")
print("  - certificate_analysis.png")
print("  - vulnerabilities.png")
print("  - results/misconfigurations.json")

# Print quick stats for final report
stats = analyzer.generate_statistics()
print("\nFINAL REPORT STATISTICS:")
print("=" * 40)
print(f"  - Total servers scanned: {stats['total_scanned']}")
print(f"  - Successful scans: {stats['successful_scans']}")
print(f"  - TLS 1.3 support: {stats['tls_1_3_support']:.1f}%")
print(f"  - TLS 1.2 support: {stats['tls_1_2_support']:.1f}%")
print(f"  - Weak ciphers: {stats['weak_ciphers_present']:.1f}%")
print(f"  - Weak keys (RSA <2048): {stats['weak_keys']:.1f}%")
print(f"  - Expired certs: {stats['expired_certificates']:.1f}%")
print(f"  - Self-signed certs: {stats['self_signed_certs']:.1f}%")
print(f"  - Average key size: {stats['avg_key_size']:.0f} bits")
print(f"  - Average days remaining: {stats['avg_days_remaining']:.0f} days")
print("=" * 40)

# Convert stats to JSON serializable format and save
serializable_stats = convert_to_serializable(stats)
with open('results/final_statistics.json', 'w') as f:
    json.dump(serializable_stats, f, indent=2)
print("\nStatistics saved to: results/final_statistics.json")