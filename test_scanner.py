#!/usr/bin/env python3
"""
Quick test script to verify scanner is working
"""

from tls_scanner import TLSScanner

print("Testing TLS Scanner...\n")

# Create scanner
scanner = TLSScanner(timeout=10)

# Test with google.com
print("Testing google.com...")
result = scanner.scan("google.com")

print(f"\nResults for {result.host}:")
print(f"  TLS 1.3 Support: {result.tls_versions.get('TLSv1.3', False)}")
print(f"  TLS 1.2 Support: {result.tls_versions.get('TLSv1.2', False)}")
print(f"  Certificate Key Size: {result.certificate.get('key_size', 'N/A')} bits")
print(f"  Certificate Valid: {not result.certificate.get('is_expired', True)}")
print(f"  Days Remaining: {result.certificate.get('days_remaining', 'N/A')}")
print(f"  Weak Ciphers: {result.weak_ciphers if result.weak_ciphers else 'None'}")
print(f"  Vulnerabilities: {[k for k, v in result.vulnerabilities.items() if v]}")
print(f"  Error: {result.error if result.error else 'None'}")

print("\n Test complete!")