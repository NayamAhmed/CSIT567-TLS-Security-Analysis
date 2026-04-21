#!/usr/bin/env python3
"""
TLS Analysis and Visualization Module
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import List, Dict
from tls_scanner import TLSResult

# Set style for better looking plots
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("Set2")


class TLSAnalyzer:
    """Analyze and visualize TLS scan results"""
    
    def __init__(self, results: List[TLSResult]):
        self.results = results
        self.df = self._to_dataframe()
        
    def _to_dataframe(self) -> pd.DataFrame:
        """Convert results to pandas DataFrame for analysis"""
        data = []
        for r in self.results:
            # Determine if key is actually weak (only RSA keys under 2048 bits)
            key_size = r.certificate.get('key_size', 0)
            key_type = r.certificate.get('key_type')
            
            # ECC keys are strong even at 256 bits, only RSA keys under 2048 are weak
            is_weak_key = False
            if key_type == 'RSA' and key_size and key_size < 2048:
                is_weak_key = True
            elif key_type == 'EC':
                is_weak_key = False  # ECC keys are strong
            
            row = {
                'host': r.host,
                'port': r.port,
                'scan_time': r.scan_time,
                'tls_1_2': r.tls_versions.get('TLSv1.2', False),
                'tls_1_3': r.tls_versions.get('TLSv1.3', False),
                'tls_1_1': r.tls_versions.get('TLSv1.1', False),
                'tls_1_0': r.tls_versions.get('TLSv1.0', False),
                'has_weak_ciphers': len(r.weak_ciphers) > 0,
                'weak_cipher_count': len(r.weak_ciphers),
                'weak_cipher_names': ', '.join(r.weak_ciphers),
                'cert_key_type': key_type,
                'cert_key_size': key_size,
                'is_weak_key': is_weak_key,  # New column for accurate weak key detection
                'is_expired': r.certificate.get('is_expired', True),
                'days_remaining': r.certificate.get('days_remaining', 0),
                'is_self_signed': r.certificate.get('is_self_signed', False),
                'signature_algorithm': r.certificate.get('signature_algorithm'),
                'poodle': r.vulnerabilities.get('poodle', False),
                'beast': r.vulnerabilities.get('beast', False),
                'logjam': r.vulnerabilities.get('logjam', False),
                'has_error': r.error is not None,
                'error': r.error
            }
            data.append(row)
        
        return pd.DataFrame(data)
    
    def generate_statistics(self) -> Dict:
        """Generate quantitative statistics"""
        valid_df = self.df[~self.df['has_error']]
        
        if len(valid_df) == 0:
            return {'error': 'No successful scans'}
        
        # For key size stats, only include RSA keys for accurate representation
        rsa_keys = valid_df[valid_df['cert_key_type'] == 'RSA']
        avg_rsa_key_size = rsa_keys['cert_key_size'].mean() if len(rsa_keys) > 0 else 0
        
        stats = {
            'total_scanned': len(self.df),
            'successful_scans': len(valid_df),
            'tls_1_3_support': (valid_df['tls_1_3'].sum() / len(valid_df)) * 100,
            'tls_1_2_support': (valid_df['tls_1_2'].sum() / len(valid_df)) * 100,
            'tls_1_1_support': (valid_df['tls_1_1'].sum() / len(valid_df)) * 100,
            'tls_1_0_support': (valid_df['tls_1_0'].sum() / len(valid_df)) * 100,
            'weak_ciphers_present': (valid_df['has_weak_ciphers'].sum() / len(valid_df)) * 100,
            'weak_keys': (valid_df['is_weak_key'].sum() / len(valid_df)) * 100,  # Now only counts weak RSA
            'expired_certificates': (valid_df['is_expired'].sum() / len(valid_df)) * 100,
            'self_signed_certs': (valid_df['is_self_signed'].sum() / len(valid_df)) * 100,
            'avg_key_size': avg_rsa_key_size,  # Average of RSA keys only
            'avg_days_remaining': valid_df['days_remaining'].mean(),
            'poodle_vulnerable': (valid_df['poodle'].sum() / len(valid_df)) * 100,
            'beast_vulnerable': (valid_df['beast'].sum() / len(valid_df)) * 100,
            'ecc_count': (valid_df['cert_key_type'] == 'EC').sum(),
            'rsa_count': (valid_df['cert_key_type'] == 'RSA').sum(),
        }
        
        return stats
    
    def get_misconfigurations(self) -> List[Dict]:
        """Identify common misconfigurations"""
        misconfigs = []
        
        for r in self.results:
            if r.error:
                continue
                
            issues = {
                'host': r.host,
                'issues': []
            }
            
            # Check TLS versions
            if r.tls_versions.get('TLSv1.0', False):
                issues['issues'].append('Uses obsolete TLS 1.0')
            if r.tls_versions.get('TLSv1.1', False):
                issues['issues'].append('Uses obsolete TLS 1.1')
            
            # Check weak ciphers
            if r.weak_ciphers:
                issues['issues'].append(f"Weak ciphers: {', '.join(r.weak_ciphers)}")
            
            # Check certificate - ONLY flag RSA keys under 2048 bits
            key_size = r.certificate.get('key_size')
            key_type = r.certificate.get('key_type')
            
            if r.certificate.get('is_expired'):
                issues['issues'].append('Certificate expired')
            
            # Only RSA keys under 2048 bits are weak
            if key_type == 'RSA' and key_size and key_size < 2048:
                issues['issues'].append(f"Weak RSA key size: {key_size} bits (should be ≥2048)")
            # ECC keys are strong even at 256 bits - no issue
            
            if r.certificate.get('is_self_signed'):
                issues['issues'].append('Self-signed certificate')
            
            # Check vulnerabilities
            if r.vulnerabilities.get('poodle'):
                issues['issues'].append('Vulnerable to POODLE')
            if r.vulnerabilities.get('beast'):
                issues['issues'].append('Vulnerable to BEAST')
            if r.vulnerabilities.get('logjam'):
                # Only flag logjam for RSA keys
                if key_type == 'RSA' and key_size and key_size < 2048:
                    issues['issues'].append('Vulnerable to Logjam (weak DH/RSA)')
            
            if issues['issues']:
                misconfigs.append(issues)
        
        return misconfigs
    
    def plot_tls_version_support(self):
        """Plot TLS version support distribution"""
        valid_df = self.df[~self.df['has_error']]
        
        if len(valid_df) == 0:
            print("No data to plot")
            return
        
        versions = ['TLSv1.3', 'TLSv1.2', 'TLSv1.1', 'TLSv1.0']
        support = [
            valid_df['tls_1_3'].sum() / len(valid_df) * 100,
            valid_df['tls_1_2'].sum() / len(valid_df) * 100,
            valid_df['tls_1_1'].sum() / len(valid_df) * 100,
            valid_df['tls_1_0'].sum() / len(valid_df) * 100,
        ]
        
        colors = ['#2ecc71', '#3498db', '#e74c3c', '#e74c3c']
        
        plt.figure(figsize=(10, 6))
        bars = plt.bar(versions, support, color=colors, edgecolor='black')
        plt.ylabel('Percentage (%)')
        plt.title('TLS Version Support Across Scanned Servers')
        plt.ylim(0, 100)
        
        # Add value labels
        for bar, value in zip(bars, support):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                    f'{value:.1f}%', ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        plt.savefig('tls_version_support.png', dpi=150)
        plt.show()
        print("Saved plot to tls_version_support.png")
    
    def plot_certificate_analysis(self):
        """Plot certificate key strength distribution"""
        valid_df = self.df[~self.df['has_error']]
        
        if len(valid_df) == 0:
            print("No data to plot")
            return
        
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        
        # Key size distribution - only for RSA keys (since ECC is different)
        rsa_keys = valid_df[valid_df['cert_key_type'] == 'RSA']
        ecc_keys = valid_df[valid_df['cert_key_type'] == 'EC']
        
        if len(rsa_keys) > 0:
            axes[0].hist(rsa_keys['cert_key_size'], bins=15, edgecolor='black', color='#3498db')
            axes[0].axvline(x=2048, color='red', linestyle='--', linewidth=2, 
                           label='Recommended minimum (2048 bits)')
            axes[0].set_xlabel('RSA Key Size (bits)')
            axes[0].set_ylabel('Number of Servers')
            axes[0].set_title('RSA Certificate Key Size Distribution')
            axes[0].legend()
        
        # Weak vs Strong keys (only for RSA)
        weak_rsa = rsa_keys[rsa_keys['cert_key_size'] < 2048] if len(rsa_keys) > 0 else []
        strong_rsa = rsa_keys[rsa_keys['cert_key_size'] >= 2048] if len(rsa_keys) > 0 else []
        
        # Add ECC note
        labels = []
        sizes = []
        colors_pie = []
        
        if len(weak_rsa) > 0:
            labels.append(f'Weak RSA (<2048 bits): {len(weak_rsa)}')
            sizes.append(len(weak_rsa))
            colors_pie.append('#e74c3c')
        
        if len(strong_rsa) > 0:
            labels.append(f'Strong RSA (≥2048 bits): {len(strong_rsa)}')
            sizes.append(len(strong_rsa))
            colors_pie.append('#2ecc71')
        
        if len(ecc_keys) > 0:
            labels.append(f'ECC (Strong): {len(ecc_keys)}')
            sizes.append(len(ecc_keys))
            colors_pie.append('#3498db')
        
        if sizes:
            axes[1].pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors_pie, startangle=90)
            axes[1].set_title('Key Type and Strength Distribution')
        
        plt.tight_layout()
        plt.savefig('certificate_analysis.png', dpi=150)
        plt.show()
        print("Saved plot to certificate_analysis.png")
    
    def plot_vulnerabilities(self):
        """Plot vulnerability distribution"""
        valid_df = self.df[~self.df['has_error']]
        
        if len(valid_df) == 0:
            print("No data to plot")
            return
        
        vulns = ['POODLE', 'BEAST', 'Logjam']
        rates = [
            valid_df['poodle'].sum() / len(valid_df) * 100,
            valid_df['beast'].sum() / len(valid_df) * 100,
            valid_df['logjam'].sum() / len(valid_df) * 100,
        ]
        
        colors = ['#e74c3c' if r > 0 else '#2ecc71' for r in rates]
        
        plt.figure(figsize=(10, 6))
        bars = plt.bar(vulns, rates, color=colors, edgecolor='black')
        plt.ylabel('Percentage of Servers (%)')
        plt.title('Vulnerability Exposure')
        plt.ylim(0, 100)
        
        for bar, rate in zip(bars, rates):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                    f'{rate:.1f}%', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig('vulnerabilities.png', dpi=150)
        plt.show()
        print("Saved plot to vulnerabilities.png")
    
    def print_summary(self):
        """Print a formatted summary of findings"""
        stats = self.generate_statistics()
        misconfigs = self.get_misconfigurations()
        
        print("\n" + "="*70)
        print("TLS DEPLOYMENT ANALYSIS SUMMARY")
        print("="*70)
        
        if 'error' in stats:
            print(f"\nError: {stats['error']}")
            return
        
        print("\n QUANTITATIVE METRICS:")
        print(f"  • Total servers scanned: {stats['total_scanned']}")
        print(f"  • Successful scans: {stats['successful_scans']}")
        print(f"  • TLS 1.3 support: {stats['tls_1_3_support']:.1f}%")
        print(f"  • TLS 1.2 support: {stats['tls_1_2_support']:.1f}%")
        print(f"  • TLS 1.1 support: {stats['tls_1_1_support']:.1f}%")
        print(f"  • TLS 1.0 support: {stats['tls_1_0_support']:.1f}%")
        print(f"  • Weak ciphers present: {stats['weak_ciphers_present']:.1f}%")
        print(f"  • Weak RSA keys (<2048 bits): {stats['weak_keys']:.1f}%")
        print(f"  • ECC certificates (strong): {stats.get('ecc_count', 0)}")
        print(f"  • RSA certificates: {stats.get('rsa_count', 0)}")
        print(f"  • Expired certificates: {stats['expired_certificates']:.1f}%")
        print(f"  • Self-signed certificates: {stats['self_signed_certs']:.1f}%")
        print(f"  • Average RSA key size: {stats['avg_key_size']:.0f} bits")
        print(f"  • Average days remaining: {stats['avg_days_remaining']:.0f} days")
        print(f"  • POODLE vulnerable: {stats['poodle_vulnerable']:.1f}%")
        print(f"  • BEAST vulnerable: {stats['beast_vulnerable']:.1f}%")
        
        print("\n  COMMON MISCONFIGURATIONS:")
        if misconfigs:
            print(f"  • Total servers with issues: {len(misconfigs)}/{stats['successful_scans']}")
            
            # Count issue types
            issue_counts = {}
            for m in misconfigs:
                for issue in m['issues']:
                    base_issue = issue.split(':')[0] if ':' in issue else issue
                    issue_counts[base_issue] = issue_counts.get(base_issue, 0) + 1
            
            for issue, count in sorted(issue_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  • {issue}: {count} servers")
        else:
            print("  No misconfigurations found!")
        
        print("\n" + "="*70)