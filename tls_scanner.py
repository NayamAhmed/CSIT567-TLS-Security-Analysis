#!/usr/bin/env python3
"""
Pure Python TLS Scanner - No external tools required
"""

import ssl
import socket
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import logging

# For certificate parsing
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

# For advanced SSL/TLS features
import OpenSSL
from OpenSSL import SSL

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class TLSResult:
    """Container for TLS scan results"""
    host: str
    port: int
    scan_time: str
    tls_versions: Dict[str, bool]
    supported_ciphers: List[str]
    weak_ciphers: List[str]
    certificate: Dict
    vulnerabilities: Dict[str, bool]
    error: Optional[str] = None


class TLSScanner:
    """Pure Python TLS Scanner using built-in libraries"""
    
    # Weak cipher suites to detect (partial list)
    WEAK_CIPHERS = {
        'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 
        'ANON', 'CBC', 'SEED', 'IDEA'
    }
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.tls_versions = {}  # Will store last scan's versions for vulnerability checks
        
    def scan(self, host: str, port: int = 443) -> TLSResult:
        """
        Comprehensive TLS scan for a single host
        """
        logger.info(f"Scanning {host}:{port}")
        
        result = TLSResult(
            host=host,
            port=port,
            scan_time=datetime.now().isoformat(),
            tls_versions={},
            supported_ciphers=[],
            weak_ciphers=[],
            certificate={},
            vulnerabilities={}
        )
        
        try:
            # Test TLS versions
            result.tls_versions = self._test_tls_versions(host, port)
            self.tls_versions = result.tls_versions  # Store for vulnerability checks
            
            # Test cipher suites
            result.supported_ciphers, result.weak_ciphers = self._test_ciphers(host, port)
            
            # Get certificate info
            result.certificate = self._get_certificate_info(host, port)
            
            # Test for known vulnerabilities
            result.vulnerabilities = self._test_vulnerabilities(host, port, result)
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"Error scanning {host}: {e}")
            
        return result
    
    def _test_tls_versions(self, host: str, port: int) -> Dict[str, bool]:
        """Test which TLS versions are supported"""
        versions = {}
        
        # TLS versions to test (SSLv3 is deprecated and dangerous)
        tls_tests = [
            (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
            (ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
        ]
        
        # Add older versions if available
        try:
            tls_tests.append((ssl.TLSVersion.TLSv1_1, "TLSv1.1"))
            tls_tests.append((ssl.TLSVersion.TLSv1, "TLSv1.0"))
        except AttributeError:
            pass
        
        for tls_version, version_name in tls_tests:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = tls_version
                context.maximum_version = tls_version
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        versions[version_name] = True
            except (ssl.SSLError, socket.error, socket.timeout) as e:
                versions[version_name] = False
            except Exception:
                versions[version_name] = False
                
        return versions
    
    def _test_ciphers(self, host: str, port: int) -> Tuple[List[str], List[str]]:
        """Test supported cipher suites and identify weak ones"""
        supported = []
        weak = []
        
        try:
            # Use pyOpenSSL for cipher information
            context = SSL.Context(SSL.TLS_METHOD)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            ssl_sock = SSL.Connection(context, sock)
            ssl_sock.set_connect_state()
            ssl_sock.set_tlsext_host_name(host.encode())
            
            try:
                ssl_sock.do_handshake()
                cipher_name = ssl_sock.get_cipher_name()
                if cipher_name:
                    supported.append(cipher_name)
                    if self._is_weak_cipher(cipher_name):
                        weak.append(cipher_name)
            except SSL.Error:
                pass
            finally:
                ssl_sock.close()
                sock.close()
                
        except Exception as e:
            logger.debug(f"Cipher test failed for {host}: {e}")
            
        return supported, weak
    
    def _is_weak_cipher(self, cipher_name: str) -> bool:
        """Check if a cipher suite is considered weak"""
        cipher_upper = cipher_name.upper()
        for weak_pattern in self.WEAK_CIPHERS:
            if weak_pattern in cipher_upper:
                return True
        return False
    
    def _get_certificate_info(self, host: str, port: int) -> Dict:
        """Extract detailed certificate information"""
        cert_info = {
            'subject': {},
            'issuer': {},
            'valid_from': None,
            'valid_to': None,
            'days_remaining': None,
            'key_type': None,
            'key_size': None,
            'signature_algorithm': None,
            'serial_number': None,
            'san': [],
            'is_self_signed': False,
            'is_expired': False,
            'is_valid': False
        }
        
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    
                    if cert_der:
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        
                        # Subject
                        subject = cert.subject
                        cert_info['subject'] = {
                            'CN': self._get_attr(subject, 'common_name'),
                            'O': self._get_attr(subject, 'organization_name'),
                            'OU': self._get_attr(subject, 'organizational_unit_name'),
                            'C': self._get_attr(subject, 'country_name')
                        }
                        
                        # Issuer
                        issuer = cert.issuer
                        cert_info['issuer'] = {
                            'CN': self._get_attr(issuer, 'common_name'),
                            'O': self._get_attr(issuer, 'organization_name')
                        }
                        
                        # Validity
                        # Use UTC versions to avoid deprecation warnings
                        cert_info['valid_from'] = cert.not_valid_before_utc.isoformat()
                        cert_info['valid_to'] = cert.not_valid_after_utc.isoformat()
                        days_remaining = (cert.not_valid_after_utc - datetime.now().astimezone()).days
                        cert_info['days_remaining'] = days_remaining
                        cert_info['is_expired'] = days_remaining < 0
                        cert_info['is_valid'] = days_remaining > 0
                        
                        # Key information
                        public_key = cert.public_key()
                        if isinstance(public_key, rsa.RSAPublicKey):
                            cert_info['key_type'] = 'RSA'
                            cert_info['key_size'] = public_key.key_size
                        elif isinstance(public_key, ec.EllipticCurvePublicKey):
                            cert_info['key_type'] = 'EC'
                            cert_info['key_size'] = public_key.curve.key_size
                        elif isinstance(public_key, dsa.DSAPublicKey):
                            cert_info['key_type'] = 'DSA'
                            cert_info['key_size'] = public_key.key_size
                        
                        # Signature algorithm
                        cert_info['signature_algorithm'] = cert.signature_algorithm_oid._name
                        
                        # Serial number
                        cert_info['serial_number'] = hex(cert.serial_number)
                        
                        # Subject Alternative Names
                        try:
                            san_ext = cert.extensions.get_extension_for_oid(
                                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                            )
                            cert_info['san'] = san_ext.value.get_values_for_type(x509.DNSName)
                        except x509.extensions.ExtensionNotFound:
                            pass
                        
                        # Check if self-signed
                        cert_info['is_self_signed'] = cert.subject == cert.issuer
                        
        except Exception as e:
            logger.debug(f"Certificate parsing failed for {host}: {e}")
            cert_info['error'] = str(e)
            
        return cert_info
    
    def _get_attr(self, name, attr_type):
        """Helper to extract attribute from x509 name"""
        attributes = {
            'common_name': 'CN',
            'organization_name': 'O',
            'organizational_unit_name': 'OU',
            'country_name': 'C'
        }
        
        oid_attr = getattr(x509.oid.NameOID, attr_type.upper(), None)
        if oid_attr:
            try:
                return name.get_attributes_for_oid(oid_attr)[0].value
            except (IndexError, AttributeError):
                pass
        return None
    
    def _test_vulnerabilities(self, host: str, port: int, result: TLSResult) -> Dict[str, bool]:
        """Test for known TLS vulnerabilities"""
        vulnerabilities = {
            'heartbleed': False,
            'robot': False,
            'freak': False,
            'logjam': False,
            'poodle': False,
            'crime': False,
            'beast': False,
        }
        
        # Check for POODLE (SSLv3 support)
        if result.tls_versions.get('SSLv3', False):
            vulnerabilities['poodle'] = True
        
        # Check for BEAST (TLSv1.0 with CBC ciphers)
        if result.tls_versions.get('TLSv1.0', False):
            for cipher in result.supported_ciphers:
                if 'CBC' in cipher and 'AES' not in cipher:
                    vulnerabilities['beast'] = True
                    break
        
        # Check for weak keys (Logjam)
        key_size = result.certificate.get('key_size')
        key_type = result.certificate.get('key_type')
        if key_type == 'RSA' and key_size and key_size < 2048:
            vulnerabilities['logjam'] = True
        elif key_type =="EC":
            vulnerabilities['logjam'] = False
        
        return vulnerabilities
    
    def scan_batch(self, hosts: List[str], port: int = 443) -> List[TLSResult]:
        """Scan multiple hosts sequentially"""
        results = []
        total = len(hosts)
        
        for i, host in enumerate(hosts):
            logger.info(f"Progress: {i+1}/{total} - {host}")
            result = self.scan(host, port)
            results.append(result)
            time.sleep(1)  # Be polite to servers
            
        return results
    
    def save_results(self, results: List[TLSResult], filename: str = "scan_results.json"):
        """Save results to JSON file"""
        data = [asdict(r) for r in results]
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Results saved to {filename}")
    
    def load_results(self, filename: str) -> List[TLSResult]:
        """Load results from JSON file"""
        with open(filename, 'r') as f:
            data = json.load(f)
        return [TLSResult(**item) for item in data]