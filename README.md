TLS Security Scanner
CSIT 567 Cryptography - Montclair State University
Author: Nayam Ahmed
Course: Masters in Cybersecurity, CSIT 567 Cryptography
Date: Spring 2026


Requirements: 
- Python 3.8 or higher
- Pip manager
- pip install cryptography pyOpenSSL requests pandas matplotlib seaborn
- cryptography>=41.0.0
- pyOpenSSL>=23.0.0
-requests>=2.31.0
- pandas>=2.0.0
- matplotlib>=3.7.0
- seaborn>=0.12.0


Project Overview
This project implements a pure-Python TLS security scanner that analyzes the security posture of web servers. The scanner evaluates TLS protocol versions, cipher suite configurations, certificate strength, and known vulnerabilities across commercial, government, and educational domains.

Key Findings from 165 Scanned Servers
Metric	Result
TLS 1.3 Support	69.7%
TLS 1.2 Support	90.9%
Weak Ciphers	0.0%
Weak RSA Keys	0.0%
Expired Certificates	1.8%
Average Key Size	2124 bits
Features
TLS Version Detection - Tests support for TLS 1.0, 1.1, 1.2, and 1.3

Certificate Analysis - Extracts key type, key size, expiration, issuer, and SAN

Cipher Suite Detection - Identifies negotiated ciphers and flags weak algorithms

Vulnerability Assessment - Tests for POODLE, BEAST, and Logjam vulnerabilities

Batch Scanning - Scans multiple hosts with rate limiting

Data Persistence - Saves results in JSON format

Statistical Analysis - Generates metrics using Pandas

Visualization - Creates plots with Matplotlib and Seaborn

