# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Content Analysis Module
Entropy analysis, encoding detection, and basic DLP for network payloads
"""

import math
import re
import base64
from collections import Counter
from typing import Tuple, Optional, List, Dict


class ContentAnalyzer:
    """Analyzes packet content for suspicious patterns"""

    # Regex patterns for sensitive data (basic DLP)
    PATTERNS = {
        'credit_card': re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'api_key': re.compile(r'\b[A-Za-z0-9_-]{32,}\b'),  # Generic API key pattern
        'private_key': re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
        'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
        'jwt_token': re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
    }

    # Suspicious DNS/domain patterns (DGA indicators)
    DGA_INDICATORS = [
        re.compile(r'[a-z]{20,}'),  # Very long random strings
        re.compile(r'[0-9]{5,}'),   # Many consecutive numbers
        re.compile(r'([a-z]{2,})\1{2,}'),  # Repeated patterns
    ]

    @staticmethod
    def calculate_entropy(data: str) -> float:
        """
        Calculate Shannon entropy of a string

        Returns: float between 0 (no randomness) and 8 (maximum randomness for byte data)

        High entropy (>4.5) suggests encrypted/compressed data or random strings
        """
        if not data:
            return 0.0

        # Count character frequencies
        char_counts = Counter(data)
        data_len = len(data)

        # Calculate Shannon entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def detect_encoding(data: str) -> Dict[str, any]:
        """
        Detect if data contains encoded content (Base64, Hex, etc.)

        Returns: dict with encoding type and confidence
        """
        result = {
            'encoded': False,
            'type': None,
            'confidence': 0.0,
            'decoded_sample': None
        }

        # Base64 detection
        # Base64 pattern: alphanumeric + / and = for padding
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')

        if base64_pattern.match(data):
            try:
                # Try to decode
                decoded = base64.b64decode(data, validate=True)
                # Check if decoded data is printable (likely valid base64)
                if all(32 <= b < 127 or b in (9, 10, 13) for b in decoded[:50]):
                    result['encoded'] = True
                    result['type'] = 'base64'
                    result['confidence'] = 0.9
                    result['decoded_sample'] = decoded[:50].decode('utf-8', errors='ignore')
            except Exception:
                pass

        # Hexadecimal detection (long hex strings)
        hex_pattern = re.compile(r'^[0-9a-fA-F]{40,}$')
        if not result['encoded'] and hex_pattern.match(data):
            result['encoded'] = True
            result['type'] = 'hexadecimal'
            result['confidence'] = 0.8
            try:
                decoded = bytes.fromhex(data)
                result['decoded_sample'] = decoded[:50].decode('utf-8', errors='ignore')
            except Exception:
                pass

        # URL encoding detection (% followed by hex)
        url_encoded_count = len(re.findall(r'%[0-9a-fA-F]{2}', data))
        if url_encoded_count > 5:
            result['encoded'] = True
            result['type'] = 'url_encoded'
            result['confidence'] = min(0.9, url_encoded_count / len(data) * 2)

        return result

    @staticmethod
    def analyze_dns_query(query: str) -> Dict[str, any]:
        """
        Analyze DNS query for suspicious patterns

        Returns: dict with analysis results including:
        - entropy: Shannon entropy of query
        - encoding: detected encoding
        - dga_score: DGA likelihood (0-1)
        - suspicious: boolean
        """
        # Remove trailing dot if present
        query = query.rstrip('.')

        # Split into labels (subdomain parts)
        labels = query.split('.')

        # Analyze longest label (most likely to contain tunneled data)
        longest_label = max(labels, key=len) if labels else query

        analysis = {
            'entropy': ContentAnalyzer.calculate_entropy(longest_label),
            'encoding': ContentAnalyzer.detect_encoding(longest_label),
            'dga_score': 0.0,
            'suspicious': False,
            'reasons': []
        }

        # DGA scoring
        dga_indicators = 0

        # Check for DGA patterns
        for pattern in ContentAnalyzer.DGA_INDICATORS:
            if pattern.search(longest_label):
                dga_indicators += 1

        # High entropy suggests randomness (DGA)
        if analysis['entropy'] > 4.0:
            dga_indicators += 1
            analysis['reasons'].append(f"High entropy ({analysis['entropy']:.2f})")

        # Long labels with few vowels (random)
        if len(longest_label) > 15:
            vowels = sum(1 for c in longest_label.lower() if c in 'aeiou')
            vowel_ratio = vowels / len(longest_label)
            if vowel_ratio < 0.2:  # Less than 20% vowels
                dga_indicators += 1
                analysis['reasons'].append(f"Low vowel ratio ({vowel_ratio:.2%})")

        # Calculate DGA score (0-1)
        analysis['dga_score'] = min(1.0, dga_indicators / 3.0)

        # Mark as suspicious if high DGA score or encoding detected
        if analysis['dga_score'] > 0.5 or analysis['encoding']['encoded']:
            analysis['suspicious'] = True
            if analysis['encoding']['encoded']:
                analysis['reasons'].append(f"Encoded: {analysis['encoding']['type']}")

        return analysis

    @staticmethod
    def scan_for_sensitive_data(data: str, max_length: int = 10000) -> List[Dict]:
        """
        Scan data for sensitive information (DLP)

        Returns: list of findings with type and sample
        """
        findings = []

        # Limit data length to prevent DoS
        data = data[:max_length]

        for pattern_name, pattern in ContentAnalyzer.PATTERNS.items():
            matches = pattern.findall(data)
            if matches:
                # Redact sensitive data in findings
                redacted_samples = []
                for match in matches[:3]:  # Max 3 samples
                    if pattern_name == 'credit_card':
                        # Mask credit card
                        redacted = match[:4] + '*' * (len(match) - 8) + match[-4:]
                    elif pattern_name == 'ssn':
                        # Mask SSN
                        redacted = '***-**-' + match[-4:]
                    elif pattern_name == 'email':
                        # Partially mask email
                        parts = match.split('@')
                        redacted = parts[0][:2] + '***@' + parts[1]
                    else:
                        # Generic masking
                        redacted = match[:8] + '***'

                    redacted_samples.append(redacted)

                findings.append({
                    'type': pattern_name,
                    'count': len(matches),
                    'samples': redacted_samples
                })

        return findings

    @staticmethod
    def analyze_http_payload(payload: bytes, max_size: int = 50000) -> Dict[str, any]:
        """
        Analyze HTTP payload for suspicious content

        Returns: dict with analysis results
        """
        analysis = {
            'size': len(payload),
            'entropy': 0.0,
            'encoding': {'encoded': False},
            'dlp_findings': [],
            'suspicious': False,
            'reasons': []
        }

        # Skip very large payloads
        if len(payload) > max_size:
            analysis['reasons'].append(f"Payload too large ({len(payload)} bytes)")
            return analysis

        # Try to decode as text
        try:
            text = payload.decode('utf-8', errors='ignore')
        except Exception:
            text = str(payload)

        # Calculate entropy
        analysis['entropy'] = ContentAnalyzer.calculate_entropy(text[:5000])

        # Detect encoding
        analysis['encoding'] = ContentAnalyzer.detect_encoding(text[:1000])

        # DLP scan
        analysis['dlp_findings'] = ContentAnalyzer.scan_for_sensitive_data(text)

        # Determine if suspicious
        if analysis['entropy'] > 6.0:
            analysis['suspicious'] = True
            analysis['reasons'].append(f"Very high entropy ({analysis['entropy']:.2f})")

        if analysis['encoding']['encoded']:
            analysis['suspicious'] = True
            analysis['reasons'].append(f"Encoded payload: {analysis['encoding']['type']}")

        if analysis['dlp_findings']:
            analysis['suspicious'] = True
            analysis['reasons'].append(f"Sensitive data detected: {', '.join([f['type'] for f in analysis['dlp_findings']])}")

        return analysis


# Convenience functions
def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy"""
    return ContentAnalyzer.calculate_entropy(data)


def is_likely_encoded(data: str) -> bool:
    """Quick check if data is likely encoded"""
    result = ContentAnalyzer.detect_encoding(data)
    return result['encoded'] and result['confidence'] > 0.7


def analyze_dns(query: str) -> Dict:
    """Analyze DNS query"""
    return ContentAnalyzer.analyze_dns_query(query)
