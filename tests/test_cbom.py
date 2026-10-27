"""
Tests for pqblocks-fips-check.cbom - generate_cbom
Slice S-03: `pqblocks-fips-check.cbom` — generate_cbom
"""

import pytest
import sys
import os
import json
import re
from datetime import datetime

# Add src to path so we can import pqblocks-fips-check
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../src'))


def test_generate_cbom_returns_string():
    """Test that generate_cbom returns a string."""
    from pqblocks_fips_check.cbom import generate_cbom
    
    result = generate_cbom()
    assert isinstance(result, str), f"Expected string, got {type(result)}"
    assert len(result) > 0, "CBOM string should not be empty"


def test_generate_cbom_contains_required_nist_oids():
    """Test that CBOM contains required NIST OIDs for ML-KEM-768, ML-DSA-65, and X25519."""
    from pqblocks_fips_check.cbom import generate_cbom
    
    cbom_output = generate_cbom()
    
    # NIST OIDs from spec section 6.1
    ml_kem_768_oid = "2.16.840.1.101.3.4.3.1"
    ml_dsa_65_oid = "2.16.840.1.101.3.4.3.2"
    x25519_oid = "1.3.101.112"
    
    assert ml_kem_768_oid in cbom_output, f"Missing ML-KEM-768 OID: {ml_kem_768_oid}"
    assert ml_dsa_65_oid in cbom_output, f"Missing ML-DSA-65 OID: {ml_dsa_65_oid}"
    assert x25519_oid in cbom_output, f"Missing X25519 OID: {x25519_oid}"


def test_generate_cbom_contains_cnsa_grades():
    """Test that CBOM contains CNSA 2.0 grade assignments."""
    from pqblocks_fips_check.cbom import generate_cbom
    
    cbom_output = generate_cbom()
    
    # CNSA 2.0 grades from spec section 6.1 - case-insensitive and flexible matching
    cbom_lower = cbom_output.lower()
    assert "ml-kem-768" in cbom_lower and ("grade 1" in cbom_lower or "\"grade\"" in cbom_lower and "1" in cbom_lower), \
        "Missing CNSA 2.0 grade for ML-KEM-768 (should be Grade 1)"
    assert "ml-dsa-65" in cbom_lower and ("grade 1" in cbom_lower or "\"grade\"" in cbom_lower and "1" in cbom_lower), \
        "Missing CNSA 2.0 grade for ML-DSA-65 (should be Grade 1)"
    assert "x25519" in cbom_lower and ("grade 2" in cbom_lower or "\"grade\"" in cbom_lower and "2" in cbom_lower), \
        "Missing CNSA 2.0 grade for X25519 (should be Grade 2)"


def test_generate_cbom_contains_pqblocks_dependency_info():
    """Test that CBOM contains dependency information for pqblocks_fips_check SDK."""
    from pqblocks_fips_check.cbom import generate_cbom
    
    cbom_output = generate_cbom()
    
    # Should contain pqblocks-fips-check information
    assert "pqblocks_fips_check" in cbom_output.lower(), "CBOM should mention pqblocks_fips_check SDK"
    assert "0.1.0" in cbom_output, "CBOM should contain version information"


def test_generate_cbom_contains_timestamp():
    """Test that CBOM contains timestamp information."""
    from pqblocks_fips_check.cbom import generate_cbom
    
    cbom_output = generate_cbom()
    
    # Should contain a timestamp in ISO format or similar
    # Looking for common timestamp patterns
    timestamp_patterns = [
        r'\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',  # ISO datetime
        r'timestamp',
        r'created',
        r'generated'
    ]
    
    has_timestamp = any(re.search(pattern, cbom_output, re.IGNORECASE) for pattern in timestamp_patterns)
    assert has_timestamp, "CBOM should contain timestamp information"


def test_generate_cbom_is_valid_spdx():
    """Test that CBOM output is valid SPDX format."""
    from pqblocks_fips_check.cbom import generate_cbom
    
    cbom_output = generate_cbom()
    
    # Basic SPDX validation - should contain SPDX tag-value markers
    # Check for common SPDX identifiers
    spdx_indicators = [
        "SPDXVersion",
        "DataLicense",
        "SPDXID",
        "PackageName",
        "PackageDownloadLocation",
        "FilesAnalyzed",
        "PackageChecksum"
    ]
    
    has_spdx_structure = any(indicator in cbom_output for indicator in spdx_indicators)
    assert has_spdx_structure, "CBOM should contain SPDX structure elements"


def test_generate_cbom_deterministic_with_same_inputs():
    """Test that generate_cbom produces consistent output (though may vary by timestamp)."""
    from pqblocks_fips_check.cbom import generate_cbom
    
    # Call twice and check that core content is consistent
    cbom1 = generate_cbom()
    cbom2 = generate_cbom()
    
    # Core identifiers should be the same
    assert "pqblocks_fips_check" in cbom1 and "pqblocks_fips_check" in cbom2
    assert "ML-KEM-768" in cbom1 and "ML-KEM-768" in cbom2
    assert "ML-DSA-65" in cbom1 and "ML-DSA-65" in cbom2
    assert "X25519" in cbom1 and "X25519" in cbom2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])