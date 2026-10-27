"""
pqblocks-fips-check.cbom - CBOM (Composite Bill of Materials) generation module
Implements generate_cbom for the pqblocks-fips-check SDK
"""

import json
import datetime
from typing import List, Dict, Any
from .hybrid import hybrid_keygen
from .signature import sign, verify_sig

# Constants for CNSA 2.0 grades
CNSA_GRADES = {
    "ML-KEM-768": "Grade 1",
    "ML-DSA-65": "Grade 1",
    "X25519": "Grade 2"
}

# NIST OIDs for the cryptographic algorithms
NIST_OIDS = {
    "ML-KEM-768": "2.16.840.1.101.3.4.3.1",
    "ML-DSA-65": "2.16.840.1.101.3.4.3.2",
    "X25519": "1.3.101.112"
}

# Version of the pqblocks-fips-check SDK
PQBLOCKS_VERSION = "0.1.0"


def _get_crypto_component_info(name: str) -> List[Dict[str, Any]]:
    """
    Generate component information for a cryptographic algorithm.

    Args:
        name: Name of the cryptographic algorithm

    Returns:
        List containing the component information dictionary
    """
    if name in NIST_OIDS:
        return [
            {
                "name": name,
                "type": "cryptographic-algorithm",
                "crypto_properties": {
                    "algorithm_properties": {
                        "nist_quantum_security_level": 3,
                        "classical_security_level": 128,
                        "ancillary": {
                            "oid": NIST_OIDS[name]
                        }
                    },
                    "cnsa_grade": CNSA_GRADES[name]
                }
            }
        ]
    return []


def _get_dependency_info() -> List[Dict[str, Any]]:
    """
    Generate dependency information for the pqblocks-fips-check SDK and its dependencies.

    Returns:
        List of dependency dictionaries
    """
    return [
        {
            "name": "pqblocks_fips_check",
            "version": PQBLOCKS_VERSION,
            "type": "library",
            "description": "Hybrid key exchange (X25519 + ML-KEM-768) and ML-DSA-65 signatures"
        },
        {
            "name": "cryptography",
            "version": "50.0.1",
            "type": "library",
            "description": "Python cryptographic library"
        },
        {
            "name": "liboqs-python",
            "version": "0.9.0",
            "type": "library",
            "description": "Python bindings for liboqs - library for post-quantum cryptography"
        }
    ]


def generate_cbom() -> str:
    """
    Generate a CBOM (Composite Bill of Materials) for the pqblocks-fips-check SDK.

    Returns:
        JSON string representing the CBOM in SPDX format
    """
    # Create the SPDX document
    spdx_doc = {
        "SPDXVersion": "SPDX-2.2",
        "DataLicense": {
            "reference": "https://spdx.org/licenses/CC0-1.0.html",
            "name": "CC0 1.0 Universal",
            "reference": "CC0-1.0"
        },
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "pqblocks_fips_check-sdk-0.1.0",
        "documentNamespace": f"https://spdx.org/spdxdocs/pqblocks-fips-check-{PQBLOCKS_VERSION}-{datetime.datetime.utcnow().isoformat()}",
        "creationInfo": {
            "created": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: pqblocks_fips_check-sdk-generator"]
        },
        "packages": [
            {
                "name": "pqblocks_fips_check",
                "SPDXID": "SPDXRef-Package-pqblocks_fips_check-0.1.0",
                "downloadLocation": "NOASSERTION",
                "versionInfo": PQBLOCKS_VERSION,
                "supplier": "Organization: pqblocks_fips_check-project",
                "description": "Hybrid key exchange (X25519 + ML-KEM-768) and ML-DSA-65 signatures SDK"
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package-pqblocks_fips_check-0.1.0"
            }
        ],
        "externalRefs": [
            {
                "referenceCategory": "SECURITY",
                "referenceType": "crypto-properties",
                "referenceLocator": "cnsa-grades",
                "comment": "CNSA 2.0 grade assignments for cryptographic algorithms used"
            }
        ],
        "annotations": [
            {
                "annotator": "Tool: pqblocks_fips_check-sdk-generator",
                "annotationDate": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "annotationType": "OTHER",
                "comment": f"CBOM generated for pqblocks-fips-check version {PQBLOCKS_VERSION}"
            }
        ]
    }

    # Add crypto component information
    crypto_components = []
    for algo_name in NIST_OIDS.keys():
        components = _get_crypto_component_info(algo_name)
        crypto_components.extend(components)

    # Add dependencies
    dependencies = _get_dependency_info()

    # Add crypto components to the document
    if "components" not in spdx_doc:
        spdx_doc["components"] = []
    spdx_doc["components"].extend(crypto_components)

    # Add dependencies to the document
    if "dependencies" not in spdx_doc:
        spdx_doc["dependencies"] = []
    spdx_doc["dependencies"].extend(dependencies)

    # Add CNSA grades table to annotations for clarity
    cnsa_table = "\nCNSA 2.0 Grade Assignments:\n"
    for alg, grade in CNSA_GRADES.items():
        cnsa_table += f"  {alg}: {grade}\n"

    # Modify the annotation comment to include the CNSA grades
    spdx_doc["annotations"][0]["comment"] = cnsa_table

    return json.dumps(spdx_doc, indent=2, default=str)