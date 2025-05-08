from pydantic import BaseModel, RootModel
from typing import List, Optional, Dict

class CipherSuiteInfo(BaseModel):
    gnutls_name: str
    openssl_name: str
    hex_byte_1: str
    hex_byte_2: str
    protocol_version: str
    kex_algorithm: str
    auth_algorithm: str
    enc_algorithm: str
    hash_algorithm: str
    security: str
    tls_version: List[str]

class CipherSuiteEntry(RootModel):
    root: Dict[str, CipherSuiteInfo]

class CipherSuiteResponse(BaseModel):
    ciphersuites: List[CipherSuiteEntry] 