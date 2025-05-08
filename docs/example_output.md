# Example Output

When you run the SSL Traffic Analyzer on the provided JSON file (`example.txt`), you'll get output similar to the following:

```
+-----------------------------------------------+-------------+------------------------------------------+-----------------------------------------------------------------------+
| URL (host+path)                               | SSL Protocol | Cipher Suite                             | Detailed Information                                                   |
+===============================================+=============+==========================================+=======================================================================+
| mobile.eum-appdynamics.com/eumcollector/      | TLSv1.2     | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256    | **Protocol:** TLSv1.2                                                  |
| mobileMetrics                                 |             |                                           | **Key Exchange:** ECDHE                                                |
|                                               |             |                                           | **Authentication:** RSA                                                |
|                                               |             |                                           | **Encryption:** AES_128_GCM                                            |
|                                               |             |                                           | **Hash:** SHA256                                                       |
+-----------------------------------------------+-------------+------------------------------------------+-----------------------------------------------------------------------+
| firebaseinstallations.googleapis.com/v1/      | TLSv1.2     | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  | **Protocol:** TLSv1.2                                                  |
| projects/activehealth-f6a98/installations/    |             |                                           | **Key Exchange:** ECDHE                                                |
|                                               |             |                                           | **Authentication:** ECDSA                                              |
|                                               |             |                                           | **Encryption:** AES_128_GCM                                            |
|                                               |             |                                           | **Hash:** SHA256                                                       |
+-----------------------------------------------+-------------+------------------------------------------+-----------------------------------------------------------------------+
| device-provisioning.googleapis.com/checkin    | TLSv1.2     | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  | **Protocol:** TLSv1.2                                                  |
|                                               |             |                                           | **Key Exchange:** ECDHE                                                |
|                                               |             |                                           | **Authentication:** ECDSA                                              |
|                                               |             |                                           | **Encryption:** AES_128_GCM                                            |
|                                               |             |                                           | **Hash:** SHA256                                                       |
+-----------------------------------------------+-------------+------------------------------------------+-----------------------------------------------------------------------+
```

## Understanding Cipher Suite Information

The detailed information column breaks down each cipher suite:

### For TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:

- **Protocol:** Transport Layer Security (TLS)
- **Key Exchange:** Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) - Provides forward secrecy
- **Authentication:** RSA (Rivest Shamir Adleman algorithm)
- **Encryption:** AES 128-bit in Galois/Counter Mode (GCM)
- **Hash:** SHA-256 (Secure Hash Algorithm 256-bit)

### For TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:

- **Protocol:** Transport Layer Security (TLS)
- **Key Exchange:** Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) - Provides forward secrecy
- **Authentication:** Elliptic Curve Digital Signature Algorithm (ECDSA)
- **Encryption:** AES 128-bit in Galois/Counter Mode (GCM)
- **Hash:** SHA-256 (Secure Hash Algorithm 256-bit)
