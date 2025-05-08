# SSL Traffic Analyzer

This Python application analyzes network traffic JSON files to extract SSL/TLS information and provide detailed data about the cipher suites used in the connections.

## Features

- Extracts unique URLs (host + path) from JSON network traffic data
- Identifies the SSL/TLS protocol version used for each connection
- Shows the cipher suite used for each connection
- Fetches detailed information about each cipher suite from the ciphersuite.info API
- Presents all information in a well-formatted table

## Requirements

- Python 3.6+
- Required Python packages:
  - requests
  - tabulate

## Installation

1. Clone or download this repository
2. Install required packages:
   ```
   pip install requests tabulate
   ```

## Usage

Run the script with the path to your JSON file:

```
python ssl_analyzer.py example.txt
```

The script will:
1. Parse the JSON data
2. Extract unique URLs with their SSL information
3. Query the ciphersuite.info API for detailed cipher suite information
4. Display a table with all the collected information

## Example Output

```
+--------------------------------------+---------------+-------------------------------------------+-----------------------------------------------------------------------+
| URL (host+path)                      | SSL Protocol  | Cipher Suite                              | Detailed Information                                                   |
+======================================+===============+===========================================+=======================================================================+
| mobile.eum-appdynamics.com/          | TLSv1.2       | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256    | **Protocol:** TLSv1.2                                                  |
| eumcollector/mobileMetrics           |               |                                           | **Key Exchange:** ECDHE                                                |
|                                      |               |                                           | **Authentication:** RSA                                                |
|                                      |               |                                           | **Encryption:** AES_128_GCM                                            |
|                                      |               |                                           | **Hash:** SHA256                                                       |
+--------------------------------------+---------------+-------------------------------------------+-----------------------------------------------------------------------+
| firebaseinstallations.googleapis.com/| TLSv1.2       | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  | **Protocol:** TLSv1.2                                                  |
| v1/projects/activehealth-f6a98/      |               |                                           | **Key Exchange:** ECDHE                                                |
| installations/                       |               |                                           | **Authentication:** ECDSA                                              |
|                                      |               |                                           | **Encryption:** AES_128_GCM                                            |
|                                      |               |                                           | **Hash:** SHA256                                                       |
+--------------------------------------+---------------+-------------------------------------------+-----------------------------------------------------------------------+
```

## API Information

This application uses the ciphersuite.info API to fetch detailed information about cipher suites:

- Base URL: `https://ciphersuite.info/api`
- Endpoint: `/cs/{cipher_suite_name}`

For more information about the API, see the included `api-spec-cyphersuite.txt` file.
