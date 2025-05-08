import json
import sys
import requests
from tabulate import tabulate
from urllib.parse import quote

def load_json_data(filename):
    """Load JSON data from a file."""
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading JSON file: {e}")
        sys.exit(1)

def extract_unique_urls(json_data):
    """Extract unique URLs with their SSL information."""
    unique_urls = {}
    
    for entry in json_data:
        if 'ssl' in entry and entry['ssl'].get('protocol') and entry['ssl'].get('cipherSuite'):
            host = entry.get('host', '')
            path = entry.get('path', '')
            url = f"{host}{path}"
            
            if url not in unique_urls:
                unique_urls[url] = {
                    'host': host,
                    'path': path,
                    'protocol': entry['ssl']['protocol'],
                    'cipher_suite': entry['ssl']['cipherSuite']
                }
    
    return unique_urls

def fetch_cipher_suite_info(cipher_suite):
    """Fetch detailed information about a cipher suite from ciphersuite.info."""
    # Convert cipher suite name to the format expected by the API
    api_name = cipher_suite.replace('_', '-')
    encoded_name = quote(api_name)
    
    try:
        response = requests.get(f"https://ciphersuite.info/api/cs/{encoded_name}")
        if response.status_code == 200:
            data = response.json()
            cs_data = data.get(api_name, {})
            
            # Extract relevant information
            if cs_data:
                kex_algorithm = cs_data.get('kex_algorithm', 'Unknown')
                auth_algorithm = cs_data.get('auth_algorithm', 'Unknown')
                enc_algorithm = cs_data.get('enc_algorithm', 'Unknown')
                hash_algorithm = cs_data.get('hash_algorithm', 'Unknown')
                
                details = {
                    'Key Exchange': kex_algorithm,
                    'Authentication': auth_algorithm,
                    'Encryption': enc_algorithm,
                    'Hash': hash_algorithm
                }
                
                return details
        
        return {'Error': 'Unable to fetch cipher suite details'}
    
    except requests.RequestException:
        return {'Error': 'API request failed'}

def create_ssl_info_table(unique_urls):
    """Create a table with SSL information for each unique URL."""
    table_data = []
    
    for url, info in unique_urls.items():
        # Fetch cipher suite details
        cipher_details = fetch_cipher_suite_info(info['cipher_suite'])
        
        # Create formatted cipher suite details string
        cipher_details_str = ""
        if 'Error' not in cipher_details:
            cipher_details_str = f"""**Protocol:** {info['protocol']}
**Key Exchange:** {cipher_details.get('Key Exchange', 'Unknown')}
**Authentication:** {cipher_details.get('Authentication', 'Unknown')}
**Encryption:** {cipher_details.get('Encryption', 'Unknown')}
**Hash:** {cipher_details.get('Hash', 'Unknown')}"""
        else:
            cipher_details_str = f"**Protocol:** {info['protocol']}\n{cipher_details['Error']}"
        
        # Add to table data
        table_data.append([
            url,
            info['protocol'],
            info['cipher_suite'],
            cipher_details_str
        ])
    
    return table_data

def main():
    if len(sys.argv) != 2:
        print("Usage: python ssl_analyzer.py <json_file>")
        sys.exit(1)
    
    # Load JSON data
    json_file = sys.argv[1]
    json_data = load_json_data(json_file)
    
    # Extract unique URLs with SSL info
    unique_urls = extract_unique_urls(json_data)
    
    # Create table with SSL information
    table_data = create_ssl_info_table(unique_urls)
    
    # Print table
    headers = ["URL (host+path)", "SSL Protocol", "Cipher Suite", "Detailed Information"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    main()
