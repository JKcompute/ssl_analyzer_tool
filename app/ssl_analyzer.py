import json
import sys
import requests
from tabulate import tabulate
from urllib.parse import quote
import argparse
import os
import time
from concurrent.futures import ThreadPoolExecutor
from app.models import CipherSuiteResponse, CipherSuiteEntry, CipherSuiteInfo

class SSLAnalyzer:
    def __init__(self, cache_dir='.cache'):
        """Initialize the SSL Analyzer with caching support."""
        self.cache_dir = cache_dir
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)
        self.cipher_suite_data = self.load_cipher_suite_data()
        # Common asset file extensions to exclude
        self.asset_extensions = {
            # Images
            '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.svg', '.ico',
            # Documents
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            # Archives
            '.zip', '.rar', '.7z', '.tar', '.gz',
            # Web assets
            '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
            # Media
            '.mp3', '.mp4', '.avi', '.mov', '.wmv',
            # Other common assets
            '.xml', '.json', '.txt', '.csv', '.dat'
        }
    
    def load_cipher_suite_data(self):
        """Load or fetch the complete cipher suite data."""
        cache_file = os.path.join(self.cache_dir, 'cipher_suite_data.json')
        
        # Try to load from cache first
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    cache_data = json.load(f)
                # Return cached data if still valid (less than 24 hours old)
                if time.time() - cache_data.get('timestamp', 0) < 86400:
                    return cache_data.get('data', {})
            except (json.JSONDecodeError, IOError):
                pass  # If cache read fails, proceed to fetch from API
        
        try:
            response = requests.get("https://ciphersuite.info/api/cs/")
            if response.status_code == 200:
                # Parse the response using our Pydantic model
                cipher_suite_response = CipherSuiteResponse.model_validate(response.json())
                
                # Convert to a more easily accessible dictionary format
                cipher_suite_dict = {}
                for entry in cipher_suite_response.ciphersuites:
                    for cipher_name, cipher_info in entry.root.items():
                        cipher_suite_dict[cipher_name] = cipher_info.model_dump()
                
                # Cache the data
                with open(cache_file, 'w') as f:
                    json.dump({'timestamp': time.time(), 'data': cipher_suite_dict}, f)
                return cipher_suite_dict
            return {}
        except requests.RequestException as e:
            print(f"Warning: Failed to fetch cipher suite data: {str(e)}")
            return {}
    
    def load_json_data(self, filename):
        """Load JSON data from a file."""
        try:
            print(f"Attempting to load file: {filename}")
            print(f"Current working directory: {os.getcwd()}")
            print(f"Absolute path of file: {os.path.abspath(filename)}")
            
            with open(filename, 'r') as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading JSON file: {e}")
            print(f"File exists check: {os.path.exists(filename)}")
            sys.exit(1)
    
    def is_asset_file(self, path):
        """Check if the given path is an asset file."""
        return any(path.lower().endswith(ext) for ext in self.asset_extensions)
    
    def extract_unique_urls(self, json_data, include_assets=False):
        """Extract unique URLs with their SSL information."""
        unique_urls = {}
        
        for entry in json_data:
            # Skip entries without SSL information
            if not entry.get('ssl') or not entry['ssl'].get('protocol') or not entry['ssl'].get('cipherSuite'):
                continue
                
            host = entry.get('host', '')
            path = entry.get('path', '')
            
            # Skip asset files unless explicitly included
            if not include_assets and self.is_asset_file(path):
                continue
                
            url = f"{host}{path}"
            
            if url not in unique_urls:
                unique_urls[url] = {
                    'host': host,
                    'path': path,
                    'protocol': entry['ssl']['protocol'],
                    'cipher_suite': entry['ssl']['cipherSuite']
                }
        
        return unique_urls
    
    def fetch_cipher_suite_info(self, cipher_suite):
        """Fetch detailed information about a cipher suite from cached data."""
        print(f"\nDebug: Looking up cipher suite:")
        print(f"Cipher suite name: {cipher_suite}")
        print(f"Found in cache: {cipher_suite in self.cipher_suite_data}")
        
        # Look up the cipher suite in our cached data using original name
        if cipher_suite in self.cipher_suite_data:
            cs_data = self.cipher_suite_data[cipher_suite]
            details = {
                'Key Exchange': cs_data.get('kex_algorithm', 'Unknown'),
                'Authentication': cs_data.get('auth_algorithm', 'Unknown'),
                'Encryption': cs_data.get('enc_algorithm', 'Unknown'),
                'Hash': cs_data.get('hash_algorithm', 'Unknown')
            }
            
            # Add human-readable descriptions
            details = self.add_human_readable_descriptions(details)
            return details
        
        # If not found, print some available cipher suites for debugging
        print("\nAvailable cipher suites in cache:")
        for cs in list(self.cipher_suite_data.keys())[:5]:  # Show first 5 for brevity
            print(f"- {cs}")
        print("...")
        
        return {'Error': f"Unable to find cipher suite details for {cipher_suite}"}
    
    def add_human_readable_descriptions(self, details):
        """Add human-readable descriptions to cipher suite components."""
        # Key Exchange descriptions
        kex_desc = {
            'ECDHE': 'PFS Elliptic Curve Diffie-Hellman Ephemeral',
            'DHE': 'PFS Diffie-Hellman Ephemeral',
            'ECDH': 'Elliptic Curve Diffie-Hellman (no forward secrecy)',
            'DH': 'Diffie-Hellman (no forward secrecy)',
            'RSA': 'RSA key exchange (no forward secrecy)'
        }
        
        # Authentication descriptions
        auth_desc = {
            'RSA': 'Rivest Shamir Adleman algorithm',
            'ECDSA': 'Elliptic Curve Digital Signature Algorithm',
            'DSS': 'Digital Signature Standard',
            'PSK': 'Pre-Shared Key'
        }
        
        # Encryption descriptions
        enc_desc = {
            'AES_128_GCM': 'AEAD Advanced Encryption Standard with 128bit key in Galois/Counter mode',
            'AES_256_GCM': 'AEAD Advanced Encryption Standard with 256bit key in Galois/Counter mode',
            'AES_128_CBC': 'Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode',
            'AES_256_CBC': 'Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode',
            'CHACHA20_POLY1305': 'AEAD ChaCha20 stream cipher with Poly1305 authenticator'
        }
        
        # Hash descriptions
        hash_desc = {
            'SHA256': 'Secure Hash Algorithm 256',
            'SHA384': 'Secure Hash Algorithm 384',
            'SHA': 'Secure Hash Algorithm (SHA1)',
            'MD5': 'Message Digest 5 (insecure)'
        }
        
        # Update details with descriptions
        key_exchange = details['Key Exchange']
        if key_exchange in kex_desc:
            details['Key Exchange'] = f"{key_exchange} ({kex_desc[key_exchange]})"
        
        auth = details['Authentication']
        if auth in auth_desc:
            details['Authentication'] = f"{auth} ({auth_desc[auth]})"
            # Add RSA warning
            if auth == 'RSA':
                details['RSA Warning'] = "There are reports that servers using the RSA authentication algorithm with keys longer than 3072-bit may experience heavy performance issues."
        
        enc = details['Encryption']
        if enc in enc_desc:
            details['Encryption'] = f"{enc} ({enc_desc[enc]})"
        
        hash_algo = details['Hash']
        if hash_algo in hash_desc:
            details['Hash'] = f"{hash_algo} ({hash_desc[hash_algo]})"
        
        return details
    
    def create_ssl_info_table(self, unique_urls, parallel=True):
        """Create a table with SSL information for each unique URL."""
        table_data = []
        
        if parallel:
            # Use parallel processing to fetch cipher suite details
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {executor.submit(self.fetch_cipher_suite_info, info['cipher_suite']): (url, info) 
                          for url, info in unique_urls.items()}
                
                for future in futures:
                    url, info = futures[future]
                    cipher_details = future.result()
                    table_data.append(self.format_table_row(url, info, cipher_details))
        else:
            # Sequential processing
            for url, info in unique_urls.items():
                cipher_details = self.fetch_cipher_suite_info(info['cipher_suite'])
                table_data.append(self.format_table_row(url, info, cipher_details))
        
        return table_data
    
    def format_table_row(self, url, info, cipher_details):
        """Format a row for the SSL info table."""
        # Create formatted cipher suite details string
        cipher_details_str = ""
        if 'Error' not in cipher_details:
            details = []
            details.append(f"Protocol: {info['protocol']}")
            details.append(f"Key Exchange: {cipher_details.get('Key Exchange', 'Unknown')}")
            details.append(f"Authentication: {cipher_details.get('Authentication', 'Unknown')}")
            
            # Add RSA warning if present
            if 'RSA Warning' in cipher_details:
                details.append(f"RSA Authentication: {cipher_details['RSA Warning']}")
                
            details.append(f"Encryption: {cipher_details.get('Encryption', 'Unknown')}")
            details.append(f"Hash: {cipher_details.get('Hash', 'Unknown')}")
            cipher_details_str = "\n".join(details)
        else:
            cipher_details_str = f"Protocol: {info['protocol']}\n{cipher_details['Error']}"
        
        # Return formatted row
        return [
            url,
            info['protocol'],
            info['cipher_suite'],
            cipher_details_str
        ]
    
    def export_to_json(self, table_data, filename):
        """Export the table data to a JSON file."""
        output = []
        for row in table_data:
            output.append({
                'url': row[0],
                'protocol': row[1],
                'cipher_suite': row[2],
                'details': row[3]
            })
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
    
    def export_to_csv(self, table_data, filename):
        """Export the table data to a CSV file."""
        import csv
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["URL", "SSL Protocol", "Cipher Suite", "Detailed Information"])
            writer.writerows(table_data)

def main():
    parser = argparse.ArgumentParser(description='Analyze SSL/TLS information in network traffic JSON files.')
    parser.add_argument('json_file', help='Path to the JSON file to analyze')
    parser.add_argument('--export', choices=['json', 'csv', 'html', 'markdown'], help='Export results to specified format')
    parser.add_argument('--output', help='Output file name for export')
    parser.add_argument('--sequential', action='store_true', help='Use sequential processing instead of parallel')
    parser.add_argument('--include-assets', action='store_true', help='Include asset files (images, CSS, JS, etc.) in the analysis')
    args = parser.parse_args()
    
    # Initialize SSL analyzer
    analyzer = SSLAnalyzer()
    
    # Load JSON data
    json_data = analyzer.load_json_data(args.json_file)
    
    # Extract unique URLs with SSL info
    unique_urls = analyzer.extract_unique_urls(json_data, include_assets=args.include_assets)
    
    if not unique_urls:
        print("No SSL/TLS connections found in the provided JSON file.")
        sys.exit(0)
    
    # Create table with SSL information
    table_data = analyzer.create_ssl_info_table(unique_urls, not args.sequential)
    
    # Export if requested
    if args.export:
        output_file = args.output or f"ssl_analysis.{args.export}"
        if args.export == 'json':
            analyzer.export_to_json(table_data, output_file)
        elif args.export == 'csv':
            analyzer.export_to_csv(table_data, output_file)
        elif args.export in ['html', 'markdown']:
            with open(output_file, 'w') as f:
                headers = ["URL (host+path)", "SSL Protocol", "Cipher Suite", "Detailed Information"]
                if args.export == 'html':
                    analyzer._is_html_output = True
                    # Add some basic CSS to make the table more readable
                    f.write("""<!DOCTYPE html>
<html>
<head>
<style>
    table { 
        border-collapse: collapse; 
        width: 100%; 
        font-family: Arial, sans-serif;
    }
    th, td { 
        border: 1px solid #ddd; 
        padding: 8px; 
        text-align: left; 
        vertical-align: top;
    }
    th { 
        background-color: #f2f2f2; 
    }
    tr:nth-child(even) { 
        background-color: #f9f9f9; 
    }
    .details-cell {
        white-space: pre-line;
        line-height: 1.5;
    }
</style>
</head>
<body>
""")
                    # Convert the table data to HTML format
                    html_table = tabulate(table_data, headers=headers, tablefmt="html")
                    # Add the details-cell class to the last column
                    html_table = html_table.replace('<td>', '<td class="details-cell">')
                    f.write(html_table)
                    f.write("</body></html>")
                    analyzer._is_html_output = False
                else:  # markdown
                    f.write(tabulate(table_data, headers=headers, tablefmt="pipe"))
        print(f"Results exported to {output_file}")
    
    # Print table
    headers = ["URL (host+path)", "SSL Protocol", "Cipher Suite", "Detailed Information"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    main()
