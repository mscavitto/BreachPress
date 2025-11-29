# BreachPress

A comprehensive penetration testing tool for WordPress that intelligently enumerates attack surfaces, discovers users, and performs efficient password spraying across multiple authentication mechanisms.

## Features

- **Automatic Attack Surface Enumeration**
  - Detects wp-login.php availability
  - Checks REST API accessibility
  - Identifies XML-RPC availability
  - Tests for XML-RPC system.multicall support

- **User Enumeration**
  - REST API user discovery (`/wp-json/wp/v2/users`)
  - wp-login.php user validation

- **Multiple Attack Methods**
  - **XML-RPC Multicall** (Most Efficient) - Tests hundreds of credentials in a single HTTP request
  - **XML-RPC Single** - Individual XML-RPC authentication attempts
  - **wp-login.php** - Traditional form-based authentication
  - **Auto-selection** - Automatically chooses the best available method

- **Smart Features**
  - Automatic method selection based on available attack vectors
  - Batch processing for multicall attacks
  - Configurable delays and timeouts
  - Colored terminal output
  - Verbose logging option
  - Output file support

## Installation

```bash
chmod +x breachpress.py

# Install dependencies (none required beyond standard library!)
python3 --version  # Requires Python 3.6+
```

## Usage

### Basic Usage

**Enumerate attack surface and users only:**
```bash
python3 breachpress.py -u https://target.com --enumerate-only
```

**Auto-enumerate users and spray with password list:**
```bash
python3 breachpress.py -u https://target.com --auto-enum -P passwords.txt
```

**Spray with specific user and password lists:**
```bash
python3 breachpress.py -u https://target.com -U users.txt -P passwords.txt
```

**Force specific attack method:**
```bash
python3 breachpress.py -u https://target.com -U users.txt -P passwords.txt --method xmlrpc-multicall
```

**Single user/password test:**
```bash
python3 breachpress.py -u https://target.com --user admin --password Password123!
```

### Advanced Options

```bash
python3 breachpress.py -u https://target.com \
    -U users.txt \
    -P passwords.txt \
    --method auto \
    --batch-size 200 \
    --delay 2.0 \
    --timeout 15 \
    --no-ssl-verify \
    --verbose \
    -o successful_creds.txt
```

### Command-Line Options

```
Required:
  -u, --url URL              Target WordPress URL

User Options:
  -U, --userlist FILE        File containing usernames (one per line)
  --user USERNAME            Single username to test
  --auto-enum                Automatically enumerate users via REST API

Password Options:
  -P, --passwordlist FILE    File containing passwords (one per line)
  --password PASSWORD        Single password to test

Attack Options:
  --method METHOD            Attack method: auto, xmlrpc-multicall, xmlrpc-single, wp-login
                            (default: auto - selects best available)
  --enumerate-only           Only enumerate attack surface and users
  --batch-size N             Multicall batch size (default: 100)
  --delay SECONDS            Delay between requests (default: 1.0)
  --timeout SECONDS          Request timeout (default: 10)

Output Options:
  -o, --output FILE          Save successful credentials to file
  -v, --verbose              Enable verbose output
  --no-ssl-verify            Disable SSL certificate verification
```

## Attack Methods Explained

### XML-RPC Multicall (Preferred)

The most efficient method when available. Uses `system.multicall` to bundle multiple authentication attempts into a single HTTP request.

**Advantages:**
- Tests 100+ credentials per HTTP request
- Bypasses traditional rate limiting (which counts HTTP requests)
- Significantly faster than other methods
- Reduces detection surface (fewer requests in logs)

**Example:**
- Traditional: 1000 passwords = 1000 HTTP requests
- Multicall: 1000 passwords = 10 HTTP requests (batch size 100)

### XML-RPC Single

Uses individual `wp.getUsersBlogs` calls via XML-RPC. Less efficient than multicall but still effective.

### wp-login.php

Traditional form-based authentication. Least efficient but most commonly available.

## Example Workflow

```bash
# Step 1: Enumerate attack surface
python3 breachpress.py -u https://target.com --enumerate-only

# Step 2: If REST API available, users are auto-discovered
# Step 3: Spray with password list
python3 breachpress.py -u https://target.com --auto-enum -P common_passwords.txt -v

# Step 4: Review results
cat successful_creds.txt
```

## Creating Password Lists

**Season-based passwords:**
```bash
cat > seasonal_passwords.txt << EOF
Winter2024
Winter2025
Spring2024
Spring2025
Summer2024
Autumn2024
Fall2024
Password123!
Companyname2024!
EOF
```

**Common corporate patterns:**
```bash
cat > corporate_passwords.txt << EOF
Welcome123!
Password1!
Company2024!
January2024
February2024
ChangeMe123!
EOF
```

## Output Example

```
======================================================================
BreachPress
By: Michael @ Breach Craft
======================================================================
Target: https://target.com

[*] Enumerating Attack Surface...
[+] wp-login.php: Available
[+] REST API: Available
[+] XML-RPC: Available
[++] XML-RPC system.multicall: Available (BEST ATTACK VECTOR)

[*] Enumerating users via REST API...
[+] Found user: admin
[+] Found user: wpuser

[*] Auto-selected method: XML-RPC Multicall (most efficient)

[*] Spraying via XML-RPC system.multicall (OPTIMIZED)...
[*] Testing 2 users with 50 passwords
[*] Total attempts: 100
[*] HTTP requests needed: 1

[*] Processing batch 1 (100 attempts)...

======================================================================
[*] Spray Complete!
======================================================================

[+++] Found 1 valid credential(s):

  wpuser:Summer2024!

[*] Credentials saved to successful_creds.txt
```

## Detection Evasion

The tool includes several features to help evade detection:

1. **Configurable delays** between requests
2. **Batch processing** reduces total HTTP requests
3. **SSL verification bypass** for testing environments
4. **User-agent** can be modified in code if needed

## Legal Disclaimer

This tool is designed for authorized penetration testing and security assessments only. Always obtain written permission before testing any systems you do not own. Unauthorized access to computer systems is illegal.

## Troubleshooting

**Connection errors:**
- Use `--no-ssl-verify` for self-signed certificates
- Increase `--timeout` for slow servers

**No methods available:**
- Target may have hardened WordPress installation
- Try different endpoints or manual testing

**Rate limiting encountered:**
- Increase `--delay` value
- Reduce `--batch-size` for multicall
- Use proxy rotation (requires code modification)

## Future Enhancements

- [ ] Proxy support for rotation
- [ ] User-agent randomization
- [ ] Additional enumeration methods
- [ ] REST API authentication support
- [ ] Threading for wp-login method
- [ ] CAPTCHA detection

## Author

Michael @ Breach Craft

## Version

1.0.0 - Initial Release
