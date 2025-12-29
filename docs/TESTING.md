# SecOps Hub - Testing Guide

Complete guide for testing all features of SecOps Hub.

## Prerequisites

1. **Server running**: `npm run dev`
2. **Database initialized**: `npm run setup-db`
3. **API Keys configured** in `.env`:
   - `VIRUSTOTAL_API_KEY` - [Get free key](https://www.virustotal.com/gui/join-us)
   - `SHODAN_API_KEY` - [Get free key](https://account.shodan.io/register)
   - `ABUSEIPDB_API_KEY` - [Get free key](https://www.abuseipdb.com/register)

> **Note:** All features work without API keys, but you'll get "API key not configured" errors. The CVE database doesn't require API keys!

## Setup Test Environment

### 1. Create a Test User

```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@secops.local",
    "password": "TestPass123!",
    "fullName": "Test User"
  }'
```

**Save the token from the response!**

### 2. Login (if needed)

```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@secops.local",
    "password": "TestPass123!"
  }'
```

### 3. Set Token as Environment Variable

```bash
# Linux/macOS
export TOKEN="your_jwt_token_here"

# Windows (PowerShell)
$env:TOKEN="your_jwt_token_here"
```

---

## Testing Threat Intelligence

### 1. Unified Threat Check (Multi-Source)

Check an IP across VirusTotal, Shodan, and AbuseIPDB:

```bash
curl -X POST http://localhost:5000/api/threats/check \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "indicator": "1.1.1.1",
    "type": "ip",
    "save": true
  }'
```

**Test with known malicious IP:**
```bash
curl -X POST http://localhost:5000/api/threats/check \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "indicator": "185.220.101.1",
    "type": "ip",
    "save": true
  }'
```

**Check a domain:**
```bash
curl -X POST http://localhost:5000/api/threats/check \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "indicator": "google.com",
    "type": "domain",
    "save": true
  }'
```

**Check a file hash:**
```bash
curl -X POST http://localhost:5000/api/threats/check \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "indicator": "44d88612fea8a8f36de82e1278abb02f",
    "type": "hash",
    "save": true
  }'
```

### 2. VirusTotal Individual Check

```bash
# Check IP
curl "http://localhost:5000/api/threats/virustotal?indicator=8.8.8.8&type=ip" \
  -H "Authorization: Bearer $TOKEN"

# Check domain
curl "http://localhost:5000/api/threats/virustotal?indicator=example.com&type=domain" \
  -H "Authorization: Bearer $TOKEN"

# Check file hash (EICAR test file)
curl "http://localhost:5000/api/threats/virustotal?indicator=44d88612fea8a8f36de82e1278abb02f&type=hash" \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Shodan Check

```bash
# Check a known server (Google DNS)
curl "http://localhost:5000/api/threats/shodan?ip=8.8.8.8" \
  -H "Authorization: Bearer $TOKEN"

# Check another IP
curl "http://localhost:5000/api/threats/shodan?ip=1.1.1.1" \
  -H "Authorization: Bearer $TOKEN"
```

### 4. AbuseIPDB Check

```bash
# Check Cloudflare DNS
curl "http://localhost:5000/api/threats/abuseipdb?ip=1.1.1.1" \
  -H "Authorization: Bearer $TOKEN"

# Check Google DNS
curl "http://localhost:5000/api/threats/abuseipdb?ip=8.8.8.8" \
  -H "Authorization: Bearer $TOKEN"
```

### 5. CVE Database Search (No API Key Required!)

```bash
# Search for Apache vulnerabilities
curl "http://localhost:5000/api/threats/cve/search?keyword=apache&limit=5" \
  -H "Authorization: Bearer $TOKEN"

# Search for Windows vulnerabilities
curl "http://localhost:5000/api/threats/cve/search?keyword=windows&limit=10" \
  -H "Authorization: Bearer $TOKEN"

# Search for Log4j
curl "http://localhost:5000/api/threats/cve/search?keyword=log4j&limit=5" \
  -H "Authorization: Bearer $TOKEN"

# Search for OpenSSL
curl "http://localhost:5000/api/threats/cve/search?keyword=openssl&limit=5" \
  -H "Authorization: Bearer $TOKEN"
```

### 6. Get CVE Details

```bash
# Get details for Log4Shell
curl "http://localhost:5000/api/threats/cve/CVE-2021-44228" \
  -H "Authorization: Bearer $TOKEN"

# Get details for Heartbleed
curl "http://localhost:5000/api/threats/cve/CVE-2014-0160" \
  -H "Authorization: Bearer $TOKEN"
```

### 7. Get All Stored Threats

```bash
# Get all threats
curl "http://localhost:5000/api/threats/" \
  -H "Authorization: Bearer $TOKEN"

# Get only critical threats
curl "http://localhost:5000/api/threats/?severity=critical" \
  -H "Authorization: Bearer $TOKEN"

# Get threats with pagination
curl "http://localhost:5000/api/threats/?limit=10&offset=0" \
  -H "Authorization: Bearer $TOKEN"
```

### 8. Get Threat Statistics

```bash
curl "http://localhost:5000/api/threats/statistics" \
  -H "Authorization: Bearer $TOKEN"
```

### 9. Search Threats

```bash
# Search for specific indicator
curl "http://localhost:5000/api/threats/search?q=1.1.1.1" \
  -H "Authorization: Bearer $TOKEN"

# Search for malware
curl "http://localhost:5000/api/threats/search?q=malware" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Testing Authentication

### Get Your Profile

```bash
curl http://localhost:5000/api/auth/profile \
  -H "Authorization: Bearer $TOKEN"
```

### Logout

```bash
curl -X POST http://localhost:5000/api/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

---

## Testing with Python (Optional)

Create `test_secops.py`:

```python
import requests
import json

# Configuration
BASE_URL = "http://localhost:5000/api"
EMAIL = "test@secops.local"
PASSWORD = "TestPass123!"

# Login
response = requests.post(f"{BASE_URL}/auth/login", json={
    "email": EMAIL,
    "password": PASSWORD
})
token = response.json()["token"]
print(f"Token: {token[:20]}...")

headers = {"Authorization": f"Bearer {token}"}

# Check threat
print("\n=== Checking IP Threat ===")
response = requests.post(f"{BASE_URL}/threats/check", 
    headers=headers,
    json={
        "indicator": "1.1.1.1",
        "type": "ip",
        "save": True
    }
)
print(json.dumps(response.json(), indent=2))

# Search CVE
print("\n=== Searching CVE Database ===")
response = requests.get(f"{BASE_URL}/threats/cve/search",
    headers=headers,
    params={"keyword": "apache", "limit": 3}
)
print(json.dumps(response.json(), indent=2))

# Get statistics
print("\n=== Threat Statistics ===")
response = requests.get(f"{BASE_URL}/threats/statistics", headers=headers)
print(json.dumps(response.json(), indent=2))
```

Run it:
```bash
python test_secops.py
```

---

## Expected Results

### Successful Threat Check Response:

```json
{
  "success": true,
  "data": {
    "indicator": "1.1.1.1",
    "indicator_type": "ip",
    "timestamp": "2025-12-29T...",
    "sources": {
      "virustotal": {
        "source": "virustotal",
        "reputation_score": 0,
        "malicious": 0,
        "harmless": 85,
        "country": "US"
      },
      "shodan": {
        "open_ports": [53, 80, 443],
        "country": "United States",
        "isp": "Cloudflare"
      },
      "abuseipdb": {
        "abuse_confidence_score": 0,
        "total_reports": 0
      }
    },
    "risk_assessment": {
      "risk_score": 0,
      "severity": "info",
      "factors": ["VT: 0", "AbuseIPDB: 0"],
      "recommendation": "SAFE - No threats detected"
    }
  }
}
```

### Successful CVE Search:

```json
{
  "success": true,
  "data": {
    "source": "nvd",
    "total_results": 1523,
    "vulnerabilities": [
      {
        "cve_id": "CVE-2024-12345",
        "description": "Apache vulnerability...",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "published": "2024-01-15T..."
      }
    ]
  }
}
```

---

## Troubleshooting

### "API key not configured" errors

**Solution:** Add API keys to your `.env` file:

```bash
VIRUSTOTAL_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

Restart the server: `npm run dev`

### "Authentication required" error

**Solution:** Make sure you're including the token:

```bash
-H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### "No information available" from Shodan

**Solution:** This is normal! Shodan only has data for IPs it has scanned. Try these IPs:
- `8.8.8.8` (Google DNS)
- `1.1.1.1` (Cloudflare)

### Rate limiting errors

**Solution:** Wait 15 minutes or adjust rate limits in `.env`:

```bash
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

---

## Getting Free API Keys

### VirusTotal
1. Visit https://www.virustotal.com/gui/join-us
2. Sign up for free account
3. Go to your profile → API Key
4. **Free tier:** 500 requests/day

### Shodan
1. Visit https://account.shodan.io/register
2. Create free account
3. Go to Account → API Key
4. **Free tier:** 100 results/month

### AbuseIPDB
1. Visit https://www.abuseipdb.com/register
2. Create free account
3. Go to Account → API
4. **Free tier:** 1,000 requests/day

---

## Next Steps

Once testing is complete, you can:

1. **Build the Frontend Dashboard** - Visualize threat data
2. **Add Log Analysis** - SIEM capabilities
3. **Create Vulnerability Scanner** - Custom scanning engine
4. **Implement Alerting** - Webhook notifications

Great job! Your threat intelligence system is working! 🎉
