# SecOps Hub - API Documentation

## Base URL

```
http://localhost:5000/api
```

## Authentication

All API endpoints (except `/auth/register` and `/auth/login`) require JWT authentication.

Include the token in the Authorization header:

```
Authorization: Bearer YOUR_JWT_TOKEN
```

## Authentication Endpoints

### Register User

```http
POST /api/auth/register
```

**Request Body:**
```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePass123!",
  "fullName": "John Doe"
}
```

**Response:**
```json
{
  "message": "User registered successfully",
  "user": {
    "id": "uuid",
    "username": "johndoe",
    "email": "john@example.com",
    "fullName": "John Doe",
    "role": "analyst"
  },
  "token": "jwt_token_here"
}
```

### Login

```http
POST /api/auth/login
```

**Request Body:**
```json
{
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

### Get Profile

```http
GET /api/auth/profile
```

**Headers:** `Authorization: Bearer TOKEN`

### Logout

```http
POST /api/auth/logout
```

**Headers:** `Authorization: Bearer TOKEN`

---

## Threat Intelligence Endpoints

### Unified Threat Check

Check a threat indicator across multiple sources (VirusTotal, Shodan, AbuseIPDB).

```http
POST /api/threats/check
```

**Request Body:**
```json
{
  "indicator": "8.8.8.8",
  "type": "ip",
  "save": true
}
```

**Types:** `ip`, `domain`, `hash`, `email`, `url`

**Response:**
```json
{
  "success": true,
  "data": {
    "indicator": "8.8.8.8",
    "indicator_type": "ip",
    "timestamp": "2025-12-29T...",
    "sources": {
      "virustotal": { ... },
      "shodan": { ... },
      "abuseipdb": { ... }
    },
    "risk_assessment": {
      "risk_score": 0,
      "severity": "info",
      "factors": [],
      "recommendation": "SAFE - No threats detected"
    }
  }
}
```

### VirusTotal Check

```http
GET /api/threats/virustotal?indicator=8.8.8.8&type=ip
```

**Query Parameters:**
- `indicator` - IP, domain, or file hash
- `type` - `ip`, `domain`, or `hash`

### Shodan Check

```http
GET /api/threats/shodan?ip=8.8.8.8
```

**Query Parameters:**
- `ip` - IP address to check

### AbuseIPDB Check

```http
GET /api/threats/abuseipdb?ip=8.8.8.8
```

**Query Parameters:**
- `ip` - IP address to check

### Search CVE Database

```http
GET /api/threats/cve/search?keyword=apache&limit=10
```

**Query Parameters:**
- `keyword` - Search term
- `limit` - Number of results (1-100, default: 10)

**Response:**
```json
{
  "success": true,
  "data": {
    "source": "nvd",
    "total_results": 1500,
    "vulnerabilities": [
      {
        "cve_id": "CVE-2024-12345",
        "description": "...",
        "published": "2024-01-15T...",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "references": ["..."]
      }
    ]
  }
}
```

### Get CVE Details

```http
GET /api/threats/cve/CVE-2024-12345
```

### Get All Stored Threats

```http
GET /api/threats?limit=50&offset=0&severity=high
```

**Query Parameters:**
- `limit` - Results per page (default: 50)
- `offset` - Pagination offset (default: 0)
- `severity` - Filter by severity: `critical`, `high`, `medium`, `low`, `info`
- `indicatorType` - Filter by type: `ip`, `domain`, `hash`, etc.

### Get Threat Statistics

```http
GET /api/threats/statistics
```

**Response:**
```json
{
  "success": true,
  "data": {
    "total_threats": 1250,
    "critical_count": 45,
    "high_count": 120,
    "medium_count": 300,
    "low_count": 785,
    "active_threats": 1100,
    "indicator_types": 5,
    "sources": 3
  }
}
```

### Search Threats

```http
GET /api/threats/search?q=malware&limit=50
```

**Query Parameters:**
- `q` - Search query
- `limit` - Max results (default: 50)

---

## Error Responses

All errors follow this format:

```json
{
  "error": "Error message here"
}
```

### Common HTTP Status Codes

- `200` - Success
- `201` - Created
- `400` - Bad Request (validation error)
- `401` - Unauthorized (missing or invalid token)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `409` - Conflict (e.g., user already exists)
- `500` - Internal Server Error

---

## Rate Limiting

- **Window:** 15 minutes
- **Max Requests:** 100 per window per IP

---

## Example cURL Commands

### Check an IP for threats:

```bash
curl -X POST http://localhost:5000/api/threats/check \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "indicator": "1.2.3.4",
    "type": "ip",
    "save": true
  }'
```

### Search for vulnerabilities:

```bash
curl "http://localhost:5000/api/threats/cve/search?keyword=windows&limit=5" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Get threat statistics:

```bash
curl http://localhost:5000/api/threats/statistics \
  -H "Authorization: Bearer YOUR_TOKEN"
```
