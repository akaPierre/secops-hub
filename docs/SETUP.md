# SecOps Hub - Setup Guide

Complete guide to get SecOps Hub running on your local machine.

## Prerequisites

Before starting, ensure you have the following installed:

- **Node.js** >= 18.0.0 ([Download](https://nodejs.org/))
- **PostgreSQL** >= 14 ([Download](https://www.postgresql.org/download/))
- **Redis** >= 6.0 ([Download](https://redis.io/download))
- **Git** ([Download](https://git-scm.com/downloads))

## Quick Start (Local Development)

### 1. Clone the Repository

```bash
git clone https://github.com/akaPierre/secops-hub.git
cd secops-hub
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Setup PostgreSQL Database

#### On Linux (Arch/Ubuntu/Debian):

```bash
# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql
```

Inside PostgreSQL shell:
```sql
CREATE DATABASE secops_hub;
CREATE USER secops_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE secops_hub TO secops_user;
\q
```

#### On macOS:

```bash
# Using Homebrew
brew services start postgresql

# Create database
psql postgres
CREATE DATABASE secops_hub;
CREATE USER secops_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE secops_hub TO secops_user;
\q
```

#### On Windows:

1. Install PostgreSQL from the official installer
2. Use pgAdmin or command line to create database and user

### 4. Setup Redis

#### On Linux:

```bash
# Start Redis service
sudo systemctl start redis
sudo systemctl enable redis

# Test connection
redis-cli ping
# Should return: PONG
```

#### On macOS:

```bash
brew services start redis
```

#### On Windows:

1. Download Redis for Windows
2. Run `redis-server.exe`

### 5. Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` and update the following:

```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=secops_hub
DB_USER=secops_user
DB_PASSWORD=your_secure_password  # Use the password you set

# JWT
JWT_SECRET=your_random_jwt_secret_key_here  # Generate a strong random string

# Optional: Add API keys later
# VIRUSTOTAL_API_KEY=
# SHODAN_API_KEY=
# ABUSEIPDB_API_KEY=
```

### 6. Initialize Database Schema

```bash
node backend/scripts/setup-database.js
```

You should see:
```
🔧 Starting database setup...
📄 Executing schema SQL...
✅ Database schema created successfully!
```

### 7. Start the Server

```bash
npm run dev
```

You should see:
```
🛡️  SecOps Hub API running on port 5000
📊 Environment: development
🔗 Health check: http://localhost:5000/health
```

### 8. Test the API

#### Health Check:
```bash
curl http://localhost:5000/health
```

#### Register a User:
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@secops.local",
    "password": "SecurePass123!",
    "fullName": "Admin User"
  }'
```

#### Login:
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@secops.local",
    "password": "SecurePass123!"
  }'
```

Save the `token` from the response!

#### Get Profile (Protected Route):
```bash
curl http://localhost:5000/api/auth/profile \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## Docker Setup (Alternative)

If you prefer using Docker:

### 1. Make sure Docker is installed

```bash
docker --version
docker-compose --version
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your settings
```

### 3. Start services

```bash
docker-compose up -d
```

### 4. Initialize database

```bash
docker-compose exec backend node scripts/setup-database.js
```

### 5. Check logs

```bash
docker-compose logs -f backend
```

## Next Steps

✅ **Phase 1 Complete!** You now have:
- Working authentication system (register, login, JWT)
- PostgreSQL database with complete schema
- Redis caching ready
- API documentation endpoint

### What to Build Next:

1. **Threat Intelligence Module** - Integrate VirusTotal, Shodan, AbuseIPDB
2. **Frontend Dashboard** - React UI for visualization
3. **Log Analysis** - SIEM capabilities for security events
4. **Vulnerability Scanner** - Custom scanning engine

## Troubleshooting

### Database Connection Issues:

```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Test connection manually
psql -h localhost -U secops_user -d secops_hub
```

### Redis Connection Issues:

```bash
# Check Redis is running
redis-cli ping

# Check Redis service
sudo systemctl status redis
```

### Port Already in Use:

```bash
# Find process using port 5000
sudo lsof -i :5000

# Kill the process
kill -9 <PID>
```

## API Documentation

Full API documentation available at: http://localhost:5000/api

## Need Help?

Open an issue on GitHub: https://github.com/akaPierre/secops-hub/issues
