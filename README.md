# SecOps Hub 🛡️

> Real-time Security Operations Dashboard - Unified threat intelligence, vulnerability scanning, log analysis, and network monitoring platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)

## 🎯 Project Overview

SecOps Hub is a comprehensive security operations platform that combines multiple cybersecurity capabilities into a single, professional-grade application. Built for security professionals, DevOps teams, and organizations looking to centralize their security monitoring and threat intelligence operations.

### Key Features

#### 🔍 Threat Intelligence Engine
- Real-time threat data aggregation from multiple sources (VirusTotal, Shodan, AbuseIPDB, CVE databases)
- Automated vulnerability correlation and risk scoring
- Threat actor tracking and IOC (Indicators of Compromise) management

#### 📊 Security Information & Event Management (SIEM)
- Centralized log aggregation and analysis
- Pattern-based attack detection (brute force, SQL injection, XSS)
- Real-time alerting via webhooks (Slack, Discord, Email)
- Geographic threat visualization

#### 🌐 Network Traffic Analysis
- Passive network monitoring and anomaly detection
- Port scanning detection and honeypot integration
- Protocol analysis for malicious pattern identification

#### 🔐 Automated Penetration Testing
- Custom vulnerability scanner for OWASP Top 10
- Scheduled security assessments with historical tracking
- Professional penetration testing report generation (PDF)

## 🏗️ Architecture

```
secops-hub/
├── backend/                 # Node.js API server
│   ├── controllers/        # Route controllers
│   ├── services/           # Business logic & integrations
│   ├── models/             # Database models
│   ├── middleware/         # Auth, validation, rate limiting
│   └── utils/              # Helper functions
├── frontend/               # React dashboard
│   ├── src/
│   │   ├── components/    # Reusable UI components
│   │   ├── pages/         # Dashboard pages
│   │   ├── services/      # API client
│   │   └── utils/         # Frontend helpers
├── scanners/              # Custom security scanners
│   ├── vuln-scanner/     # Vulnerability scanning engine
│   ├── log-analyzer/     # Log parsing and analysis
│   └── network-monitor/  # Traffic analysis tools
├── docker/                # Docker configurations
└── docs/                  # Documentation
```

## 🚀 Getting Started

### Prerequisites

- Node.js >= 18.0.0
- PostgreSQL >= 14
- Redis >= 6.0
- Docker & Docker Compose (optional)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/akaPierre/secops-hub.git
cd secops-hub
```

2. **Install dependencies**
```bash
# Backend
cd backend
npm install

# Frontend
cd ../frontend
npm install
```

3. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your API keys and configuration
```

4. **Start with Docker Compose (recommended)**
```bash
docker-compose up -d
```

Or manually:
```bash
# Start PostgreSQL and Redis
# Then start backend
cd backend
npm run dev

# In another terminal, start frontend
cd frontend
npm start
```

5. **Access the dashboard**
- Frontend: http://localhost:3000
- API: http://localhost:5000

## 📋 Development Roadmap

### Phase 1: Foundation (Current)
- [x] Project setup and architecture
- [ ] Backend API structure with Express
- [ ] PostgreSQL database schema design
- [ ] JWT authentication system
- [ ] Basic React frontend with routing

### Phase 2: Threat Intelligence
- [ ] VirusTotal API integration
- [ ] Shodan API integration
- [ ] AbuseIPDB integration
- [ ] CVE database connector
- [ ] Threat correlation engine
- [ ] Risk scoring algorithm

### Phase 3: SIEM Capabilities
- [ ] Log ingestion API endpoints
- [ ] Log parsing for common formats (syslog, JSON, Apache)
- [ ] Attack pattern detection rules
- [ ] Real-time alerting system
- [ ] Webhook integrations (Slack, Discord)
- [ ] Event timeline visualization

### Phase 4: Network Monitoring
- [ ] Packet capture integration
- [ ] Port scanning detection
- [ ] Traffic anomaly detection
- [ ] Geographic IP mapping
- [ ] Protocol analysis engine

### Phase 5: Penetration Testing
- [ ] Custom vulnerability scanner
- [ ] OWASP Top 10 automated checks
- [ ] Scheduled scanning system
- [ ] Report generation engine
- [ ] Historical vulnerability tracking

### Phase 6: Advanced Features
- [ ] Machine learning for anomaly detection
- [ ] Custom rule engine for threat detection
- [ ] Multi-tenant support
- [ ] API rate limiting and security
- [ ] Comprehensive documentation

## 🔧 Technology Stack

### Backend
- **Runtime**: Node.js with Express.js
- **Database**: PostgreSQL (structured data) + Redis (caching)
- **Authentication**: JWT with bcrypt
- **WebSockets**: Socket.io for real-time updates
- **APIs**: Axios for external integrations

### Frontend
- **Framework**: React 18
- **State Management**: Redux Toolkit
- **UI Components**: Material-UI / Tailwind CSS
- **Charts**: Chart.js / Recharts
- **Real-time**: Socket.io-client

### DevOps
- **Containerization**: Docker & Docker Compose
- **CI/CD**: GitHub Actions
- **Testing**: Jest + Supertest
- **Code Quality**: ESLint + Prettier

## 🤝 Contributing

This is currently a portfolio project, but suggestions and feedback are welcome! Feel free to open issues or submit pull requests.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

## 👤 Author

**Daniel Pierre Fachini**
- GitHub: [@akaPierre](https://github.com/akaPierre)
- Website: [danielpierre.tech](https://www.danielpierre.tech/)
- Twitter: [@PierreDani_](https://twitter.com/PierreDani_)

## 🙏 Acknowledgments

- Inspired by real-world security operations centers (SOCs)
- Built as a comprehensive cybersecurity portfolio project
- Demonstrates full-stack development and security expertise

---

⭐ **Star this repository if you find it helpful!**