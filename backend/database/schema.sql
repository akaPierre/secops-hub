-- SecOps Hub Database Schema
-- PostgreSQL Database Structure

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(100),
  role VARCHAR(20) DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst', 'viewer')),
  is_active BOOLEAN DEFAULT true,
  last_login TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Threat Intelligence table
CREATE TABLE IF NOT EXISTS threats (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  threat_type VARCHAR(50) NOT NULL,
  indicator VARCHAR(255) NOT NULL,
  indicator_type VARCHAR(50) NOT NULL CHECK (indicator_type IN ('ip', 'domain', 'url', 'hash', 'email')),
  severity VARCHAR(20) DEFAULT 'medium' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  risk_score INTEGER DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  source VARCHAR(50) NOT NULL,
  description TEXT,
  tags TEXT[],
  first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  is_active BOOLEAN DEFAULT true,
  metadata JSONB,
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Security Events/Logs table
CREATE TABLE IF NOT EXISTS security_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  event_type VARCHAR(50) NOT NULL,
  severity VARCHAR(20) DEFAULT 'info' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  source_ip INET,
  destination_ip INET,
  source_port INTEGER,
  destination_port INTEGER,
  protocol VARCHAR(20),
  description TEXT,
  raw_log TEXT,
  parsed_data JSONB,
  is_alert BOOLEAN DEFAULT false,
  is_resolved BOOLEAN DEFAULT false,
  resolved_by UUID REFERENCES users(id),
  resolved_at TIMESTAMP,
  tags TEXT[],
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerability Scans table
CREATE TABLE IF NOT EXISTS vulnerability_scans (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_name VARCHAR(100) NOT NULL,
  scan_type VARCHAR(50) NOT NULL,
  target VARCHAR(255) NOT NULL,
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
  started_at TIMESTAMP,
  completed_at TIMESTAMP,
  duration_seconds INTEGER,
  vulnerabilities_found INTEGER DEFAULT 0,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  low_count INTEGER DEFAULT 0,
  scan_results JSONB,
  error_message TEXT,
  scheduled BOOLEAN DEFAULT false,
  schedule_cron VARCHAR(50),
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerability Findings table
CREATE TABLE IF NOT EXISTS vulnerability_findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID REFERENCES vulnerability_scans(id) ON DELETE CASCADE,
  vulnerability_name VARCHAR(255) NOT NULL,
  cve_id VARCHAR(50),
  severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  cvss_score DECIMAL(3,1) CHECK (cvss_score BETWEEN 0 AND 10),
  description TEXT,
  affected_component VARCHAR(255),
  remediation TEXT,
  references TEXT[],
  proof_of_concept TEXT,
  is_false_positive BOOLEAN DEFAULT false,
  is_mitigated BOOLEAN DEFAULT false,
  mitigated_at TIMESTAMP,
  mitigated_by UUID REFERENCES users(id),
  discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Alerts table
CREATE TABLE IF NOT EXISTS alerts (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  alert_type VARCHAR(50) NOT NULL,
  severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  title VARCHAR(255) NOT NULL,
  description TEXT,
  source VARCHAR(100),
  is_read BOOLEAN DEFAULT false,
  is_resolved BOOLEAN DEFAULT false,
  resolved_by UUID REFERENCES users(id),
  resolved_at TIMESTAMP,
  resolution_notes TEXT,
  metadata JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- API Keys table (for external integrations)
CREATE TABLE IF NOT EXISTS api_keys (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  key_name VARCHAR(100) NOT NULL,
  api_key_hash VARCHAR(255) NOT NULL,
  permissions TEXT[],
  last_used TIMESTAMP,
  expires_at TIMESTAMP,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit Log table
CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id),
  action VARCHAR(100) NOT NULL,
  resource_type VARCHAR(50),
  resource_id UUID,
  ip_address INET,
  user_agent TEXT,
  details JSONB,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better query performance
CREATE INDEX idx_threats_indicator ON threats(indicator);
CREATE INDEX idx_threats_severity ON threats(severity);
CREATE INDEX idx_threats_created_at ON threats(created_at);
CREATE INDEX idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX idx_security_events_severity ON security_events(severity);
CREATE INDEX idx_security_events_source_ip ON security_events(source_ip);
CREATE INDEX idx_vulnerability_scans_status ON vulnerability_scans(status);
CREATE INDEX idx_vulnerability_scans_created_at ON vulnerability_scans(created_at);
CREATE INDEX idx_vulnerability_findings_scan_id ON vulnerability_findings(scan_id);
CREATE INDEX idx_vulnerability_findings_severity ON vulnerability_findings(severity);
CREATE INDEX idx_alerts_created_at ON alerts(created_at);
CREATE INDEX idx_alerts_is_resolved ON alerts(is_resolved);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at trigger to users table
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();