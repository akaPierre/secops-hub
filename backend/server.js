/**
 * SecOps Hub - Main Server Entry Point
 * 
 * Real-time Security Operations Dashboard
 * Author: Daniel Pierre Fachini
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const logger = require('./utils/logger');

// Import routes
const authRoutes = require('./routes/authRoutes');

const app = express();
const PORT = process.env.PORT || 5000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.get('user-agent')
  });
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// API routes
app.get('/api', (req, res) => {
  res.json({
    message: 'SecOps Hub API',
    version: '0.1.0',
    documentation: 'https://github.com/akaPierre/secops-hub',
    endpoints: {
      health: '/health',
      auth: {
        register: 'POST /api/auth/register',
        login: 'POST /api/auth/login',
        profile: 'GET /api/auth/profile (protected)',
        logout: 'POST /api/auth/logout (protected)'
      },
      threats: '/api/threats/* (coming soon)',
      logs: '/api/logs/* (coming soon)',
      scans: '/api/scans/* (coming soon)',
      alerts: '/api/alerts/* (coming soon)'
    }
  });
});

// Mount routes
app.use('/api/auth', authRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Cannot ${req.method} ${req.path}`
  });
});

// Error handler
app.use((err, req, res, next) => {
  logger.error('Server error:', { error: err.message, stack: err.stack });
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    logger.info('HTTP server closed');
  });
});

// Start server
const server = app.listen(PORT, () => {
  logger.info(`🛡️  SecOps Hub API running on port ${PORT}`);
  logger.info(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`🔗 Health check: http://localhost:${PORT}/health`);
  logger.info(`📚 API docs: http://localhost:${PORT}/api`);
});

module.exports = app;