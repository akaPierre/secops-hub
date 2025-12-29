/**
 * WebSocket Threat Feed
 * Real-time threat notifications
 */

const logger = require('../utils/logger');

class ThreatFeed {
  constructor(io) {
    this.io = io;
    this.clients = new Map();
  }

  initialize() {
    this.io.on('connection', (socket) => {
      logger.info(`Client connected: ${socket.id}`);
      this.clients.set(socket.id, socket);

      // Send welcome message
      socket.emit('connected', {
        message: 'Connected to SecOps Hub threat feed',
        timestamp: new Date().toISOString()
      });

      // Handle authentication
      socket.on('authenticate', (data) => {
        logger.info(`Client authenticated: ${data.userId}`);
        socket.userId = data.userId;
      });

      // Handle disconnection
      socket.on('disconnect', () => {
        logger.info(`Client disconnected: ${socket.id}`);
        this.clients.delete(socket.id);
      });
    });
  }

  /**
   * Broadcast new threat to all connected clients
   */
  broadcastThreat(threatData) {
    logger.info('Broadcasting new threat to all clients');
    this.io.emit('new-threat', {
      threat: threatData,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Send threat update to specific user
   */
  sendToUser(userId, event, data) {
    this.clients.forEach((socket) => {
      if (socket.userId === userId) {
        socket.emit(event, data);
      }
    });
  }

  /**
   * Broadcast statistics update
   */
  broadcastStats(stats) {
    this.io.emit('stats-update', {
      stats,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Send alert notification
   */
  broadcastAlert(alert) {
    this.io.emit('alert', {
      alert,
      timestamp: new Date().toISOString()
    });
  }
}

module.exports = ThreatFeed;