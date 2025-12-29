/**
 * Report Routes
 * /api/reports endpoints
 */

const express = require('express');
const router = express.Router();
const reportController = require('../controllers/reportController');
const { authenticate } = require('../middleware/auth');

// All routes require authentication
router.use(authenticate);

router.post('/threat', reportController.generateThreatReport);
router.get('/statistics', reportController.generateStatsReport);

module.exports = router;