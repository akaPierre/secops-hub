/**
 * Threat Intelligence Routes
 * /api/threats endpoints
 */

const express = require('express');
const router = express.Router();
const threatController = require('../controllers/threatController');
const { authenticate, authorize } = require('../middleware/auth');

// All threat routes require authentication
router.use(authenticate);

// Unified threat check (queries multiple sources)
router.post('/check', threatController.checkThreat);

// Individual source checks
router.get('/virustotal', threatController.checkVirusTotal);
router.get('/shodan', threatController.checkShodan);
router.get('/abuseipdb', threatController.checkAbuseIPDB);

// CVE database
router.get('/cve/search', threatController.searchCVE);
router.get('/cve/:cveId', threatController.getCVEDetails);

// Stored threats management
router.get('/', threatController.getThreats);
router.get('/statistics', threatController.getStatistics);
router.get('/search', threatController.searchThreats);

module.exports = router;