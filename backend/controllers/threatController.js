/**
 * Threat Intelligence Controller
 * Handles threat intelligence API endpoints
 */

const Joi = require('joi');
const threatService = require('../services/threatIntelligence');
const Threat = require('../models/Threat');
const logger = require('../utils/logger');

// Validation schemas
const checkThreatSchema = Joi.object({
  indicator: Joi.string().required(),
  type: Joi.string().valid('ip', 'domain', 'hash', 'email', 'url').required(),
  save: Joi.boolean().default(true)
});

const searchCVESchema = Joi.object({
  keyword: Joi.string().required(),
  limit: Joi.number().min(1).max(100).default(10)
});

/**
 * Check threat indicator across multiple sources
 */
const checkThreat = async (req, res) => {
  try {
    const { error, value } = checkThreatSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { indicator, type, save } = value;

    logger.info(`Checking threat: ${indicator} (${type})`, { user: req.user.username });

    // Query threat intelligence sources
    const results = await threatService.checkThreat(indicator, type);

    // Save to database if requested
    if (save && results.risk_assessment.risk_score > 0) {
      try {
        await Threat.create({
          threatType: 'intelligence_scan',
          indicator,
          indicatorType: type,
          severity: results.risk_assessment.severity,
          riskScore: results.risk_assessment.risk_score,
          source: Object.keys(results.sources).join(', '),
          description: results.risk_assessment.recommendation,
          tags: results.risk_assessment.factors,
          metadata: results,
          createdBy: req.user.id
        });
      } catch (dbError) {
        logger.error('Failed to save threat to database:', dbError);
      }
    }

    res.json({
      success: true,
      data: results
    });
  } catch (error) {
    logger.error('Threat check error:', error);
    res.status(500).json({ error: error.message || 'Threat check failed' });
  }
};

/**
 * Check IP on VirusTotal
 */
const checkVirusTotal = async (req, res) => {
  try {
    const { indicator, type } = req.query;

    if (!indicator || !type) {
      return res.status(400).json({ error: 'indicator and type are required' });
    }

    let result;
    if (type === 'ip') {
      result = await threatService.checkIPVirusTotal(indicator);
    } else if (type === 'domain') {
      result = await threatService.checkDomainVirusTotal(indicator);
    } else if (type === 'hash') {
      result = await threatService.checkHashVirusTotal(indicator);
    } else {
      return res.status(400).json({ error: 'Invalid type. Must be ip, domain, or hash' });
    }

    res.json({ success: true, data: result });
  } catch (error) {
    logger.error('VirusTotal check error:', error);
    res.status(500).json({ error: error.message });
  }
};

/**
 * Check IP on Shodan
 */
const checkShodan = async (req, res) => {
  try {
    const { ip } = req.query;

    if (!ip) {
      return res.status(400).json({ error: 'ip parameter is required' });
    }

    const result = await threatService.checkIPShodan(ip);
    res.json({ success: true, data: result });
  } catch (error) {
    logger.error('Shodan check error:', error);
    res.status(500).json({ error: error.message });
  }
};

/**
 * Check IP on AbuseIPDB
 */
const checkAbuseIPDB = async (req, res) => {
  try {
    const { ip } = req.query;

    if (!ip) {
      return res.status(400).json({ error: 'ip parameter is required' });
    }

    const result = await threatService.checkIPAbuseIPDB(ip);
    res.json({ success: true, data: result });
  } catch (error) {
    logger.error('AbuseIPDB check error:', error);
    res.status(500).json({ error: error.message });
  }
};

/**
 * Search CVE database
 */
const searchCVE = async (req, res) => {
  try {
    const { error, value } = searchCVESchema.validate(req.query);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { keyword, limit } = value;
    const result = await threatService.searchCVE(keyword, limit);
    
    res.json({ success: true, data: result });
  } catch (error) {
    logger.error('CVE search error:', error);
    res.status(500).json({ error: error.message });
  }
};

/**
 * Get CVE details
 */
const getCVEDetails = async (req, res) => {
  try {
    const { cveId } = req.params;

    if (!cveId) {
      return res.status(400).json({ error: 'CVE ID is required' });
    }

    const result = await threatService.getCVEDetails(cveId);
    res.json({ success: true, data: result });
  } catch (error) {
    logger.error('CVE details error:', error);
    res.status(500).json({ error: error.message });
  }
};

/**
 * Get all stored threats
 */
const getThreats = async (req, res) => {
  try {
    const { limit = 50, offset = 0, severity, indicatorType } = req.query;

    const threats = await Threat.getAll({
      limit: parseInt(limit),
      offset: parseInt(offset),
      severity,
      indicatorType
    });

    const stats = await Threat.getStatistics();

    res.json({
      success: true,
      data: threats,
      statistics: stats,
      pagination: {
        limit: parseInt(limit),
        offset: parseInt(offset),
        total: parseInt(stats.total_threats)
      }
    });
  } catch (error) {
    logger.error('Get threats error:', error);
    res.status(500).json({ error: 'Failed to fetch threats' });
  }
};

/**
 * Get threat statistics
 */
const getStatistics = async (req, res) => {
  try {
    const stats = await Threat.getStatistics();
    res.json({ success: true, data: stats });
  } catch (error) {
    logger.error('Get statistics error:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
};

/**
 * Search threats
 */
const searchThreats = async (req, res) => {
  try {
    const { q, limit = 50 } = req.query;

    if (!q) {
      return res.status(400).json({ error: 'Search query (q) is required' });
    }

    const results = await Threat.search(q, parseInt(limit));
    res.json({ success: true, data: results, count: results.length });
  } catch (error) {
    logger.error('Search threats error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
};

module.exports = {
  checkThreat,
  checkVirusTotal,
  checkShodan,
  checkAbuseIPDB,
  searchCVE,
  getCVEDetails,
  getThreats,
  getStatistics,
  searchThreats
};