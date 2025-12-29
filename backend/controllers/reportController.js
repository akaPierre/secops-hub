/**
 * Report Controller
 * Handles PDF report generation
 */

const path = require('path');
const fs = require('fs');
const reportGenerator = require('../services/reportGenerator');
const Threat = require('../models/Threat');
const logger = require('../utils/logger');

/**
 * Generate threat analysis report
 */
const generateThreatReport = async (req, res) => {
  try {
    const { threatData } = req.body;

    if (!threatData) {
      return res.status(400).json({ error: 'Threat data is required' });
    }

    // Create reports directory if it doesn't exist
    const reportsDir = path.join(__dirname, '../../reports');
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }

    // Generate unique filename
    const filename = `threat-report-${Date.now()}.pdf`;
    const outputPath = path.join(reportsDir, filename);

    // Generate PDF
    await reportGenerator.generateThreatReport(threatData, outputPath);

    // Send file
    res.download(outputPath, filename, (err) => {
      if (err) {
        logger.error('File download error:', err);
      }
      // Clean up file after download
      setTimeout(() => {
        if (fs.existsSync(outputPath)) {
          fs.unlinkSync(outputPath);
        }
      }, 60000); // Delete after 1 minute
    });
  } catch (error) {
    logger.error('Report generation error:', error);
    res.status(500).json({ error: 'Failed to generate report' });
  }
};

/**
 * Generate statistics report
 */
const generateStatsReport = async (req, res) => {
  try {
    const stats = await Threat.getStatistics();
    const threats = await Threat.getAll({ limit: 20, offset: 0 });

    const reportsDir = path.join(__dirname, '../../reports');
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }

    const filename = `statistics-report-${Date.now()}.pdf`;
    const outputPath = path.join(reportsDir, filename);

    await reportGenerator.generateStatisticsReport(stats, threats, outputPath);

    res.download(outputPath, filename, (err) => {
      if (err) {
        logger.error('File download error:', err);
      }
      setTimeout(() => {
        if (fs.existsSync(outputPath)) {
          fs.unlinkSync(outputPath);
        }
      }, 60000);
    });
  } catch (error) {
    logger.error('Stats report generation error:', error);
    res.status(500).json({ error: 'Failed to generate statistics report' });
  }
};

module.exports = {
  generateThreatReport,
  generateStatsReport
};