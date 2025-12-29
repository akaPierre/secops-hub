/**
 * PDF Report Generator Service
 * Generates professional threat intelligence reports
 */

const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

class ReportGenerator {
  /**
   * Generate Threat Analysis Report
   */
  async generateThreatReport(threatData, outputPath) {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 50, size: 'A4' });
        const writeStream = fs.createWriteStream(outputPath);
        
        doc.pipe(writeStream);

        // Header
        this.addHeader(doc);
        
        // Title
        doc.fontSize(24)
           .fillColor('#00d4ff')
           .text('Threat Intelligence Report', { align: 'center' })
           .moveDown();

        doc.fontSize(10)
           .fillColor('#666666')
           .text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' })
           .moveDown(2);

        // Threat Overview
        doc.fontSize(16)
           .fillColor('#000000')
           .text('Threat Overview', { underline: true })
           .moveDown();

        doc.fontSize(11)
           .fillColor('#333333')
           .text(`Indicator: ${threatData.indicator}`, { bold: true })
           .text(`Type: ${threatData.indicator_type.toUpperCase()}`)
           .text(`Risk Score: ${threatData.risk_assessment.risk_score}/100`)
           .text(`Severity: ${threatData.risk_assessment.severity.toUpperCase()}`)
           .moveDown();

        // Risk Assessment
        doc.fontSize(14)
           .fillColor('#000000')
           .text('Risk Assessment', { underline: true })
           .moveDown(0.5);

        doc.fontSize(11)
           .fillColor('#333333')
           .text(`Recommendation: ${threatData.risk_assessment.recommendation}`, {
             width: 500,
             align: 'justify'
           })
           .moveDown();

        if (threatData.risk_assessment.factors.length > 0) {
          doc.text('Contributing Factors:', { bold: true });
          threatData.risk_assessment.factors.forEach(factor => {
            doc.text(`  • ${factor}`);
          });
          doc.moveDown();
        }

        // Source Analysis
        doc.addPage();
        doc.fontSize(16)
           .fillColor('#000000')
           .text('Source Analysis', { underline: true })
           .moveDown();

        // VirusTotal
        if (threatData.sources.virustotal && !threatData.sources.virustotal.error) {
          this.addSourceSection(doc, 'VirusTotal', threatData.sources.virustotal);
        }

        // Shodan
        if (threatData.sources.shodan && !threatData.sources.shodan.error) {
          this.addSourceSection(doc, 'Shodan', threatData.sources.shodan);
        }

        // AbuseIPDB
        if (threatData.sources.abuseipdb && !threatData.sources.abuseipdb.error) {
          this.addSourceSection(doc, 'AbuseIPDB', threatData.sources.abuseipdb);
        }

        // Footer
        this.addFooter(doc);

        doc.end();

        writeStream.on('finish', () => {
          logger.info('PDF report generated successfully');
          resolve(outputPath);
        });

        writeStream.on('error', reject);
      } catch (error) {
        logger.error('PDF generation error:', error);
        reject(error);
      }
    });
  }

  addHeader(doc) {
    doc.fontSize(10)
       .fillColor('#00d4ff')
       .text('SecOps Hub', 50, 30)
       .fillColor('#666666')
       .text('Security Operations Dashboard', 50, 45);
  }

  addFooter(doc) {
    const bottomY = doc.page.height - 50;
    doc.fontSize(8)
       .fillColor('#999999')
       .text(
         'This report is confidential and for authorized use only.',
         50,
         bottomY,
         { align: 'center' }
       );
  }

  addSourceSection(doc, sourceName, data) {
    doc.fontSize(13)
       .fillColor('#00d4ff')
       .text(sourceName, { bold: true })
       .moveDown(0.3);

    doc.fontSize(10)
       .fillColor('#333333');

    // Display relevant data based on source
    Object.entries(data).forEach(([key, value]) => {
      if (key === 'raw_data' || key === 'source') return;
      
      if (typeof value !== 'object') {
        const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        doc.text(`${displayKey}: ${value}`);
      } else if (Array.isArray(value) && value.length > 0) {
        const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        doc.text(`${displayKey}: ${value.join(', ')}`);
      }
    });

    doc.moveDown();
  }

  /**
   * Generate Statistics Report
   */
  async generateStatisticsReport(stats, threats, outputPath) {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 50 });
        const writeStream = fs.createWriteStream(outputPath);
        
        doc.pipe(writeStream);

        this.addHeader(doc);

        doc.fontSize(24)
           .fillColor('#00d4ff')
           .text('Threat Intelligence Statistics', { align: 'center' })
           .moveDown();

        doc.fontSize(10)
           .fillColor('#666666')
           .text(`Report Period: ${new Date().toLocaleDateString()}`, { align: 'center' })
           .moveDown(2);

        // Statistics Overview
        doc.fontSize(16)
           .fillColor('#000000')
           .text('Overview', { underline: true })
           .moveDown();

        doc.fontSize(11)
           .fillColor('#333333')
           .text(`Total Threats: ${stats.total_threats}`)
           .text(`Critical: ${stats.critical_count}`)
           .text(`High: ${stats.high_count}`)
           .text(`Medium: ${stats.medium_count}`)
           .text(`Low: ${stats.low_count}`)
           .text(`Active Threats: ${stats.active_threats}`)
           .moveDown(2);

        // Recent Threats
        if (threats && threats.length > 0) {
          doc.fontSize(16)
             .fillColor('#000000')
             .text('Recent Threats', { underline: true })
             .moveDown();

          threats.slice(0, 10).forEach(threat => {
            doc.fontSize(10)
               .fillColor('#333333')
               .text(`• ${threat.indicator} (${threat.severity.toUpperCase()}) - Risk: ${threat.risk_score}`);
          });
        }

        this.addFooter(doc);
        doc.end();

        writeStream.on('finish', () => resolve(outputPath));
        writeStream.on('error', reject);
      } catch (error) {
        reject(error);
      }
    });
  }
}

module.exports = new ReportGenerator();