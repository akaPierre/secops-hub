/**
 * Threat Intelligence Service
 * Integrates multiple threat intelligence sources
 */

const axios = require('axios');
const redisClient = require('../config/redis');
const logger = require('../utils/logger');

class ThreatIntelligenceService {
  constructor() {
    this.virusTotalKey = process.env.VIRUSTOTAL_API_KEY;
    this.shodanKey = process.env.SHODAN_API_KEY;
    this.abuseIPDBKey = process.env.ABUSEIPDB_API_KEY;
    this.cacheExpiry = 3600; // 1 hour cache
  }

  /**
   * Check cache before making API call
   */
  async getFromCache(key) {
    try {
      const cached = await redisClient.get(key);
      if (cached) {
        logger.info(`Cache hit for: ${key}`);
        return JSON.parse(cached);
      }
      return null;
    } catch (error) {
      logger.error('Redis cache error:', error);
      return null;
    }
  }

  /**
   * Store result in cache
   */
  async setCache(key, data, expiry = this.cacheExpiry) {
    try {
      await redisClient.setEx(key, expiry, JSON.stringify(data));
    } catch (error) {
      logger.error('Redis cache set error:', error);
    }
  }

  /**
   * VirusTotal - Check IP address reputation
   */
  async checkIPVirusTotal(ip) {
    if (!this.virusTotalKey) {
      throw new Error('VirusTotal API key not configured');
    }

    const cacheKey = `vt:ip:${ip}`;
    const cached = await this.getFromCache(cacheKey);
    if (cached) return cached;

    try {
      const response = await axios.get(
        `https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
        {
          headers: { 'x-apikey': this.virusTotalKey },
          timeout: 10000
        }
      );

      const data = response.data.data;
      const attributes = data.attributes;
      const lastAnalysisStats = attributes.last_analysis_stats || {};

      const result = {
        source: 'virustotal',
        indicator: ip,
        indicator_type: 'ip',
        reputation_score: this.calculateVTScore(lastAnalysisStats),
        malicious: lastAnalysisStats.malicious || 0,
        suspicious: lastAnalysisStats.suspicious || 0,
        harmless: lastAnalysisStats.harmless || 0,
        undetected: lastAnalysisStats.undetected || 0,
        country: attributes.country || 'Unknown',
        as_owner: attributes.as_owner || 'Unknown',
        last_analysis_date: attributes.last_analysis_date,
        raw_data: data
      };

      await this.setCache(cacheKey, result);
      return result;
    } catch (error) {
      logger.error('VirusTotal IP check error:', error.message);
      throw new Error(`VirusTotal API error: ${error.response?.data?.error?.message || error.message}`);
    }
  }

  /**
   * VirusTotal - Check domain reputation
   */
  async checkDomainVirusTotal(domain) {
    if (!this.virusTotalKey) {
      throw new Error('VirusTotal API key not configured');
    }

    const cacheKey = `vt:domain:${domain}`;
    const cached = await this.getFromCache(cacheKey);
    if (cached) return cached;

    try {
      const response = await axios.get(
        `https://www.virustotal.com/api/v3/domains/${domain}`,
        {
          headers: { 'x-apikey': this.virusTotalKey },
          timeout: 10000
        }
      );

      const data = response.data.data;
      const attributes = data.attributes;
      const lastAnalysisStats = attributes.last_analysis_stats || {};

      const result = {
        source: 'virustotal',
        indicator: domain,
        indicator_type: 'domain',
        reputation_score: this.calculateVTScore(lastAnalysisStats),
        malicious: lastAnalysisStats.malicious || 0,
        suspicious: lastAnalysisStats.suspicious || 0,
        harmless: lastAnalysisStats.harmless || 0,
        undetected: lastAnalysisStats.undetected || 0,
        categories: attributes.categories || {},
        last_analysis_date: attributes.last_analysis_date,
        raw_data: data
      };

      await this.setCache(cacheKey, result);
      return result;
    } catch (error) {
      logger.error('VirusTotal domain check error:', error.message);
      throw new Error(`VirusTotal API error: ${error.response?.data?.error?.message || error.message}`);
    }
  }

  /**
   * VirusTotal - Check file hash
   */
  async checkHashVirusTotal(hash) {
    if (!this.virusTotalKey) {
      throw new Error('VirusTotal API key not configured');
    }

    const cacheKey = `vt:hash:${hash}`;
    const cached = await this.getFromCache(cacheKey);
    if (cached) return cached;

    try {
      const response = await axios.get(
        `https://www.virustotal.com/api/v3/files/${hash}`,
        {
          headers: { 'x-apikey': this.virusTotalKey },
          timeout: 10000
        }
      );

      const data = response.data.data;
      const attributes = data.attributes;
      const lastAnalysisStats = attributes.last_analysis_stats || {};

      const result = {
        source: 'virustotal',
        indicator: hash,
        indicator_type: 'hash',
        reputation_score: this.calculateVTScore(lastAnalysisStats),
        malicious: lastAnalysisStats.malicious || 0,
        suspicious: lastAnalysisStats.suspicious || 0,
        harmless: lastAnalysisStats.harmless || 0,
        undetected: lastAnalysisStats.undetected || 0,
        file_type: attributes.type_description || 'Unknown',
        file_size: attributes.size || 0,
        names: attributes.names || [],
        last_analysis_date: attributes.last_analysis_date,
        raw_data: data
      };

      await this.setCache(cacheKey, result);
      return result;
    } catch (error) {
      logger.error('VirusTotal hash check error:', error.message);
      throw new Error(`VirusTotal API error: ${error.response?.data?.error?.message || error.message}`);
    }
  }

  /**
   * Shodan - Check IP information
   */
  async checkIPShodan(ip) {
    if (!this.shodanKey) {
      throw new Error('Shodan API key not configured');
    }

    const cacheKey = `shodan:ip:${ip}`;
    const cached = await this.getFromCache(cacheKey);
    if (cached) return cached;

    try {
      const response = await axios.get(
        `https://api.shodan.io/shodan/host/${ip}`,
        {
          params: { key: this.shodanKey },
          timeout: 10000
        }
      );

      const data = response.data;

      const result = {
        source: 'shodan',
        indicator: ip,
        indicator_type: 'ip',
        open_ports: data.ports || [],
        vulnerabilities: data.vulns || [],
        hostnames: data.hostnames || [],
        domains: data.domains || [],
        country: data.country_name || 'Unknown',
        city: data.city || 'Unknown',
        isp: data.isp || 'Unknown',
        organization: data.org || 'Unknown',
        last_update: data.last_update,
        services: (data.data || []).map(service => ({
          port: service.port,
          protocol: service.transport,
          product: service.product,
          version: service.version,
          banner: service.data
        })),
        raw_data: data
      };

      await this.setCache(cacheKey, result);
      return result;
    } catch (error) {
      logger.error('Shodan IP check error:', error.message);
      if (error.response?.status === 404) {
        throw new Error('No information available for this IP on Shodan');
      }
      throw new Error(`Shodan API error: ${error.message}`);
    }
  }

  /**
   * AbuseIPDB - Check IP reputation
   */
  async checkIPAbuseIPDB(ip) {
    if (!this.abuseIPDBKey) {
      throw new Error('AbuseIPDB API key not configured');
    }

    const cacheKey = `abuseipdb:ip:${ip}`;
    const cached = await this.getFromCache(cacheKey);
    if (cached) return cached;

    try {
      const response = await axios.get(
        'https://api.abuseipdb.com/api/v2/check',
        {
          params: {
            ipAddress: ip,
            maxAgeInDays: 90,
            verbose: true
          },
          headers: {
            'Key': this.abuseIPDBKey,
            'Accept': 'application/json'
          },
          timeout: 10000
        }
      );

      const data = response.data.data;

      const result = {
        source: 'abuseipdb',
        indicator: ip,
        indicator_type: 'ip',
        abuse_confidence_score: data.abuseConfidenceScore,
        total_reports: data.totalReports,
        num_distinct_users: data.numDistinctUsers,
        is_whitelisted: data.isWhitelisted,
        country_code: data.countryCode,
        usage_type: data.usageType,
        isp: data.isp,
        domain: data.domain,
        last_reported_at: data.lastReportedAt,
        reports: data.reports || [],
        raw_data: data
      };

      await this.setCache(cacheKey, result);
      return result;
    } catch (error) {
      logger.error('AbuseIPDB check error:', error.message);
      throw new Error(`AbuseIPDB API error: ${error.response?.data?.errors?.[0]?.detail || error.message}`);
    }
  }

  /**
   * CVE Database - Search for vulnerabilities
   */
  async searchCVE(keyword, limit = 10) {
    const cacheKey = `cve:search:${keyword}:${limit}`;
    const cached = await this.getFromCache(cacheKey);
    if (cached) return cached;

    try {
      const response = await axios.get(
        'https://services.nvd.nist.gov/rest/json/cves/2.0',
        {
          params: {
            keywordSearch: keyword,
            resultsPerPage: limit
          },
          headers: {
            'User-Agent': 'SecOps-Hub/0.1.0'
          },
          timeout: 15000
        }
      );

      const vulnerabilities = response.data.vulnerabilities || [];

      const result = {
        source: 'nvd',
        total_results: response.data.totalResults || 0,
        vulnerabilities: vulnerabilities.map(vuln => {
          const cve = vuln.cve;
          const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV2?.[0];
          
          return {
            cve_id: cve.id,
            description: cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description',
            published: cve.published,
            last_modified: cve.lastModified,
            cvss_score: metrics?.cvssData?.baseScore || 0,
            severity: metrics?.cvssData?.baseSeverity || 'UNKNOWN',
            vector_string: metrics?.cvssData?.vectorString,
            references: cve.references?.map(ref => ref.url) || [],
            cwe: cve.weaknesses?.[0]?.description?.[0]?.value
          };
        })
      };

      await this.setCache(cacheKey, result, 7200); // Cache for 2 hours
      return result;
    } catch (error) {
      logger.error('CVE search error:', error.message);
      throw new Error(`CVE database error: ${error.message}`);
    }
  }

  /**
   * Get specific CVE details
   */
  async getCVEDetails(cveId) {
    const cacheKey = `cve:detail:${cveId}`;
    const cached = await this.getFromCache(cacheKey);
    if (cached) return cached;

    try {
      const response = await axios.get(
        `https://services.nvd.nist.gov/rest/json/cves/2.0`,
        {
          params: { cveId },
          headers: {
            'User-Agent': 'SecOps-Hub/0.1.0'
          },
          timeout: 15000
        }
      );

      const cve = response.data.vulnerabilities?.[0]?.cve;
      if (!cve) {
        throw new Error('CVE not found');
      }

      const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV2?.[0];

      const result = {
        source: 'nvd',
        cve_id: cve.id,
        description: cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description',
        published: cve.published,
        last_modified: cve.lastModified,
        cvss_score: metrics?.cvssData?.baseScore || 0,
        severity: metrics?.cvssData?.baseSeverity || 'UNKNOWN',
        vector_string: metrics?.cvssData?.vectorString,
        exploitability_score: metrics?.exploitabilityScore,
        impact_score: metrics?.impactScore,
        references: cve.references?.map(ref => ({
          url: ref.url,
          source: ref.source,
          tags: ref.tags
        })) || [],
        weaknesses: cve.weaknesses?.map(w => w.description?.[0]?.value) || [],
        configurations: cve.configurations,
        raw_data: cve
      };

      await this.setCache(cacheKey, result, 86400); // Cache for 24 hours
      return result;
    } catch (error) {
      logger.error('CVE details error:', error.message);
      throw new Error(`CVE database error: ${error.message}`);
    }
  }

  /**
   * Unified threat check - queries multiple sources
   */
  async checkThreat(indicator, indicatorType) {
    const results = {
      indicator,
      indicator_type: indicatorType,
      timestamp: new Date().toISOString(),
      sources: {}
    };

    try {
      if (indicatorType === 'ip') {
        // Check all IP sources in parallel
        const checks = [];
        
        if (this.virusTotalKey) {
          checks.push(
            this.checkIPVirusTotal(indicator)
              .then(data => { results.sources.virustotal = data; })
              .catch(err => { results.sources.virustotal = { error: err.message }; })
          );
        }

        if (this.shodanKey) {
          checks.push(
            this.checkIPShodan(indicator)
              .then(data => { results.sources.shodan = data; })
              .catch(err => { results.sources.shodan = { error: err.message }; })
          );
        }

        if (this.abuseIPDBKey) {
          checks.push(
            this.checkIPAbuseIPDB(indicator)
              .then(data => { results.sources.abuseipdb = data; })
              .catch(err => { results.sources.abuseipdb = { error: err.message }; })
          );
        }

        await Promise.all(checks);
      } else if (indicatorType === 'domain') {
        if (this.virusTotalKey) {
          results.sources.virustotal = await this.checkDomainVirusTotal(indicator)
            .catch(err => ({ error: err.message }));
        }
      } else if (indicatorType === 'hash') {
        if (this.virusTotalKey) {
          results.sources.virustotal = await this.checkHashVirusTotal(indicator)
            .catch(err => ({ error: err.message }));
        }
      }

      // Calculate overall risk score
      results.risk_assessment = this.calculateOverallRisk(results.sources);

      return results;
    } catch (error) {
      logger.error('Unified threat check error:', error);
      throw error;
    }
  }

  /**
   * Calculate VirusTotal score (0-100)
   */
  calculateVTScore(stats) {
    const total = (stats.malicious || 0) + (stats.suspicious || 0) + 
                  (stats.harmless || 0) + (stats.undetected || 0);
    
    if (total === 0) return 0;
    
    const maliciousScore = ((stats.malicious || 0) * 100) / total;
    const suspiciousScore = ((stats.suspicious || 0) * 50) / total;
    
    return Math.round(maliciousScore + suspiciousScore);
  }

  /**
   * Calculate overall risk from multiple sources
   */
  calculateOverallRisk(sources) {
    let totalScore = 0;
    let sourceCount = 0;
    const factors = [];

    if (sources.virustotal && !sources.virustotal.error) {
      totalScore += sources.virustotal.reputation_score || 0;
      sourceCount++;
      factors.push(`VT: ${sources.virustotal.reputation_score}`);
    }

    if (sources.abuseipdb && !sources.abuseipdb.error) {
      totalScore += sources.abuseipdb.abuse_confidence_score || 0;
      sourceCount++;
      factors.push(`AbuseIPDB: ${sources.abuseipdb.abuse_confidence_score}`);
    }

    if (sources.shodan && !sources.shodan.error) {
      const vulnScore = (sources.shodan.vulnerabilities?.length || 0) > 0 ? 50 : 0;
      totalScore += vulnScore;
      if (vulnScore > 0) {
        sourceCount++;
        factors.push(`Shodan: ${sources.shodan.vulnerabilities.length} vulns`);
      }
    }

    const averageScore = sourceCount > 0 ? Math.round(totalScore / sourceCount) : 0;

    let severity = 'info';
    if (averageScore >= 75) severity = 'critical';
    else if (averageScore >= 50) severity = 'high';
    else if (averageScore >= 25) severity = 'medium';
    else if (averageScore > 0) severity = 'low';

    return {
      risk_score: averageScore,
      severity,
      factors,
      recommendation: this.getRiskRecommendation(averageScore)
    };
  }

  /**
   * Get risk recommendation
   */
  getRiskRecommendation(score) {
    if (score >= 75) return 'BLOCK IMMEDIATELY - High threat detected';
    if (score >= 50) return 'INVESTIGATE - Suspicious activity detected';
    if (score >= 25) return 'MONITOR - Potentially malicious';
    if (score > 0) return 'REVIEW - Low risk detected';
    return 'SAFE - No threats detected';
  }
}

module.exports = new ThreatIntelligenceService();