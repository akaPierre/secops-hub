/**
 * Threat Model
 * Database operations for threat intelligence
 */

const db = require('../config/database');

class Threat {
  /**
   * Create new threat entry
   */
  static async create({
    threatType,
    indicator,
    indicatorType,
    severity,
    riskScore,
    source,
    description,
    tags,
    metadata,
    createdBy
  }) {
    const query = `
      INSERT INTO threats (
        threat_type, indicator, indicator_type, severity, risk_score,
        source, description, tags, metadata, created_by
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *
    `;

    const result = await db.query(query, [
      threatType,
      indicator,
      indicatorType,
      severity,
      riskScore,
      source,
      description,
      tags,
      JSON.stringify(metadata),
      createdBy
    ]);

    return result.rows[0];
  }

  /**
   * Find threat by indicator
   */
  static async findByIndicator(indicator) {
    const query = 'SELECT * FROM threats WHERE indicator = $1 ORDER BY created_at DESC';
    const result = await db.query(query, [indicator]);
    return result.rows;
  }

  /**
   * Get all threats with pagination
   */
  static async getAll({ limit = 50, offset = 0, severity, indicatorType, isActive = true }) {
    let query = 'SELECT * FROM threats WHERE 1=1';
    const params = [];
    let paramCount = 1;

    if (severity) {
      query += ` AND severity = $${paramCount}`;
      params.push(severity);
      paramCount++;
    }

    if (indicatorType) {
      query += ` AND indicator_type = $${paramCount}`;
      params.push(indicatorType);
      paramCount++;
    }

    if (isActive !== undefined) {
      query += ` AND is_active = $${paramCount}`;
      params.push(isActive);
      paramCount++;
    }

    query += ` ORDER BY created_at DESC LIMIT $${paramCount} OFFSET $${paramCount + 1}`;
    params.push(limit, offset);

    const result = await db.query(query, params);
    return result.rows;
  }

  /**
   * Update threat
   */
  static async update(id, updates) {
    const allowedFields = ['severity', 'risk_score', 'description', 'tags', 'is_active', 'metadata'];
    const setClause = [];
    const values = [];
    let paramCount = 1;

    Object.keys(updates).forEach(key => {
      if (allowedFields.includes(key)) {
        setClause.push(`${key} = $${paramCount}`);
        values.push(updates[key]);
        paramCount++;
      }
    });

    if (setClause.length === 0) {
      throw new Error('No valid fields to update');
    }

    setClause.push('last_seen = CURRENT_TIMESTAMP');

    const query = `
      UPDATE threats
      SET ${setClause.join(', ')}
      WHERE id = $${paramCount}
      RETURNING *
    `;

    values.push(id);
    const result = await db.query(query, values);
    return result.rows[0];
  }

  /**
   * Get threat statistics
   */
  static async getStatistics() {
    const query = `
      SELECT
        COUNT(*) as total_threats,
        COUNT(*) FILTER (WHERE severity = 'critical') as critical_count,
        COUNT(*) FILTER (WHERE severity = 'high') as high_count,
        COUNT(*) FILTER (WHERE severity = 'medium') as medium_count,
        COUNT(*) FILTER (WHERE severity = 'low') as low_count,
        COUNT(*) FILTER (WHERE is_active = true) as active_threats,
        COUNT(DISTINCT indicator_type) as indicator_types,
        COUNT(DISTINCT source) as sources
      FROM threats
    `;

    const result = await db.query(query);
    return result.rows[0];
  }

  /**
   * Search threats
   */
  static async search(searchTerm, limit = 50) {
    const query = `
      SELECT * FROM threats
      WHERE indicator ILIKE $1
         OR description ILIKE $1
         OR $2 = ANY(tags)
      ORDER BY created_at DESC
      LIMIT $3
    `;

    const result = await db.query(query, [`%${searchTerm}%`, searchTerm, limit]);
    return result.rows;
  }

  /**
   * Delete threat
   */
  static async delete(id) {
    const query = 'DELETE FROM threats WHERE id = $1 RETURNING *';
    const result = await db.query(query, [id]);
    return result.rows[0];
  }
}

module.exports = Threat;