/**
 * User Model
 * Database operations for user management
 */

const bcrypt = require('bcryptjs');
const db = require('../config/database');

class User {
  // Create new user
  static async create({ username, email, password, fullName, role = 'analyst' }) {
    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    const query = `
      INSERT INTO users (username, email, password_hash, full_name, role)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id, username, email, full_name, role, created_at
    `;

    const result = await db.query(query, [
      username,
      email.toLowerCase(),
      passwordHash,
      fullName,
      role
    ]);

    return result.rows[0];
  }

  // Find user by email
  static async findByEmail(email) {
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await db.query(query, [email.toLowerCase()]);
    return result.rows[0];
  }

  // Find user by username
  static async findByUsername(username) {
    const query = 'SELECT * FROM users WHERE username = $1';
    const result = await db.query(query, [username]);
    return result.rows[0];
  }

  // Find user by ID
  static async findById(id) {
    const query = 'SELECT id, username, email, full_name, role, is_active, last_login, created_at FROM users WHERE id = $1';
    const result = await db.query(query, [id]);
    return result.rows[0];
  }

  // Verify password
  static async verifyPassword(password, passwordHash) {
    return await bcrypt.compare(password, passwordHash);
  }

  // Update last login
  static async updateLastLogin(userId) {
    const query = 'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1';
    await db.query(query, [userId]);
  }

  // Update user profile
  static async updateProfile(userId, updates) {
    const allowedUpdates = ['full_name', 'email'];
    const updates_filtered = {};

    Object.keys(updates).forEach(key => {
      if (allowedUpdates.includes(key)) {
        updates_filtered[key] = updates[key];
      }
    });

    if (Object.keys(updates_filtered).length === 0) {
      throw new Error('No valid updates provided');
    }

    const setClause = Object.keys(updates_filtered)
      .map((key, index) => `${key} = $${index + 2}`)
      .join(', ');

    const query = `
      UPDATE users 
      SET ${setClause}, updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING id, username, email, full_name, role
    `;

    const values = [userId, ...Object.values(updates_filtered)];
    const result = await db.query(query, values);

    return result.rows[0];
  }

  // Change password
  static async changePassword(userId, newPassword) {
    const passwordHash = await bcrypt.hash(newPassword, 10);
    const query = 'UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2';
    await db.query(query, [passwordHash, userId]);
  }

  // Get all users (admin only)
  static async getAll(limit = 50, offset = 0) {
    const query = `
      SELECT id, username, email, full_name, role, is_active, last_login, created_at
      FROM users
      ORDER BY created_at DESC
      LIMIT $1 OFFSET $2
    `;
    const result = await db.query(query, [limit, offset]);
    return result.rows;
  }

  // Count total users
  static async count() {
    const query = 'SELECT COUNT(*) as total FROM users';
    const result = await db.query(query);
    return parseInt(result.rows[0].total);
  }
}

module.exports = User;