/**
 * Database Setup Script
 * Initializes PostgreSQL database with schema
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { pool } = require('../config/database');

const setupDatabase = async () => {
  try {
    console.log('🔧 Starting database setup...');

    // Read schema file
    const schemaPath = path.join(__dirname, '../database/schema.sql');
    const schema = fs.readFileSync(schemaPath, 'utf8');

    console.log('📄 Executing schema SQL...');
    await pool.query(schema);

    console.log('✅ Database schema created successfully!');
    console.log('');
    console.log('📊 Database tables created:');
    console.log('  - users');
    console.log('  - threats');
    console.log('  - security_events');
    console.log('  - vulnerability_scans');
    console.log('  - vulnerability_findings');
    console.log('  - alerts');
    console.log('  - api_keys');
    console.log('  - audit_logs');
    console.log('');
    console.log('🎉 Database setup complete!');
    console.log('💡 You can now start the server with: npm run dev');

    process.exit(0);
  } catch (error) {
    console.error('❌ Database setup failed:', error.message);
    console.error(error);
    process.exit(1);
  }
};

setupDatabase();