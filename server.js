require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key';
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// PostgreSQL Database Setup
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Error connecting to PostgreSQL database:', err);
  } else {
    console.log('✅ Connected to PostgreSQL database');
    release();
  }
});

// Initialize Database Schema
async function initializeDatabase() {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');

    // Users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        full_name VARCHAR(255),
        balance DECIMAL(10,2) DEFAULT 0,
        total_earned DECIMAL(10,2) DEFAULT 0,
        referral_code VARCHAR(10) UNIQUE,
        referred_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Stores table
    await client.query(`
      CREATE TABLE IF NOT EXISTS stores (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        logo_url TEXT,
        website_url VARCHAR(500) NOT NULL,
        affiliate_url VARCHAR(500) NOT NULL,
        commission_rate DECIMAL(5,2) DEFAULT 0,
        cashback_rate DECIMAL(5,2) DEFAULT 0,
        category VARCHAR(100) DEFAULT 'general',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Clicks table
    await client.query(`
      CREATE TABLE IF NOT EXISTS clicks (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        store_id INTEGER NOT NULL REFERENCES stores(id),
        ip_address INET,
        user_agent TEXT,
        clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        commission_earned DECIMAL(10,2) DEFAULT 0,
        status VARCHAR(50) DEFAULT 'pending'
      )
    `);

    // Transactions table
    await client.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        store_id INTEGER NOT NULL REFERENCES stores(id),
        click_id INTEGER REFERENCES clicks(id),
        amount DECIMAL(10,2) NOT NULL,
        cashback_amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        confirmed_at TIMESTAMP
      )
    `);

    // Check if stores exist, if not, insert sample stores
    const storeCount = await client.query('SELECT COUNT(*) FROM stores');
    
    if (parseInt(storeCount.rows[0].count) === 0) {
      console.log('🏪 Adding sample stores...');
      
      const sampleStores = [
        ['Amazon India', 'Everything store with millions of products', 'https://logo.clearbit.com/amazon.com', 'https://amazon.in', 'https://amazon.in/?tag=yourcode', 8, 4, 'general'],
        ['Flipkart', 'India\'s leading e-commerce marketplace', 'https://logo.clearbit.com/flipkart.com', 'https://flipkart.com', 'https://flipkart.com/?affid=yourcode', 6, 3, 'general'],
        ['Myntra', 'Fashion and lifestyle destination', 'https://logo.clearbit.com/myntra.com', 'https://myntra.com', 'https://myntra.com/?ref=yourcode', 12, 6, 'fashion'],
        ['Nykaa', 'Beauty and cosmetics online store', 'https://logo.clearbit.com/nykaa.com', 'https://nykaa.com', 'https://nykaa.com/?src=yourcode', 15, 7.5, 'beauty'],
        ['Zomato', 'Food delivery and restaurant discovery', 'https://logo.clearbit.com/zomato.com', 'https://zomato.com', 'https://zomato.com/?r=yourcode', 10, 5, 'food'],
        ['BookMyShow', 'Movie tickets and entertainment', 'https://logo.clearbit.com/bookmyshow.com', 'https://bookmyshow.com', 'https://bookmyshow.com/?ref=yourcode', 5, 2.5, 'entertainment']
      ];

      for (const store of sampleStores) {
        await client.query(
          'INSERT INTO stores (name, description, logo_url, website_url, affiliate_url, commission_rate, cashback_rate, category) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
          store
        );
      }
    }

    await client.query('COMMIT');
    console.log('✅ Database schema initialized successfully');
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Error initializing database:', error);
  } finally {
    client.release();
  }
}

// Initialize database on startup
initializeDatabase();

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// API Routes

// User Registration
app.post('/api/auth/register', async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { email, password, fullName, referralCode } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    const userReferralCode = Math.random().toString(36).substring(2, 8).toUpperCase();
    
    // Check if referral code exists
    let referredById = null;
    if (referralCode) {
      const referrerResult = await client.query('SELECT id FROM users WHERE referral_code = $1', [referralCode]);
      referredById = referrerResult.rows.length > 0 ? referrerResult.rows[0].id : null;
    }
    
    const result = await client.query(
      'INSERT INTO users (email, password, full_name, referral_code, referred_by) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [email, hashedPassword, fullName, userReferralCode, referredById]
    );
    
    res.status(201).json({ 
      message: 'Account created successfully', 
      userId: result.rows[0].id,
      referralCode: userReferralCode
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    if (error.constraint === 'users_email_key') {
      return res.status(400).json({ error: 'Email already registered' });
    }
    res.status(500).json({ error: 'Registration failed' });
  } finally {
    client.release();
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const token = jwt.sign(
      { userId: user.id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );
    
    res.json({ 
      token, 
      user: { 
        id: user.id, 
        email: user.email,
        fullName: user.full_name,
        balance: parseFloat(user.balance),
        totalEarned: parseFloat(user.total_earned),
        referralCode: user.referral_code
      } 
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  } finally {
    client.release();
  }
});

// Get all stores
app.get('/api/stores', async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { category, search } = req.query;
    let query = 'SELECT * FROM stores WHERE is_active = true';
    let params = [];
    let paramCount = 0;
    
    if (category && category !== 'all') {
      paramCount++;
      query += ` AND category = $${paramCount}`;
      params.push(category);
    }
    
    if (search) {
      paramCount++;
      query += ` AND name ILIKE $${paramCount}`;
      params.push(`%${search}%`);
    }
    
    query += ' ORDER BY name ASC';
    
    const result = await client.query(query, params);
    
    // Convert decimal fields to numbers
    const stores = result.rows.map(store => ({
      ...store,
      commission_rate: parseFloat(store.commission_rate),
      cashback_rate: parseFloat(store.cashback_rate)
    }));
    
    res.json(stores);
    
  } catch (error) {
    console.error('Stores fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch stores' });
  } finally {
    client.release();
  }
});

// Get store categories
app.get('/api/stores/categories', async (req, res) => {
  const client = await pool.connect();
  
  try {
    const result = await client.query('SELECT DISTINCT category FROM stores WHERE is_active = true ORDER BY category');
    res.json(result.rows.map(row => row.category));
  } catch (error) {
    console.error('Categories fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch categories' });
  } finally {
    client.release();
  }
});

// Track store click
app.post('/api/click', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { storeId } = req.body;
    const userId = req.user.userId;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent');
    
    if (!storeId) {
      return res.status(400).json({ error: 'Store ID is required' });
    }
    
    // Get store information
    const storeResult = await client.query('SELECT * FROM stores WHERE id = $1 AND is_active = true', [storeId]);
    
    if (storeResult.rows.length === 0) {
      return res.status(404).json({ error: 'Store not found' });
    }
    
    const store = storeResult.rows[0];
    
    // Record the click
    const clickResult = await client.query(
      'INSERT INTO clicks (user_id, store_id, ip_address, user_agent) VALUES ($1, $2, $3, $4) RETURNING id',
      [userId, storeId, ipAddress, userAgent]
    );
    
    res.json({ 
      success: true,
      clickId: clickResult.rows[0].id,
      store: store.name,
      cashbackRate: `${store.cashback_rate}%`,
      affiliateUrl: store.affiliate_url
    });
    
  } catch (error) {
    console.error('Click tracking error:', error);
    res.status(500).json({ error: 'Failed to track click' });
  } finally {
    client.release();
  }
});

// Get user dashboard data
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const userId = req.user.userId;
    
    // Get user info
    const userResult = await client.query('SELECT * FROM users WHERE id = $1', [userId]);
    
    // Get stats
    const statsResult = await client.query(`
      SELECT 
        COUNT(c.id) as total_clicks,
        COUNT(DISTINCT c.store_id) as stores_visited,
        SUM(CASE WHEN c.status = 'confirmed' THEN c.commission_earned ELSE 0 END) as confirmed_earnings
      FROM clicks c 
      WHERE c.user_id = $1
    `, [userId]);
    
    // Get recent clicks
    const recentClicksResult = await client.query(`
      SELECT c.*, s.name as store_name, s.logo_url
      FROM clicks c
      JOIN stores s ON c.store_id = s.id
      WHERE c.user_id = $1
      ORDER BY c.clicked_at DESC
      LIMIT 10
    `, [userId]);
    
    const user = userResult.rows[0];
    const stats = statsResult.rows[0];
    
    res.json({
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        balance: parseFloat(user.balance),
        totalEarned: parseFloat(user.total_earned),
        referralCode: user.referral_code
      },
      stats: {
        total_clicks: parseInt(stats.total_clicks) || 0,
        stores_visited: parseInt(stats.stores_visited) || 0,
        confirmed_earnings: parseFloat(stats.confirmed_earnings) || 0
      },
      recentClicks: recentClicksResult.rows || []
    });
    
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  } finally {
    client.release();
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    database: 'postgresql'
  });
});

// Serve static files and handle client-side routing
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Cashback App running on port ${PORT}`);
  console.log(`🌍 Environment: ${NODE_ENV}`);
  console.log(`🐘 Database: PostgreSQL`);
});

// Graceful shutdown
const gracefulShutdown = () => {
  console.log('📴 Received shutdown signal, closing server...');
  server.close(() => {
    console.log('⚡ HTTP server closed');
    pool.end(() => {
      console.log('🔒 Database connection pool closed');
      process.exit(0);
    });
  });
};

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

module.exports = app;
