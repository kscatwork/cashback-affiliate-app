require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
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

// Database Setup
const dbPath = NODE_ENV === 'production' ? '/tmp/cashback.db' : './cashback.db';
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('✅ Connected to SQLite database');
  }
});

// Initialize Database Schema
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    full_name TEXT,
    balance REAL DEFAULT 0,
    total_earned REAL DEFAULT 0,
    referral_code TEXT UNIQUE,
    referred_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(referred_by) REFERENCES users(id)
  )`);

  // Stores table
  db.run(`CREATE TABLE IF NOT EXISTS stores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    logo_url TEXT,
    website_url TEXT NOT NULL,
    affiliate_url TEXT NOT NULL,
    commission_rate REAL DEFAULT 0,
    cashback_rate REAL DEFAULT 0,
    category TEXT DEFAULT 'general',
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Clicks table
  db.run(`CREATE TABLE IF NOT EXISTS clicks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    store_id INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    clicked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    commission_earned REAL DEFAULT 0,
    status TEXT DEFAULT 'pending',
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(store_id) REFERENCES stores(id)
  )`);

  // Transactions table for cashback tracking
  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    store_id INTEGER NOT NULL,
    click_id INTEGER,
    amount REAL NOT NULL,
    cashback_amount REAL NOT NULL,
    status TEXT DEFAULT 'pending',
    transaction_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    confirmed_at DATETIME,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(store_id) REFERENCES stores(id),
    FOREIGN KEY(click_id) REFERENCES clicks(id)
  )`);

  // Insert sample stores
  db.get("SELECT COUNT(*) as count FROM stores", (err, result) => {
    if (!err && result.count === 0) {
      console.log('🏪 Adding sample stores...');
      const sampleStores = [
        ['Amazon India', 'Everything store with millions of products', 'https://logo.clearbit.com/amazon.com', 'https://amazon.in', 'https://amazon.in/?tag=yourcode', 8, 4, 'general'],
        ['Flipkart', 'India\'s leading e-commerce marketplace', 'https://logo.clearbit.com/flipkart.com', 'https://flipkart.com', 'https://flipkart.com/?affid=yourcode', 6, 3, 'general'],
        ['Myntra', 'Fashion and lifestyle destination', 'https://logo.clearbit.com/myntra.com', 'https://myntra.com', 'https://myntra.com/?ref=yourcode', 12, 6, 'fashion'],
        ['Nykaa', 'Beauty and cosmetics online store', 'https://logo.clearbit.com/nykaa.com', 'https://nykaa.com', 'https://nykaa.com/?src=yourcode', 15, 7.5, 'beauty'],
        ['Zomato', 'Food delivery and restaurant discovery', 'https://logo.clearbit.com/zomato.com', 'https://zomato.com', 'https://zomato.com/?r=yourcode', 10, 5, 'food'],
        ['BookMyShow', 'Movie tickets and entertainment', 'https://logo.clearbit.com/bookmyshow.com', 'https://bookmyshow.com', 'https://bookmyshow.com/?ref=yourcode', 5, 2.5, 'entertainment']
      ];

      sampleStores.forEach(store => {
        db.run('INSERT INTO stores (name, description, logo_url, website_url, affiliate_url, commission_rate, cashback_rate, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', store);
      });
    }
  });
});

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
      const referrer = await new Promise((resolve, reject) => {
        db.get('SELECT id FROM users WHERE referral_code = ?', [referralCode], (err, row) => {
          if (err) reject(err);
          resolve(row);
        });
      });
      referredById = referrer ? referrer.id : null;
    }
    
    db.run('INSERT INTO users (email, password, full_name, referral_code, referred_by) VALUES (?, ?, ?, ?, ?)', 
      [email, hashedPassword, fullName, userReferralCode, referredById], 
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Email already registered' });
          }
          return res.status(500).json({ error: 'Registration failed' });
        }
        
        res.status(201).json({ 
          message: 'Account created successfully', 
          userId: this.lastID,
          referralCode: userReferralCode
        });
      });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!user || !await bcrypt.compare(password, user.password)) {
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
          balance: user.balance,
          totalEarned: user.total_earned,
          referralCode: user.referral_code
        } 
      });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Get all stores
app.get('/api/stores', (req, res) => {
  const { category, search } = req.query;
  let query = 'SELECT * FROM stores WHERE is_active = 1';
  let params = [];
  
  if (category && category !== 'all') {
    query += ' AND category = ?';
    params.push(category);
  }
  
  if (search) {
    query += ' AND name LIKE ?';
    params.push(`%${search}%`);
  }
  
  query += ' ORDER BY name ASC';
  
  db.all(query, params, (err, stores) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch stores' });
    }
    res.json(stores);
  });
});

// Get store categories
app.get('/api/stores/categories', (req, res) => {
  db.all('SELECT DISTINCT category FROM stores WHERE is_active = 1 ORDER BY category', (err, categories) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch categories' });
    }
    res.json(categories.map(c => c.category));
  });
});

// Track store click
app.post('/api/click', authenticateToken, (req, res) => {
  const { storeId } = req.body;
  const userId = req.user.userId;
  const ipAddress = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent');
  
  if (!storeId) {
    return res.status(400).json({ error: 'Store ID is required' });
  }
  
  // Get store information
  db.get('SELECT * FROM stores WHERE id = ? AND is_active = 1', [storeId], (err, store) => {
    if (err || !store) {
      return res.status(404).json({ error: 'Store not found' });
    }
    
    // Record the click
    db.run(`INSERT INTO clicks (user_id, store_id, ip_address, user_agent) VALUES (?, ?, ?, ?)`,
      [userId, storeId, ipAddress, userAgent],
      function(err) {
        if (err) {
          console.error('Click tracking error:', err);
          return res.status(500).json({ error: 'Failed to track click' });
        }
        
        res.json({ 
          success: true,
          clickId: this.lastID,
          store: store.name,
          cashbackRate: `${store.cashback_rate}%`,
          affiliateUrl: store.affiliate_url
        });
      });
  });
});

// Get user dashboard data
app.get('/api/dashboard', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  
  const queries = {
    user: new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    }),
    stats: new Promise((resolve, reject) => {
      db.get(`
        SELECT 
          COUNT(c.id) as total_clicks,
          COUNT(DISTINCT c.store_id) as stores_visited,
          SUM(CASE WHEN c.status = 'confirmed' THEN c.commission_earned ELSE 0 END) as confirmed_earnings
        FROM clicks c 
        WHERE c.user_id = ?
      `, [userId], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    }),
    recentClicks: new Promise((resolve, reject) => {
      db.all(`
        SELECT c.*, s.name as store_name, s.logo_url
        FROM clicks c
        JOIN stores s ON c.store_id = s.id
        WHERE c.user_id = ?
        ORDER BY c.clicked_at DESC
        LIMIT 10
      `, [userId], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    })
  };
  
  Promise.all([queries.user, queries.stats, queries.recentClicks])
    .then(([user, stats, recentClicks]) => {
      res.json({
        user: {
          id: user.id,
          email: user.email,
          fullName: user.full_name,
          balance: user.balance,
          totalEarned: user.total_earned,
          referralCode: user.referral_code
        },
        stats: stats || { total_clicks: 0, stores_visited: 0, confirmed_earnings: 0 },
        recentClicks: recentClicks || []
      });
    })
    .catch(error => {
      console.error('Dashboard error:', error);
      res.status(500).json({ error: 'Failed to fetch dashboard data' });
    });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    environment: NODE_ENV
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
  console.log(`📊 Database: ${dbPath}`);
});

// Graceful shutdown
const gracefulShutdown = () => {
  console.log('📴 Received shutdown signal, closing server...');
  server.close(() => {
    console.log('⚡ HTTP server closed');
    db.close((err) => {
      if (err) {
        console.error('❌ Error closing database:', err);
      } else {
        console.log('🔒 Database connection closed');
      }
      process.exit(0);
    });
  });
};

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

module.exports = app;
