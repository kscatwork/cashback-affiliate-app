require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key';
const PORT = process.env.PORT || 3000;

// Database setup (Heroku uses ephemeral filesystem, but this works for MVP)
const dbPath = process.env.NODE_ENV === 'production' ? '/tmp/cashback.db' : './cashback.db';
const db = new sqlite3.Database(dbPath);

// Initialize database
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    balance REAL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS stores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    logo_url TEXT,
    affiliate_url TEXT NOT NULL,
    commission_rate REAL DEFAULT 0,
    cashback_rate REAL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS clicks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    store_id INTEGER,
    clicked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    commission_earned REAL DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(store_id) REFERENCES stores(id)
  )`);

  // Add sample stores on first run
  db.get("SELECT COUNT(*) as count FROM stores", (err, result) => {
    if (!err && result.count === 0) {
      const sampleStores = [
        ['Amazon India', 'https://logo.clearbit.com/amazon.com', 'https://amazon.in', 8, 4],
        ['Flipkart', 'https://logo.clearbit.com/flipkart.com', 'https://flipkart.com', 6, 3],
        ['Myntra', 'https://logo.clearbit.com/myntra.com', 'https://myntra.com', 10, 5],
        ['Nykaa', 'https://logo.clearbit.com/nykaa.com', 'https://nykaa.com', 12, 6]
      ];

      sampleStores.forEach(store => {
        db.run('INSERT INTO stores (name, logo_url, affiliate_url, commission_rate, cashback_rate) VALUES (?, ?, ?, ?, ?)', store);
      });
    }
  });
});

// Middleware for authentication
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run('INSERT INTO users (email, password) VALUES (?, ?)', 
      [email, hashedPassword], 
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Email already exists' });
          }
          return res.status(500).json({ error: 'Registration failed' });
        }
        res.json({ message: 'User created successfully', userId: this.lastID });
      });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ 
      token, 
      user: { 
        id: user.id, 
        email: user.email, 
        balance: user.balance 
      } 
    });
  });
});

app.get('/api/stores', (req, res) => {
  db.all('SELECT * FROM stores ORDER BY name', (err, stores) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch stores' });
    res.json(stores);
  });
});

app.post('/api/click', authenticateToken, (req, res) => {
  const { storeId } = req.body;
  const userId = req.user.userId;
  
  if (!storeId) {
    return res.status(400).json({ error: 'Store ID required' });
  }
  
  // Get store info to calculate potential earnings
  db.get('SELECT cashback_rate FROM stores WHERE id = ?', [storeId], (err, store) => {
    if (err || !store) {
      return res.status(404).json({ error: 'Store not found' });
    }
    
    db.run('INSERT INTO clicks (user_id, store_id, commission_earned) VALUES (?, ?, ?)',
      [userId, storeId, 0], // Commission will be updated when purchase is confirmed
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to track click' });
        res.json({ 
          message: 'Click tracked successfully', 
          clickId: this.lastID,
          potentialCashback: `${store.cashback_rate}%`
        });
      });
  });
});

app.get('/api/dashboard', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  
  // Get user stats
  db.all(`
    SELECT 
      u.balance,
      u.email,
      COUNT(c.id) as total_clicks,
      SUM(c.commission_earned) as total_earned
    FROM users u 
    LEFT JOIN clicks c ON u.id = c.user_id 
    WHERE u.id = ?
    GROUP BY u.id
  `, [userId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch dashboard data' });
    
    const stats = result[0] || { balance: 0, total_clicks: 0, total_earned: 0 };
    res.json(stats);
  });
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Cashback app running on port ${PORT}`);
  console.log(`📱 Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) console.error(err.message);
    console.log('Database connection closed.');
    process.exit(0);
  });
});
