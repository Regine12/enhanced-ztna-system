const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

// WebAuthn challenge store
const challengeStore = new Map();

// Failed login attempts tracking
const failedAttempts = new Map();

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-for-demo';

// WebAuthn configuration
const rpName = 'ZTNA Security Gateway';
const rpID = process.env.NODE_ENV === 'production' 
  ? 'enhanced-ztna-system.vercel.app' 
  : 'localhost';
const origin = process.env.NODE_ENV === 'production'
  ? 'https://enhanced-ztna-system.vercel.app'
  : 'http://localhost:3000';

// Middleware
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://enhanced-ztna-system.vercel.app',
    'https://enhanced-ztna-system-git-main-regines-projects-00e20a20.vercel.app'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Request logging
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path} - ${new Date().toLocaleTimeString()}`);
  next();
});

// Database setup
const dbPath = process.env.NODE_ENV === 'production' 
  ? '/tmp/database.db'
  : path.join(__dirname, 'data', 'ztna.db');

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Database error:', err);
  } else {
    console.log('Database connected:', dbPath);
    initDB();
  }
});

function initDB() {
  const tables = [
    `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME,
      failed_attempts INTEGER DEFAULT 0,
      is_active BOOLEAN DEFAULT 1
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token TEXT UNIQUE NOT NULL,
      risk_score INTEGER DEFAULT 0,
      ip_address TEXT,
      user_agent TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      is_active BOOLEAN DEFAULT 1,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`,
    `CREATE TABLE IF NOT EXISTS access_logs (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      session_id TEXT,
      resource TEXT,
      success BOOLEAN,
      risk_score INTEGER,
      ip_address TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`,
    `CREATE TABLE IF NOT EXISTS risk_events (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      event_type TEXT,
      risk_value INTEGER,
      description TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`,
    `CREATE TABLE IF NOT EXISTS user_authenticators (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      credential_id TEXT UNIQUE NOT NULL,
      credential_public_key TEXT NOT NULL,
      counter INTEGER DEFAULT 0,
      device_name TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_used DATETIME,
      is_active BOOLEAN DEFAULT 1,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`
  ];

  tables.forEach(sql => {
    db.run(sql, (err) => {
      if (err) console.error('Table creation error:', err);
    });
  });
  
  console.log('Database tables initialized');
}

// Helper functions
function trackFailedAttempt(username, ip) {
  const key = `${username}_${ip}`;
  const attempts = failedAttempts.get(key) || [];
  attempts.push(new Date());
  
  // Keep only attempts from last 15 minutes
  const recent = attempts.filter(time => Date.now() - time.getTime() < 15 * 60 * 1000);
  failedAttempts.set(key, recent);
  
  // Update database
  db.run('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?', [username]);
}

function getFailedAttempts(username, ip) {
  const key = `${username}_${ip}`;
  const attempts = failedAttempts.get(key) || [];
  return attempts.filter(time => Date.now() - time.getTime() < 15 * 60 * 1000).length;
}

function clearFailedAttempts(username, ip) {
  const key = `${username}_${ip}`;
  failedAttempts.delete(key);
  db.run('UPDATE users SET failed_attempts = 0 WHERE username = ?', [username]);
}

const calculateRiskScore = (req, session = null, username = null) => {
  let risk = 0;
  
  // Failed login attempts (high impact)
  if (username) {
    const recentFailures = getFailedAttempts(username, req.ip);
    risk += recentFailures * 20; // 20 points per failed attempt
  }
  
  // Time-based risk (outside business hours)
  const hour = new Date().getHours();
  if (hour < 7 || hour > 19) risk += 25; // Outside 7 AM - 7 PM
  
  // Weekend access
  const day = new Date().getDay();
  if (day === 0 || day === 6) risk += 15; // Weekend access
  
  // IP address change risk
  if (session && session.ip_address && session.ip_address !== req.ip) {
    risk += 30;
  }
  
  // User agent change risk
  if (session && session.user_agent && session.user_agent !== req.get('User-Agent')) {
    risk += 25;
  }
  
  // Session duration risk
  if (session && session.last_activity) {
    const now = new Date();
    const lastActivity = new Date(session.last_activity);
    const hoursInactive = (now - lastActivity) / (1000 * 60 * 60);
    
    if (hoursInactive > 2) risk += 15;
    if (hoursInactive > 6) risk += 25;
  }
  
  // Random base risk (simulating behavioral analysis)
  risk += Math.floor(Math.random() * 10);
  
  return Math.min(risk, 100);
};

const logRiskEvent = (userId, eventType, riskValue, description) => {
  db.run(
    'INSERT INTO risk_events (id, user_id, event_type, risk_value, description) VALUES (?, ?, ?, ?, ?)',
    [uuidv4(), userId, eventType, riskValue, description]
  );
};

// Routes
app.get('/', (req, res) => {
  res.json({ 
    message: 'ZTNA Security Gateway API',
    status: 'operational',
    version: '2.0.0',
    timestamp: new Date().toISOString()
  });
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    message: 'ZTNA Security Gateway',
    version: '2.0.0'
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    message: 'ZTNA Security Gateway API',
    version: '2.0.0'
  });
});

// User Registration
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    console.log('Registration attempt:', username);
    
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password required' });
    }

    // Password validation
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }

    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])/.test(password)) {
      return res.status(400).json({ 
        error: 'Password must contain uppercase, lowercase, number, and special character' 
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const userId = uuidv4();

    db.run(
      'INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)',
      [userId, username, email, passwordHash],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint')) {
            return res.status(409).json({ error: 'Username or email already exists' });
          }
          console.error('Registration error:', err);
          return res.status(500).json({ error: 'Registration failed' });
        }
        
        console.log('User registered:', username);
        res.status(201).json({ 
          success: true, 
          userId,
          username,
          message: 'User registered successfully' 
        });
      }
    );
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log('Login attempt:', username);

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!user) {
        console.log('User not found:', username);
        trackFailedAttempt(username, req.ip);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const isValid = await bcrypt.compare(password, user.password_hash);
      if (!isValid) {
        console.log('Invalid password for:', username);
        trackFailedAttempt(username, req.ip);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Clear failed attempts on successful login
      clearFailedAttempts(username, req.ip);

      // Calculate initial risk score
      const riskScore = calculateRiskScore(req, null, username);
      
      // Create session
      const sessionId = uuidv4();
      const token = jwt.sign(
        { userId: user.id, sessionId, username: user.username },
        JWT_SECRET,
        { expiresIn: '8h' }
      );

      const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000);

      db.run(
        `INSERT INTO sessions 
         (id, user_id, token, risk_score, ip_address, user_agent, expires_at) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [sessionId, user.id, token, riskScore, req.ip, req.get('User-Agent'), expiresAt.toISOString()],
        (err) => {
          if (err) {
            console.error('Session creation error:', err);
            return res.status(500).json({ error: 'Session creation failed' });
          }

          // Update last login
          db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

          // Log risk event
          logRiskEvent(user.id, 'login', riskScore, `Login from ${req.ip}`);

          console.log('Login successful:', username, 'Risk:', riskScore);
          
          res.json({
            success: true,
            token,
            user: {
              username: user.username,
              email: user.email,
              lastLogin: user.last_login
            },
            session: {
              id: sessionId,
              riskScore,
              expiresAt: expiresAt.toISOString()
            }
          });
        }
      );
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    // Get session details
    db.get(
      'SELECT * FROM sessions WHERE id = ? AND is_active = 1',
      [decoded.sessionId],
      (err, session) => {
        if (err || !session) {
          return res.status(403).json({ error: 'Invalid session' });
        }

        // Check expiration
        if (new Date() > new Date(session.expires_at)) {
          return res.status(403).json({ error: 'Session expired' });
        }

        // Calculate current risk score (continuous authentication)
        const currentRisk = calculateRiskScore(req, session, decoded.username);
        
        // Update session activity and risk
        db.run(
          'UPDATE sessions SET last_activity = CURRENT_TIMESTAMP, risk_score = ? WHERE id = ?',
          [currentRisk, session.id]
        );

        req.user = { 
          userId: decoded.userId, 
          sessionId: decoded.sessionId, 
          username: decoded.username,
          riskScore: currentRisk 
        };
        
        next();
      }
    );
  });
};

// Protected resource access
app.get('/api/protected/resource', authenticateToken, (req, res) => {
  const { userId, sessionId, riskScore, username } = req.user;
  
  console.log(`Protected access by ${username}, risk: ${riskScore}`);
  
  // Log access attempt
  const accessId = uuidv4();
  db.run(
    'INSERT INTO access_logs (id, user_id, session_id, resource, success, risk_score, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [accessId, userId, sessionId, '/api/protected/resource', true, riskScore, req.ip]
  );

  // Log high risk events
  if (riskScore > 50) {
    logRiskEvent(userId, 'high_risk_access', riskScore, `High risk access to protected resource`);
  }

  res.json({
    message: 'Access granted to protected resource',
    timestamp: new Date().toISOString(),
    riskScore,
    riskLevel: riskScore < 30 ? 'LOW' : riskScore < 60 ? 'MEDIUM' : 'HIGH',
    data: {
      sensitiveData: 'Confidential company information accessed',
      documentId: 'DOC-' + Math.random().toString(36).substr(2, 9),
      accessLevel: riskScore < 40 ? 'FULL' : 'LIMITED'
    },
    security: {
      continuousAuthEnabled: true,
      nextVerificationIn: Math.max(300 - riskScore * 2, 30) + ' seconds',
      additionalAuthRequired: riskScore > 70
    }
  });
});

// Session verification
app.post('/api/verify-session', authenticateToken, (req, res) => {
  const { riskScore } = req.user;
  
  let status = 'VALID';
  let action = 'CONTINUE';
  
  if (riskScore > 80) {
    status = 'HIGH_RISK';
    action = 'REAUTHENTICATE';
  } else if (riskScore > 60) {
    status = 'MODERATE_RISK';
    action = 'ADDITIONAL_VERIFICATION';
  } else if (riskScore > 40) {
    status = 'ELEVATED_RISK';
    action = 'MONITOR';
  }

  res.json({
    status,
    action,
    riskScore,
    timestamp: new Date().toISOString(),
    recommendation: action === 'REAUTHENTICATE' ? 'Please verify your identity' : 'Session continues normally'
  });
});

// Dashboard endpoint
app.get('/api/dashboard', authenticateToken, (req, res) => {
  const { userId } = req.user;
  
  db.get('SELECT username, email, last_login, created_at FROM users WHERE id = ?', [userId], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get recent activity
    db.all(
      'SELECT * FROM access_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10',
      [userId],
      (err, logs) => {
        if (err) logs = [];

        // Get current session info
        db.get(
          'SELECT risk_score, created_at, last_activity FROM sessions WHERE user_id = ? AND is_active = 1 ORDER BY created_at DESC LIMIT 1',
          [userId],
          (err, session) => {
            if (err) session = {};

            res.json({
              user: {
                username: user.username,
                email: user.email,
                lastLogin: user.last_login,
                memberSince: user.created_at
              },
              session: {
                currentRiskScore: session.risk_score || 0,
                sessionStart: session.created_at,
                lastActivity: session.last_activity
              },
              recentActivity: logs,
              stats: {
                totalAccess: logs.length,
                avgRiskScore: logs.reduce((sum, log) => sum + (log.risk_score || 0), 0) / Math.max(logs.length, 1),
                highRiskEvents: logs.filter(log => log.risk_score > 60).length
              }
            });
          }
        );
      }
    );
  });
});

// Analytics endpoint
app.get('/api/analytics', authenticateToken, (req, res) => {
  const queries = [
    { name: 'totalUsers', sql: 'SELECT COUNT(*) as count FROM users' },
    { name: 'activeSessions', sql: 'SELECT COUNT(*) as count FROM sessions WHERE is_active = 1' },
    { name: 'totalAccess', sql: 'SELECT COUNT(*) as count FROM access_logs' },
    { name: 'avgRiskScore', sql: 'SELECT AVG(risk_score) as avg FROM access_logs WHERE risk_score > 0' },
    { name: 'highRiskEvents', sql: 'SELECT COUNT(*) as count FROM access_logs WHERE risk_score > 60' }
  ];

  const results = { timestamp: new Date().toISOString() };
  let completed = 0;

  queries.forEach(query => {
    db.all(query.sql, (err, rows) => {
      if (!err) {
        results[query.name] = rows[0] || {};
      }
      completed++;
      
      if (completed === queries.length) {
        console.log('Analytics data requested');
        res.json(results);
      }
    });
  });
});

// WebAuthn Registration Start
app.post('/api/webauthn/register/begin', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.user;
    
    db.all(
      'SELECT credential_id FROM user_authenticators WHERE user_id = ? AND is_active = 1',
      [userId],
      async (err, authenticators) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }

        const options = await generateRegistrationOptions({
          rpName,
          rpID,
          userID: userId,
          userName: req.user.username,
          userDisplayName: req.user.username,
          attestationType: 'none',
          excludeCredentials: authenticators.map(auth => ({
            id: Buffer.from(auth.credential_id, 'base64url'),
            type: 'public-key',
          })),
          authenticatorSelection: {
            residentKey: 'preferred',
            userVerification: 'preferred',
          },
        });

        challengeStore.set(userId, options.challenge);
        console.log('WebAuthn registration started for:', req.user.username);
        res.json(options);
      }
    );
  } catch (error) {
    console.error('WebAuthn registration begin error:', error);
    res.status(500).json({ error: 'Registration initiation failed' });
  }
});

// WebAuthn Registration Finish
app.post('/api/webauthn/register/finish', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.user;
    const { credential, deviceName } = req.body;
    
    const expectedChallenge = challengeStore.get(userId);
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Invalid or expired challenge' });
    }

    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (verification.verified && verification.registrationInfo) {
      const { registrationInfo } = verification;
      const authenticatorId = uuidv4();

      db.run(
        `INSERT INTO user_authenticators 
         (id, user_id, credential_id, credential_public_key, counter, device_name) 
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          authenticatorId,
          userId,
          Buffer.from(registrationInfo.credentialID).toString('base64url'),
          Buffer.from(registrationInfo.credentialPublicKey).toString('base64url'),
          registrationInfo.counter,
          deviceName || 'Unknown Device'
        ],
        (err) => {
          if (err) {
            console.error('Error storing authenticator:', err);
            return res.status(500).json({ error: 'Failed to store authenticator' });
          }

          challengeStore.delete(userId);
          console.log('WebAuthn device registered for:', req.user.username);
          
          res.json({ 
            verified: true, 
            authenticatorId,
            message: 'Device registered successfully'
          });
        }
      );
    } else {
      res.status(400).json({ error: 'Registration verification failed' });
    }
  } catch (error) {
    console.error('WebAuthn registration finish error:', error);
    res.status(500).json({ error: 'Registration verification failed' });
  }
});

// Get user's devices
app.get('/api/webauthn/devices', authenticateToken, (req, res) => {
  const { userId } = req.user;
  
  db.all(
    'SELECT id, device_name, created_at, last_used, is_active FROM user_authenticators WHERE user_id = ? ORDER BY created_at DESC',
    [userId],
    (err, devices) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      res.json({
        devices: devices || [],
        count: devices ? devices.length : 0
      });
    }
  );
});

// Admin endpoint to view data
app.get('/api/admin/stats', (req, res) => {
  db.all('SELECT id, username, email, created_at FROM users ORDER BY created_at DESC', (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    
    db.all('SELECT COUNT(*) as count FROM user_authenticators WHERE is_active = 1', (err2, devices) => {
      if (err2) return res.status(500).json({ error: err2.message });
      
      db.all('SELECT COUNT(*) as count FROM access_logs', (err3, accesses) => {
        if (err3) return res.status(500).json({ error: err3.message });
        
        res.json({
          totalUsers: users.length,
          users: users.map(u => ({
            username: u.username,
            email: u.email,
            registeredAt: new Date(u.created_at).toLocaleString()
          })),
          totalDevices: devices[0].count,
          totalAccesses: accesses[0].count,
          lastUpdated: new Date().toISOString()
        });
      });
    });
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 ZTNA Security Gateway running on port ${PORT}`);
  console.log(`📊 Database: ${dbPath}`);
  console.log(`🔗 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🛡️  WebAuthn RP ID: ${rpID}`);
  console.log(`🌐 Origin: ${origin}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down gracefully...');
  db.close((err) => {
    if (err) {
      console.error(err.message);
    } else {
      console.log('Database connection closed.');
    }
    process.exit(0);
  });
});