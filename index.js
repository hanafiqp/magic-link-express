require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
const { Pool } = require('pg');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true,
  },
});

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
}));

app.use(express.json());

// PostgreSQL Connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT || 5432,
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

// Nodemailer Setup
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT || 587,
  secure: false, // Gunakan true jika menggunakan port 465
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// Generate Magic Link
const generateMagicLink = (email, token) => {
  return `${process.env.FRONTEND_URL}/auth/verify?token=${token}`;
};

// Kirim Magic Link via Email
const sendMagicLink = async (email, magicLink) => {
  const mailOptions = {
    from: process.env.SMTP_USER,
    to: email,
    subject: 'Your Magic Link',
    text: `Click the link to log in: ${magicLink}`,
  };

  await transporter.sendMail(mailOptions);
};

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Load index.html ketika akses root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Endpoint untuk testing database
app.get('/auth/test', async (req, res) => {
  try {
    const userResults = await pool.query('SELECT * FROM users');
    res.json({ message: 'Data users', data: userResults.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Request Magic Link
app.post('/auth/magiclink', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    // Cek apakah email terdaftar
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: 'User not registered' });
    }

    const userId = userResult.rows[0].id;

    // Generate Token
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '5m' });
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    // Simpan Token ke Database
    await pool.query('INSERT INTO tokens (user_id, token, expires_at) VALUES ($1, $2, $3)', 
      [userId, token, expiresAt]);

    // Buat Magic Link dan Kirim ke Email
    const magicLink = generateMagicLink(email, token);
    await sendMagicLink(email, magicLink);

    res.json({ message: 'Magic link sent to your email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verifikasi Magic Link
app.get('/auth/verify', async (req, res) => {
    const { token } = req.query;
  
    if (!token) {
      return res.status(400).json({ error: 'Token is required' });
    }
  
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const { email } = decoded;
  
      // Check token validity in DB
      const tokenResult = await pool.query(
        'SELECT * FROM tokens WHERE token = $1 AND expires_at > NOW()',
        [token]
      );
  
      if (tokenResult.rows.length === 0) {
        return res.status(400).json({ error: 'Invalid or expired token' });
      }
  
      // Fetch user data
      const userResult = await pool.query(
        'SELECT id, email FROM users WHERE email = $1',
        [email]
      );
  
      if (userResult.rows.length === 0) {
        return res.status(400).json({ error: 'User not found' });
      }
  
      const user = userResult.rows[0];
  
      // Generate session token
      const sessionToken = jwt.sign(
        { userId: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: '1h' }
      );
  
      // Delete used magic link token
      await pool.query('DELETE FROM tokens WHERE token = $1', [token]);
  
      // Emit event to all connected devices of this user
      io.to(email).emit('user_authenticated', {
        email: user.email,
        userId: user.id,
        sessionToken
      });
  
      // Respond to the device that opened the link
      res.json({
        message: 'Authentication successful',
        email: user.email,
        userId: user.id,
        role: user.role,
        sessionToken
      });
    } catch (err) {
      console.error(err);
      res.status(400).json({ error: 'Invalid or expired token' });
    }
  })

// Socket.IO Handling
io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  // User join berdasarkan email
  socket.on('join_room', (email) => {
    socket.join(email);
    console.log(`User with email ${email} joined room`);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Start Server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
