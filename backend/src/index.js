require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const xss = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');

const app = express();


// Set various HTTP headers for security
app.use(helmet());

// Enable CORS safely (you can restrict origin in production)
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST'],
  credentials: false
}));

// Limit repeated requests (basic rate limiting)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  message: 'Too many requests, please try again later.'
});
app.use(limiter);

// Prevent XSS attacks
app.use(xss());

// Prevent MongoDB injection
app.use(mongoSanitize());

// Prevent HTTP parameter pollution
app.use(hpp());

// Parse incoming JSON requests
app.use(express.json({ limit: '10kb' }));

// --- Basic Route ---
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Secure Node.js backend is running 🚀'
  });
});

// --- Error Handling Middleware ---
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ success: false, message: 'Internal Server Error' });
});

// --- Start Server ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Server running securely on port ${PORT}`);
});
