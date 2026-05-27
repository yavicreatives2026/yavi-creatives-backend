const rateLimit = require('express-rate-limit');

const isDev = process.env.NODE_ENV !== 'production';

// Global Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: isDev ? 10000 : 100, // Relaxed in dev, strict in production
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests from this IP, please try again later.' }
});

// Specific Rate Limiter for sensitive routes (Orders, Cart)
const sensitiveLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: isDev ? 1000 : 20, // Relaxed in dev, strict in production
  message: { error: 'Too many sensitive operations. Please wait an hour.' }
});

module.exports = { limiter, sensitiveLimiter };
