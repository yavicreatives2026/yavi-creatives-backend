const rateLimit = require('express-rate-limit');

// Global Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests from this IP, please try again later.' }
});

// Specific Rate Limiter for sensitive routes (Orders, Cart)
const sensitiveLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // Limit each IP to 20 sensitive requests per hour
  message: { error: 'Too many sensitive operations. Please wait an hour.' }
});

module.exports = { limiter, sensitiveLimiter };
