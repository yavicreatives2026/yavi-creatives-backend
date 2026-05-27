const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { limiter } = require('./src/middleware/rateLimiter');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet());
app.use(express.json({ limit: '10kb' })); // Prevent large payload attacks

// CORS
const allowedOrigins = [
  process.env.FRONTEND_URL,
  'http://localhost:5173',
  'http://localhost:5175',
].filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS: Origin ${origin} not allowed`));
    }
  },
  credentials: true
}));

app.use(limiter);

// Health Check
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'ok',
    message: 'Backend is up and running 🚀',
    uptime: `${Math.floor(process.uptime())}s`,
    timestamp: new Date().toISOString(),
  });
});

// Routes
app.use('/', require('./src/routes/authRoutes'));
app.use('/', require('./src/routes/productsRoutes'));
app.use('/', require('./src/routes/categoriesRoutes'));
app.use('/', require('./src/routes/profileRoutes'));
app.use('/', require('./src/routes/ordersRoutes'));
app.use('/', require('./src/routes/cartRoutes'));
app.use('/', require('./src/routes/settingsRoutes'));
app.use('/', require('./src/routes/adminRoutes'));

// Start server
app.listen(PORT, () => {
  console.log(`Server  is running on port ${PORT}`);
});
