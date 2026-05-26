const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const { authenticate, requireAdmin } = require('../middleware/auth');
const { validateRequest } = require('../middleware/validation');
const { sensitiveLimiter } = require('../middleware/rateLimiter');
const { body, query, param } = require('express-validator');

router.get('/api/products', async (req, res) => {
  try {
    console.log('Fetching products...');
    const { data, error } = await supabase
      .from('products')
      .select('*, product_categories(name)')
      .eq('is_active', true)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Supabase error:', error);
      throw error;
    }
    console.log('Products fetched:', data.length);
    res.json(data);
  } catch (err) {
    console.error('API error:', err);
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

router.get('/api/products/:id', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('products')
      .select('*, product_categories(name)')
      .eq('id', req.params.id)
      .eq('is_active', true)
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

module.exports = router;
