const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const { authenticate, requireAdmin } = require('../middleware/auth');
const { validateRequest } = require('../middleware/validation');
const { sensitiveLimiter } = require('../middleware/rateLimiter');
const { body, query, param } = require('express-validator');

router.get('/api/categories', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('product_categories')
      .select('*')
      .eq('is_active', true)
      .is('deleted_at', null)
      .order('name', { ascending: true });

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

router.get('/api/categories/:slug', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('product_categories')
      .select('*, products(count), product_category_attributes(id, name)')
      .eq('slug', req.params.slug)
      .eq('is_active', true)
      .is('deleted_at', null)
      .single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

module.exports = router;
