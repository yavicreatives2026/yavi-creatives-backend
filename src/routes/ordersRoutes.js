const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const { authenticate, requireAdmin } = require('../middleware/auth');
const { validateRequest } = require('../middleware/validation');
const { sensitiveLimiter } = require('../middleware/rateLimiter');
const { body, query, param } = require('express-validator');

router.get('/api/orders', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('orders')
      .select(`
        *,
        order_items (
          product_id, quantity, price_at_time,
          products (name, image)
        )
      `)
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

router.get('/api/orders/:id', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('orders')
      .select(`
        *,
        order_items (
          *,
          products (*)
        )
      `)
      .eq('id', req.params.id)
      .eq('user_id', req.user.id)
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

router.put('/api/orders/:id/cancel', authenticate, async (req, res) => {
  try {
    const { reason } = req.body;
    
    // Check ownership and current status
    const { data: order, error: fetchError } = await supabase
      .from('orders')
      .select('status, user_id')
      .eq('id', req.params.id)
      .single();

    if (fetchError || !order) return res.status(404).json({ error: 'Order not found' });
    if (order.user_id !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });
    
    const cancellableStatuses = ['Pending', 'Confirmed'];
    if (!cancellableStatuses.includes(order.status)) {
      return res.status(400).json({ error: `Cannot cancel order in ${order.status} status` });
    }

    const { data, error } = await supabase
      .from('orders')
      .update({ 
        status: 'Cancelled',
        cancel_reason: reason,
        completed_at: new Date().toISOString()
      })
      .eq('id', req.params.id)
      .select()
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

router.post('/api/orders', 
  authenticate, 
  sensitiveLimiter, 
  body('total_amount').isNumeric().withMessage('Total amount is required'),
  body('address').notEmpty().withMessage('Address is required'),
  body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
  body('phone').notEmpty().withMessage('Phone is required'),
  body('order_items').isArray({ min: 1 }).withMessage('Order items must be a non-empty array'),
  body('order_items.*.product_id').notEmpty().withMessage('Product ID is required'),
  body('order_items.*.quantity').isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
  validateRequest,
  async (req, res) => {
  try {
    const { total_amount, address, email, phone, order_items } = req.body;
    const user_id = req.user.id; // Correctly use the authenticated user ID

    // Generate order number
    const orderNumber = `ORD-${Math.floor(100000 + Math.random() * 900000)}`;

    // Calculate total items
    const totalItems = order_items.reduce((sum, item) => sum + item.quantity, 0);

    // Create order
    const { data: order, error: orderError } = await supabase
      .from('orders')
      .insert({
        user_id,
        order_number: orderNumber,
        total_amount,
        shipping_address: address, // Fixed column name
        contact_email: email, // Fixed column name
        contact_phone: phone, // Fixed column name
        status: 'Pending', // Fixed case sensitivity for CHECK constraint
        total_items: totalItems // Fixed: Satisfy hidden NOT NULL constraint
      })
      .select()
      .single();

    if (orderError) {
      console.error('Order creation error:', orderError);
      throw orderError;
    }

    // Fetch product names for historical accuracy in order_items
    const productIds = order_items.map(item => item.product_id);
    const { data: productsData, error: productsError } = await supabase
      .from('products')
      .select('id, name')
      .in('id', productIds);

    const productMap = {};
    if (productsData) {
      productsData.forEach(p => { productMap[p.id] = p.name; });
    }

    // Create order items with redundant data for history
    const orderItemsData = order_items.map(item => ({
      order_id: order.id,
      product_id: item.product_id,
      product_name: productMap[item.product_id] || 'Unknown Product', // Fixed: Added requirement
      quantity: item.quantity,
      price_at_time: item.price // Fixed: Use price_at_time from schema. Removed total_price (generated).
    }));

    console.log('DEBUG: orderItemsData being inserted:', JSON.stringify(orderItemsData, null, 2));

    const { error: itemsError } = await supabase
      .from('order_items')
      .insert(orderItemsData);

    if (itemsError) {
      console.error('Order items insertion error:', itemsError);
      throw itemsError;
    }

    // Clear user's cart safely
    try {
      const { data: cart } = await supabase
        .from('carts')
        .select('id')
        .eq('user_id', user_id)
        .maybeSingle();

      if (cart) {
        await supabase
          .from('cart_items')
          .delete()
          .eq('cart_id', cart.id);
      }
    } catch (cartErr) {
      console.error('Cart clear non-fatal error:', cartErr);
    }

    res.json(order);
  } catch (err) {
    console.error('Checkout process error:', err);
    res.status(500).json({ error: 'Order processing failed' });
  }
});

module.exports = router;
