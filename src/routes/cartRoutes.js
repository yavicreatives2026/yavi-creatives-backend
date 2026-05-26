const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const { authenticate, requireAdmin } = require('../middleware/auth');
const { validateRequest } = require('../middleware/validation');
const { sensitiveLimiter } = require('../middleware/rateLimiter');
const { body, query, param } = require('express-validator');

router.get('/api/cart', authenticate, async (req, res) => {
  try {
    console.log('Getting cart for user:', req.user.id);
    
    // First, ensure we only get one cart (in case of duplicates)
    const { data: carts, error: cartError } = await supabase
      .from('carts')
      .select('id')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false })
      .limit(1);

    if (cartError) {
      console.error('Cart query error:', cartError);
      throw cartError;
    }
    
    console.log('Carts found:', carts);
    if (!carts || carts.length === 0) return res.json([]);

    const cart = carts[0];

    const { data: items, error: itemsError } = await supabase
      .from('cart_items')
      .select(`
        *,
        products (id, name, price, image)
      `)
      .eq('cart_id', cart.id);

    if (itemsError) {
      console.error('Cart items query error:', itemsError);
      throw itemsError;
    }
    
    console.log('Cart items:', items);
    res.json(items);
  } catch (err) {
    console.error('Cart API error:', err);
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

router.post('/api/cart', 
  authenticate,
  body('product_id').notEmpty().withMessage('Product ID is required'),
  body('quantity').isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
  validateRequest,
  async (req, res) => {
  try {
    const { product_id, quantity } = req.body;

    // First, try to find existing cart for user
    let { data: carts, error: cartError } = await supabase
      .from('carts')
      .select('id')
      .eq('user_id', req.user.id);

    if (cartError) throw cartError;

    let cart;
    if (carts && carts.length > 0) {
      // Use the first cart if multiple exist (shouldn't happen due to UNIQUE constraint)
      cart = carts[0];
    } else {
      // Create new cart
      const { data: newCart, error: createError } = await supabase
        .from('carts')
        .insert([{ user_id: req.user.id }])
        .select('id')
        .single();
      if (createError) throw createError;
      cart = newCart;
    }

    // Check if item already exists in cart
    const { data: existingItems, error: checkError } = await supabase
      .from('cart_items')
      .select('*')
      .eq('cart_id', cart.id)
      .eq('product_id', product_id);

    if (checkError) throw checkError;

    // 1. Fetch current price for product_id
    const { data: product, error: productError } = await supabase
      .from('products')
      .select('price')
      .eq('id', product_id)
      .single();

    if (productError || !product) {
      console.error('Product fetch error for cart:', productError);
      return res.status(404).json({ error: 'Product not found' });
    }

    if (existingItems && existingItems.length > 0) {
      // Update existing item
      const existingItem = existingItems[0];
      const { data, error } = await supabase
        .from('cart_items')
        .update({ 
          quantity: existingItem.quantity + quantity,
          price_at_time: product.price // Update to current price as well
        })
        .eq('id', existingItem.id)
        .select()
        .single();
      if (error) throw error;
      res.json(data);
    } else {
      // Insert new item
      const { data, error } = await supabase
        .from('cart_items')
        .insert([{ 
          cart_id: cart.id, 
          product_id, 
          quantity,
          price_at_time: product.price // Required by NOT NULL constraint
        }])
        .select()
        .single();
      if (error) throw error;
      res.json(data);
    }
  } catch (err) {
    console.error('Cart POST error:', err);
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

router.put('/api/cart/:id', 
  authenticate, 
  param('id').notEmpty().withMessage('Cart item ID is required'),
  body('quantity').isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
  validateRequest,
  async (req, res) => {
  try {
    const { quantity, price } = req.body;
    
    // Ownership check: Ensure this cart item belongs to the authenticated user
    const { data: itemOwner, error: ownerError } = await supabase
      .from('cart_items')
      .select('carts(user_id)')
      .eq('id', req.params.id)
      .single();

    if (ownerError || !itemOwner || itemOwner.carts?.user_id !== req.user.id) {
      console.error(`[IDOR Prevention] User ${req.user.id} attempted to update item ${req.params.id} belonging to ${itemOwner?.carts?.user_id}`);
      return res.status(403).json({ error: 'Unauthorized: This item does not belong to your cart' });
    }
    
    let updateData = { quantity };
    
    // If price is sent, use it, otherwise fetch it for the item
    if (price) {
      updateData.price_at_time = price;
    } else {
      // Fetch current price for the product associated with this cart item
      const { data: item, error: itemError } = await supabase
        .from('cart_items')
        .select('product_id')
        .eq('id', req.params.id)
        .single();
      
      if (!itemError && item) {
        const { data: product } = await supabase
          .from('products')
          .select('price')
          .eq('id', item.product_id)
          .single();
        
        if (product) {
          updateData.price_at_time = product.price;
        }
      }
    }

    const { data, error } = await supabase
      .from('cart_items')
      .update(updateData)
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

router.delete('/api/cart/:id', authenticate, async (req, res) => {
  try {
    // Ownership check: Ensure this cart item belongs to the authenticated user
    const { data: itemOwner, error: ownerError } = await supabase
      .from('cart_items')
      .select('carts(user_id)')
      .eq('id', req.params.id)
      .single();

    if (ownerError || !itemOwner || itemOwner.carts?.user_id !== req.user.id) {
      console.error(`[IDOR Prevention] User ${req.user.id} attempted to delete item ${req.params.id} belonging to ${itemOwner?.carts?.user_id}`);
      return res.status(403).json({ error: 'Unauthorized: This item does not belong to your cart' });
    }

    const { error } = await supabase
      .from('cart_items')
      .delete()
      .eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Item removed' });
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

router.delete('/api/cart', authenticate, async (req, res) => {
  try {
    const { data: cart, error: cartError } = await supabase
      .from('carts')
      .select('id')
      .eq('user_id', req.user.id)
      .maybeSingle();

    if (cartError) throw cartError;
    if (!cart) return res.json({ message: 'No cart to clear' });

    const { error } = await supabase
      .from('cart_items')
      .delete()
      .eq('cart_id', cart.id);
    if (error) throw error;
    res.json({ message: 'Cart cleared' });
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

module.exports = router;
