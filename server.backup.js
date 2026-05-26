const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const { body, query, param, validationResult } = require('express-validator');
const winston = require('winston');
require('dotenv').config();

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console()
  ]
});

const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: 'Validation failed', details: errors.array() });
  }
  next();
};

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet());
app.use(express.json({ limit: '10kb' })); // Prevent large payload attacks

// CORS — only allow known origins
const allowedOrigins = [
  process.env.FRONTEND_URL,
  'http://localhost:5173',
  'http://localhost:5175',
].filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    // Allow server-to-server or same-origin (no origin header)
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS: Origin ${origin} not allowed`));
    }
  },
  credentials: true
}));

// Global Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests from this IP, please try again later.' }
});
app.use(limiter);

// Specific Rate Limiter for sensitive routes (Orders, Cart)
const sensitiveLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // Limit each IP to 20 sensitive requests per hour
  message: { error: 'Too many sensitive operations. Please wait an hour.' }
});

// Initialize Supabase with service role key (server-side only)
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: {
    persistSession: false,
    autoRefreshToken: false
  }
});

// Middleware to authenticate users
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token provided' });

    // Note: Full verification is performed by supabase.auth.getUser() below

    const { data: { user }, error } = await supabase.auth.getUser(token);

    if (error || !user) {
      console.error('Auth verification failed:', error?.message);
      return res.status(401).json({ error: 'Invalid or expired session' });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error('Critical Auth Error:', err);
    res.status(500).json({ error: 'Auth error' });
  }
};

// Public: Check if email exists
app.get('/api/auth/check-email', 
  query('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
  validateRequest,
  async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email required' });
    
    const { data, error } = await supabase
      .from('user_profiles')
      .select('id')
      .eq('email', email)
      .maybeSingle();
      
    res.json({ exists: !!data });
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Middleware to check admin role — verifies the role is a known admin role
const VALID_ADMIN_ROLES = ['admin', 'super_admin'];

const requireAdmin = async (req, res, next) => {
  try {
    const { data: adminProfile, error } = await supabase
      .from('admin_profiles')
      .select('role')
      .eq('id', req.user.id)
      .single();

    if (error || !adminProfile) {
      console.warn(`[requireAdmin] No admin profile found for user ${req.user.id}`);
      return res.status(403).json({ error: 'Admin access required' });
    }

    if (!VALID_ADMIN_ROLES.includes(adminProfile.role)) {
      console.warn(`[requireAdmin] User ${req.user.id} has unrecognized role: "${adminProfile.role}"`);
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    req.adminRole = adminProfile.role;
    next();
  } catch (err) {
    console.error('[requireAdmin] Error:', err.message);
    res.status(500).json({ error: 'Authorization check failed' });
  }
};

// Admin: Get own profile & role
app.get('/api/admin/profile', authenticate, requireAdmin, async (req, res) => {
  res.json({
    ...req.user,
    adminRole: req.adminRole
  });
});

// Routes

// Public: Get active products
app.get('/api/products', async (req, res) => {
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

// Public: Get single product
app.get('/api/products/:id', async (req, res) => {
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

// Public: Get all categories
app.get('/api/categories', async (req, res) => {
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

// Public: Get website settings
app.get('/api/settings', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('website_settings')
      .select('*')
      .maybeSingle();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Public: Get single category
app.get('/api/categories/:slug', async (req, res) => {
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

// Authenticated: Get user profile
app.get('/api/profile', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('user_profiles')
      .select('*')
      .eq('id', req.user.id)
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Authenticated: Update user profile
app.put('/api/profile', authenticate, async (req, res) => {
  try {
    const { full_name, phone, address, gender, date_of_birth, avatar_url } = req.body;
    
    // Whitelist only profile-related fields
    const updates = {};
    if (full_name !== undefined) updates.full_name = full_name;
    if (phone !== undefined) updates.phone = phone;
    if (address !== undefined) updates.address = address;
    if (gender !== undefined) updates.gender = gender;
    if (date_of_birth !== undefined) updates.date_of_birth = date_of_birth;
    if (avatar_url !== undefined) updates.avatar_url = avatar_url;

    const { data, error } = await supabase
      .from('user_profiles')
      .update(updates)
      .eq('id', req.user.id)
      .select()
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Authenticated: Get user orders
app.get('/api/orders', authenticate, async (req, res) => {
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

// Authenticated: Get single order details
app.get('/api/orders/:id', authenticate, async (req, res) => {
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

// Authenticated: Cancel own order
app.put('/api/orders/:id/cancel', authenticate, async (req, res) => {
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

// Authenticated: Get user cart
app.get('/api/cart', authenticate, async (req, res) => {
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

// Authenticated: Add to cart
app.post('/api/cart', 
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

// Authenticated: Update cart item
app.put('/api/cart/:id', 
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

// Authenticated: Remove from cart
app.delete('/api/cart/:id', authenticate, async (req, res) => {
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

// Authenticated: Clear cart
app.delete('/api/cart', authenticate, async (req, res) => {
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

// Authenticated: Place order
app.post('/api/orders', 
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

// Admin: Get all products
app.get('/api/admin/products', authenticate, requireAdmin, async (req, res) => {
  try {
    const { q } = req.query;

    // Sanitize: strip special regex/SQL characters from search term
    const sanitizedQ = q ? q.replace(/[%_\\]/g, '\\$&').substring(0, 100) : null;
    
    let query = supabase.from('products').select('*');
    
    if (sanitizedQ) {
      query = query.or(`name.ilike.%${sanitizedQ}%,description.ilike.%${sanitizedQ}%`);
    }

    const { data, error } = await query.order('created_at', { ascending: false }).limit(sanitizedQ ? 5 : 100);

    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('[Admin] Product search error:', err.message);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Admin: Get single product
app.get('/api/admin/products/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('products')
      .select(`
        *,
        product_categories (
          *,
          product_category_attributes (*)
        )
      `)
      .eq('id', req.params.id)
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Admin: Create product
app.post('/api/admin/products', authenticate, requireAdmin, async (req, res) => {
  try {
    const { name, description, price, category_id, image, is_active, stock_quantity, sku, Show_card, attributes } = req.body;
    
    const productData = { 
      name, description, price, category_id, image, 
      is_active: is_active ?? true, 
      stock_quantity: stock_quantity ?? 0, 
      sku, Show_card: Show_card ?? true,
      attributes: attributes || {} 
    };

    const { data, error } = await supabase
      .from('products')
      .insert([productData])
      .select()
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Admin: Update product
app.put('/api/admin/products/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { name, description, price, category_id, image, is_active, stock_quantity, sku, Show_card, attributes } = req.body;
    
    const updates = {};
    if (name !== undefined) updates.name = name;
    if (description !== undefined) updates.description = description;
    if (price !== undefined) updates.price = price;
    if (category_id !== undefined) updates.category_id = category_id;
    if (image !== undefined) updates.image = image;
    if (is_active !== undefined) updates.is_active = is_active;
    if (stock_quantity !== undefined) updates.stock_quantity = stock_quantity;
    if (sku !== undefined) updates.sku = sku;
    if (Show_card !== undefined) updates.Show_card = Show_card;
    if (attributes !== undefined) updates.attributes = attributes;

    const { data, error } = await supabase
      .from('products')
      .update(updates)
      .eq('id', req.params.id)
      .select()
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Admin: Delete product
app.delete('/api/admin/products/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { error } = await supabase
      .from('products')
      .delete()
      .eq('id', req.params.id);

    if (error) throw error;
    res.json({ message: 'Product deleted' });
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Admin: Analytics Dashboard
app.get('/api/admin/analytics', authenticate, requireAdmin, async (req, res) => {
  try {
    const { dateFilter = 'all' } = req.query;
    
    // 1. Fetch Orders
    let ordersQuery = supabase.from('orders').select('*');
    if (dateFilter === 'month') {
      const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString();
      ordersQuery = ordersQuery.gte('created_at', startOfMonth);
    }
    const { data: ordersData, error: ordersError } = await ordersQuery;
    if (ordersError) throw ordersError;

    // 2. Fetch Users
    const { count: usersCount, error: usersError } = await supabase
      .from('user_profiles')
      .select('*', { count: 'exact', head: true });
    if (usersError) throw usersError;

    // 3. Calculation Logic (Revenue, Active Orders)
    const totalOrders = ordersData.length;
    const activeOrders = ordersData.filter(o => ['Pending', 'Confirmed', 'Processing', 'Shipped'].includes(o.status)).length;
    const revenue = ordersData
      .filter(o => !['Cancelled', 'Returned'].includes(o.status))
      .reduce((sum, order) => sum + (Number(order.total_amount) || 0), 0);

    // 4. Fetch Products (for Inventory breakdown)
    const { data: productsData } = await supabase.from('products').select('*, product_categories(name)');
    const catStats = {};
    productsData?.forEach(p => {
      const catName = p.product_categories?.name || 'Uncategorized';
      catStats[catName] = (catStats[catName] || 0) + 1;
    });

    // 5. Top Products
    let topProducts = [];
    const orderIds = ordersData.map(o => o.id);
    if (orderIds.length > 0) {
      const { data: itemsData } = await supabase
        .from('order_items')
        .select('product_id, quantity, product_name, price_at_time, products(image)')
        .in('order_id', orderIds);
      
      const productMap = {};
      itemsData?.forEach(item => {
        const id = item.product_id;
        if (!productMap[id]) productMap[id] = { name: item.product_name, qty: 0, revenue: 0, image: item.products?.image };
        productMap[id].qty += item.quantity;
        productMap[id].revenue += item.quantity * (item.price_at_time || 0);
      });
      topProducts = Object.values(productMap).sort((a, b) => b.qty - a.qty);
    }

    res.json({
      revenue,
      totalOrders,
      activeOrders,
      totalUsers: usersCount || 0,
      categoryStats: Object.entries(catStats).map(([name, count]) => ({ name, count })),
      topProducts: topProducts.slice(0, 7),
      totalProducts: productsData?.length || 0
    });
  } catch (err) {
    console.error('Admin Analytics Error:', err);
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Admin: Categories CRUD
app.get('/api/admin/categories', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('product_categories')
      .select('*, products(count), product_category_attributes(*)')
      .is('deleted_at', null)
      .order('name');
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

app.post('/api/admin/categories', authenticate, requireAdmin, async (req, res) => {
  try {
    const { name, description, image, slug, attributes } = req.body;

    if (!name || !slug) {
      return res.status(400).json({ error: 'Category name and slug are required' });
    }
    
    // 0. Check for duplicates (even soft-deleted ones) — use separate .eq() to avoid injection
    const { data: existingByName } = await supabase
      .from('product_categories')
      .select('id, name, slug, deleted_at')
      .eq('name', name)
      .maybeSingle();

    const { data: existingBySlug } = !existingByName ? await supabase
      .from('product_categories')
      .select('id, name, slug, deleted_at')
      .eq('slug', slug)
      .maybeSingle() : { data: null };

    const existing = existingByName || existingBySlug;

    if (existing) {
      if (!existing.deleted_at) {
        return res.status(400).json({ error: `Category "${name}" already exists.` });
      } else {
        return res.status(400).json({ error: `Category "${name}" exists in archive. Please restore it first or use a different name.` });
      }
    }

    // 1. Insert Category
    const { data: cat, error } = await supabase
      .from('product_categories')
      .insert([{ name, description, image, slug }])
      .select()
      .single();
    
    if (error) throw error;

    // 2. Insert Attributes if any
    if (attributes && attributes.length > 0) {
      const attrsToInsert = attributes.map(a => ({ 
        category_id: cat.id, 
        name: a.name,
        is_active: a.is_active !== undefined ? a.is_active : true
      }));
      const { error: attrError } = await supabase.from('product_category_attributes').insert(attrsToInsert);
      if (attrError) console.error('Error inserting attributes:', attrError);
    }

    // 3. Re-fetch full object in requested format
    const { data: fullCat, error: fetchError } = await supabase
      .from('product_categories')
      .select('*, products(count), product_category_attributes(*)')
      .eq('id', cat.id)
      .single();

    if (fetchError) throw fetchError;
    
    res.json(fullCat);
  } catch (err) {
    console.error('[Admin] Category Create Error:', err);
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

app.put('/api/admin/categories/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { name, description, image, slug, attributes } = req.body;
    const categoryId = req.params.id;

    // 0. Check for duplicates if name/slug changed — use separate .eq() to avoid injection
    if (name || slug) {
      const checks = [];
      if (name) checks.push(supabase.from('product_categories').select('id').eq('name', name).neq('id', categoryId).maybeSingle());
      if (slug) checks.push(supabase.from('product_categories').select('id').eq('slug', slug).neq('id', categoryId).maybeSingle());
      const results = await Promise.all(checks);
      const conflict = results.find(r => r.data);

      if (conflict) {
        return res.status(400).json({ error: 'The name or slug is already taken by another category.' });
      }
    }

    // 1. Update Category
    const { error: catError } = await supabase
      .from('product_categories')
      .update({ name, description, image, slug })
      .eq('id', categoryId);
    
    if (catError) throw catError;

    // 2. Sync Attributes
    if (attributes) {
      // Get current attributes in DB
      const { data: dbAttrs } = await supabase.from('product_category_attributes').select('id').eq('category_id', categoryId);
      const dbAttrIds = dbAttrs?.map(a => a.id) || [];
      const currentAttrIds = attributes.filter(a => a.id).map(a => a.id);

      // Delete removed attributes
      const toDelete = dbAttrIds.filter(id => !currentAttrIds.includes(id));
      if (toDelete.length > 0) {
        await supabase.from('product_category_attributes').delete().in('id', toDelete);
      }

      // Update or Insert attributes
      for (const attr of attributes) {
        if (!attr.name?.trim()) continue;
        if (attr.id) {
          // Update existing
          await supabase.from('product_category_attributes')
            .update({ 
              name: attr.name,
              is_active: attr.is_active !== undefined ? attr.is_active : true
            })
            .eq('id', attr.id);
        } else {
          // Insert new
          await supabase.from('product_category_attributes')
            .insert({ 
              category_id: categoryId, 
              name: attr.name,
              is_active: true
            });
        }
      }
    }

    // 3. Re-fetch full object in requested format
    const { data: fullCat, error: fetchError } = await supabase
      .from('product_categories')
      .select('*, products(count), product_category_attributes(*)')
      .eq('id', categoryId)
      .single();

    if (fetchError) throw fetchError;
    
    res.json(fullCat);
  } catch (err) {
    console.error('[Admin] Category Update Error:', err);
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

app.delete('/api/admin/categories/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { error } = await supabase
      .from('product_categories')
      .update({ is_active: false, deleted_at: new Date().toISOString() })
      .eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Category deactivated' });
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Admin: Inventory Tracking
app.get('/api/admin/inventory/:productId', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('inventory')
      .select('*')
      .eq('product_id', req.params.productId)
      .maybeSingle();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

app.get('/api/admin/inventory/logs/:productId', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('stock_logs')
      .select('*')
      .eq('product_id', req.params.productId)
      .order('created_at', { ascending: false })
      .limit(25);
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

app.post('/api/admin/inventory/transaction', authenticate, requireAdmin, async (req, res) => {
  try {
    const { productId, changeType, quantity, message } = req.body;
    
    // 1. Get current quantity
    const { data: current } = await supabase.from('inventory').select('quantity').eq('product_id', productId).maybeSingle();
    const currentQty = current ? current.quantity : 0;

    // 2. Compute new quantity
    let newQty = changeType === 'added' ? currentQty + quantity : currentQty - quantity;
    if (newQty < 0) return res.status(400).json({ error: `Insufficient stock. Current: ${currentQty}` });

    // 3. Update Inventory
    if (current) {
      await supabase.from('inventory').update({ quantity: newQty, updated_at: new Date().toISOString() }).eq('product_id', productId);
    } else {
      await supabase.from('inventory').insert({ product_id: productId, quantity: newQty });
    }

    // 4. Log Transaction
    await supabase.from('stock_logs').insert({
      product_id: productId,
      change_type: changeType,
      quantity,
      message: message?.trim() || null
    });

    res.json({ newQuantity: newQty });
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Admin: Order Management
app.get('/api/admin/orders', authenticate, requireAdmin, async (req, res) => {
  try {
    const { q } = req.query;
    console.log(`[Admin] Orders search query: "${q || ''}"`);

    let query = supabase
      .from('orders')
      .select('*, user_profiles(full_name, email), order_items(count)');

    if (q) {
      // Search by order_number (string), full_name, or contact_email
      // Note: order_number is a string like "ORD-719394"
      query = query.or(`order_number.ilike.%${q}%,contact_email.ilike.%${q}%,user_profiles.full_name.ilike.%${q}%`);
    }

    const { data, error } = await query.order('created_at', { ascending: false });

    if (error) throw error;
    console.log(`[Admin] Orders search results: ${data?.length || 0}`);
    res.json(data);
  } catch (err) {
    console.error('[Admin] Error fetching orders:', err.message);
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

app.get('/api/admin/orders/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('orders')
      .select('*, user_profiles(*), order_items(*, products(*))')
      .eq('id', req.params.id)
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

app.post('/api/admin/orders', authenticate, requireAdmin, async (req, res) => {
  try {
    const { user_id, status, total_amount, shipping_address, payment_status, payment_method, contact_email, contact_phone, items } = req.body;
    
    // Create order
    const { data: order, error: orderError } = await supabase
      .from('orders')
      .insert({
        user_id,
        status,
        total_amount,
        shipping_address,
        payment_status,
        payment_method,
        contact_email,
        contact_phone,
        order_number: `ORD-${Math.floor(100000 + Math.random() * 900000)}`,
        total_items: items.reduce((s, i) => s + i.quantity, 0)
      })
      .select()
      .single();

    if (orderError) throw orderError;

    // Create items
    const orderItems = items.map(item => ({
      order_id: order.id,
      product_id: item.id,
      product_name: item.name,
      quantity: item.quantity,
      price_at_time: item.price
    }));

    const { error: itemsError } = await supabase.from('order_items').insert(orderItems);
    if (itemsError) throw itemsError;

    res.json(order);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

app.put('/api/admin/orders/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { status, payment_method, payment_status, completed_at } = req.body;
    const updates = { status };
    if (payment_method) updates.payment_method = payment_method;
    if (payment_status) updates.payment_status = payment_status;
    if (completed_at) updates.completed_at = completed_at;

    const { data, error } = await supabase
      .from('orders')
      .update(updates)
      .eq('id', req.params.id)
      .select()
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Admin: User Management
app.get('/api/admin/users', authenticate, requireAdmin, async (req, res) => {
  try {
    const { q } = req.query;
    console.log(`[Admin] User search query: "${q || ''}"`);
    
    let query = supabase.from('user_profiles').select('*');
    
    if (q) {
      query = query.or(`full_name.ilike.%${q}%,email.ilike.%${q}%`);
    }

    const { data, error } = await query.order('created_at', { ascending: false }).limit(q ? 5 : 100);

    if (error) throw error;
    console.log(`[Admin] User search results: ${data.length}`);
    res.json(data);
  } catch (err) {
    console.error('[Admin] User search error:', err.message);
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

app.get('/api/admin/users/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('user_profiles')
      .select('*, orders(*)')
      .eq('id', req.params.id)
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Admin: Cart Management
app.get('/api/admin/carts', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('carts')
      .select('*, user_profiles(full_name, email), cart_items(count)')
      .order('updated_at', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

app.get('/api/admin/carts/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('carts')
      .select('*, user_profiles(*), cart_items(*, products(*))')
      .eq('id', req.params.id)
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Admin: Website Settings
app.get('/api/admin/settings', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('website_settings')
      .select('*')
      .maybeSingle();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

app.put('/api/admin/settings', authenticate, requireAdmin, async (req, res) => {
  try {
    const { site_name, contact_email, contact_phone, address, hero_image, hero_badge, hero_heading_line1, hero_heading_line2, hero_description, hero_cta_label, hero_cta_link } = req.body;
    
    const settingsData = {
      id: 1,
      site_name, contact_email, contact_phone, address, 
      hero_image, hero_badge, hero_heading_line1, hero_heading_line2, 
      hero_description, hero_cta_label, hero_cta_link,
      updated_at: new Date().toISOString()
    };

    const { error } = await supabase
      .from('website_settings')
      .upsert(settingsData, { onConflict: 'id' });

    if (error) throw error;
    res.json({ message: 'Settings updated' });
  } catch (err) {
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
});
