const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const { authenticate, requireAdmin } = require('../middleware/auth');
const { validateRequest } = require('../middleware/validation');
const { sensitiveLimiter } = require('../middleware/rateLimiter');
const { body, query, param } = require('express-validator');

router.get('/api/admin/profile', authenticate, requireAdmin, async (req, res) => {
  res.json({
    ...req.user,
    adminRole: req.adminRole
  });
});

router.get('/api/admin/products', authenticate, requireAdmin, async (req, res) => {
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

router.get('/api/admin/products/:id', authenticate, requireAdmin, async (req, res) => {
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

router.post('/api/admin/products', authenticate, requireAdmin, async (req, res) => {
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

router.put('/api/admin/products/:id', authenticate, requireAdmin, async (req, res) => {
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

router.delete('/api/admin/products/:id', authenticate, requireAdmin, async (req, res) => {
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

router.get('/api/admin/analytics', authenticate, requireAdmin, async (req, res) => {
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

router.get('/api/admin/categories', authenticate, requireAdmin, async (req, res) => {
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

router.post('/api/admin/categories', authenticate, requireAdmin, async (req, res) => {
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

router.put('/api/admin/categories/:id', authenticate, requireAdmin, async (req, res) => {
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

router.delete('/api/admin/categories/:id', authenticate, requireAdmin, async (req, res) => {
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

// Bulk: fetch all inventory in one query (used by ProductList)
router.get('/api/admin/inventory', authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('inventory')
      .select('product_id, quantity');
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('[Admin] Bulk inventory error:', err);
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

// Single product inventory (used by ProductDetails)
router.get('/api/admin/inventory/:productId', authenticate, requireAdmin, async (req, res) => {
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

router.get('/api/admin/inventory/logs/:productId', authenticate, requireAdmin, async (req, res) => {
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

router.post('/api/admin/inventory/transaction', authenticate, requireAdmin, async (req, res) => {
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

router.get('/api/admin/orders', authenticate, requireAdmin, async (req, res) => {
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

router.get('/api/admin/orders/:id', authenticate, requireAdmin, async (req, res) => {
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

router.post('/api/admin/orders', authenticate, requireAdmin, async (req, res) => {
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

router.put('/api/admin/orders/:id', authenticate, requireAdmin, async (req, res) => {
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

router.get('/api/admin/users', authenticate, requireAdmin, async (req, res) => {
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

router.get('/api/admin/users/:id', authenticate, requireAdmin, async (req, res) => {
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

router.get('/api/admin/carts', authenticate, requireAdmin, async (req, res) => {
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

router.get('/api/admin/carts/:id', authenticate, requireAdmin, async (req, res) => {
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

router.get('/api/admin/settings', authenticate, requireAdmin, async (req, res) => {
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

router.put('/api/admin/settings', authenticate, requireAdmin, async (req, res) => {
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

module.exports = router;
