const supabase = require('../config/supabase');

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

module.exports = { authenticate, requireAdmin };
