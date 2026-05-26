const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// Initialize Supabase with service role key (server-side only)
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: {
    persistSession: false,
    autoRefreshToken: false
  }
});

module.exports = supabase;
