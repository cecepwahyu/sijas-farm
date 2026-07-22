PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pin_hash TEXT NOT NULL,
  pin_salt TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'operator')) DEFAULT 'operator',
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  farm_name TEXT NOT NULL DEFAULT 'Sijas Farm',
  timezone TEXT NOT NULL DEFAULT 'Asia/Jakarta',
  start_date TEXT,
  opening_stock_kg REAL NOT NULL DEFAULT 0 CHECK (opening_stock_kg >= 0),
  default_home_price INTEGER NOT NULL DEFAULT 25000 CHECK (default_home_price >= 0),
  default_shop_price INTEGER NOT NULL DEFAULT 23000 CHECK (default_shop_price >= 0),
  updated_by INTEGER REFERENCES users(id),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO settings (id, farm_name) VALUES (1, 'Sijas Farm');

CREATE TABLE IF NOT EXISTS daily_production (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  production_date TEXT NOT NULL UNIQUE,
  egg_count INTEGER NOT NULL CHECK (egg_count >= 0),
  weight_kg REAL NOT NULL CHECK (weight_kg >= 0),
  notes TEXT,
  created_by INTEGER REFERENCES users(id),
  updated_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_production_date ON daily_production(production_date);

CREATE TABLE IF NOT EXISTS daily_sales (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sale_date TEXT NOT NULL UNIQUE,
  home_weight_kg REAL NOT NULL DEFAULT 0 CHECK (home_weight_kg >= 0),
  home_price_per_kg INTEGER NOT NULL DEFAULT 0 CHECK (home_price_per_kg >= 0),
  shop_weight_kg REAL NOT NULL DEFAULT 0 CHECK (shop_weight_kg >= 0),
  shop_price_per_kg INTEGER NOT NULL DEFAULT 0 CHECK (shop_price_per_kg >= 0),
  notes TEXT,
  created_by INTEGER REFERENCES users(id),
  updated_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sales_date ON daily_sales(sale_date);

CREATE TABLE IF NOT EXISTS expenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  expense_date TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  amount INTEGER NOT NULL CHECK (amount >= 0),
  notes TEXT,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_expense_date ON expenses(expense_date);

CREATE TABLE IF NOT EXISTS stock_adjustments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  adjustment_date TEXT NOT NULL,
  amount_kg REAL NOT NULL,
  reason TEXT NOT NULL,
  notes TEXT,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_adjustment_date ON stock_adjustments(adjustment_date);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_type TEXT NOT NULL,
  entity_key TEXT NOT NULL,
  action TEXT NOT NULL,
  old_data TEXT,
  new_data TEXT,
  changed_by INTEGER REFERENCES users(id),
  changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_key);
