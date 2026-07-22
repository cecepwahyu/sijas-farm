const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', ...headers }
});

const bad = (message, status = 400) => json({ ok: false, message }, status);
const ok = (data = {}) => json({ ok: true, ...data });

function getPath(context) {
  const p = context.params.path;
  return Array.isArray(p) ? p.join('/') : (p || '');
}

function bytesToHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

async function hashPin(pin, saltHex) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: 120000, hash: 'SHA-256' }, key, 256);
  return bytesToHex(new Uint8Array(bits));
}

function randomHex(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

function cookieValue(request, name) {
  const raw = request.headers.get('cookie') || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

function sessionCookie(token, maxAge = 60 * 60 * 24 * 14) {
  return `sijas_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

async function currentUser(context) {
  const token = cookieValue(context.request, 'sijas_session');
  if (!token) return null;
  const tokenHash = await sha256(token);
  const row = await context.env.DB.prepare(`
    SELECT u.id, u.name, u.username, u.role
    FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.expires_at > datetime('now') AND u.is_active=1
  `).bind(tokenHash).first();
  return row || null;
}

async function requireUser(context, role) {
  const user = await currentUser(context);
  if (!user) return { error: bad('Sesi tidak valid. Silakan masuk kembali.', 401) };
  if (role && user.role !== role) return { error: bad('Akses ditolak.', 403) };
  return { user };
}

async function body(request) {
  try { return await request.json(); } catch { return {}; }
}

function asDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(value || '')) ? String(value) : null;
}
const n = (value, min = 0) => {
  const v = Number(value);
  return Number.isFinite(v) && v >= min ? v : null;
};
const text = (value, max = 500) => String(value ?? '').trim().slice(0, max);

async function audit(db, type, key, action, oldData, newData, userId) {
  await db.prepare(`INSERT INTO audit_log(entity_type,entity_key,action,old_data,new_data,changed_by) VALUES(?,?,?,?,?,?)`)
    .bind(type, String(key), action, oldData ? JSON.stringify(oldData) : null, newData ? JSON.stringify(newData) : null, userId).run();
}

async function handleSetupStatus(context) {
  const row = await context.env.DB.prepare('SELECT COUNT(*) AS count FROM users').first();
  return ok({ configured: Number(row?.count || 0) > 0 });
}

async function handleSetup(context) {
  const data = await body(context.request);
  if (!context.env.SETUP_KEY || data.setupKey !== context.env.SETUP_KEY) return bad('Kunci setup tidak sesuai.', 403);
  const count = await context.env.DB.prepare('SELECT COUNT(*) AS count FROM users').first();
  if (Number(count?.count || 0) > 0) return bad('Aplikasi sudah dikonfigurasi.', 409);
  const username = text(data.username, 40).toLowerCase();
  const name = text(data.name, 80);
  const pin = String(data.pin || '');
  if (!name || !/^[a-z0-9._-]{3,40}$/.test(username) || pin.length < 4) return bad('Nama, username, atau PIN tidak valid.');
  const salt = randomHex(16);
  const pinHash = await hashPin(pin, salt);
  const result = await context.env.DB.prepare(`INSERT INTO users(name,username,pin_hash,pin_salt,role) VALUES(?,?,?,?, 'admin')`)
    .bind(name, username, pinHash, salt).run();
  await context.env.DB.prepare(`UPDATE settings SET updated_by=?, updated_at=CURRENT_TIMESTAMP WHERE id=1`).bind(result.meta.last_row_id).run();
  return ok({ message: 'Admin Sijas Farm berhasil dibuat.' });
}

async function handleLogin(context) {
  const data = await body(context.request);
  const username = text(data.username, 40).toLowerCase();
  const pin = String(data.pin || '');
  const user = await context.env.DB.prepare('SELECT * FROM users WHERE username=? AND is_active=1').bind(username).first();
  if (!user || await hashPin(pin, user.pin_salt) !== user.pin_hash) return bad('Username atau PIN salah.', 401);
  const token = randomHex(32);
  const tokenHash = await sha256(token);
  const expires = new Date(Date.now() + 14 * 86400000).toISOString();
  await context.env.DB.batch([
    context.env.DB.prepare("DELETE FROM sessions WHERE expires_at <= datetime('now')"),
    context.env.DB.prepare('INSERT INTO sessions(user_id,token_hash,expires_at) VALUES(?,?,?)').bind(user.id, tokenHash, expires)
  ]);
  return json({ ok: true, user: { id: user.id, name: user.name, username: user.username, role: user.role } }, 200, { 'set-cookie': sessionCookie(token) });
}

async function handleLogout(context) {
  const token = cookieValue(context.request, 'sijas_session');
  if (token) await context.env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(token)).run();
  return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) });
}

async function getSettings(db) {
  return await db.prepare('SELECT * FROM settings WHERE id=1').first();
}

async function getDashboard(context) {
  const auth = await requireUser(context); if (auth.error) return auth.error;
  const url = new URL(context.request.url);
  const today = asDate(url.searchParams.get('today')) || new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Jakarta', year:'numeric', month:'2-digit', day:'2-digit' }).format(new Date());
  const days = Math.min(Math.max(Number(url.searchParams.get('days') || 30), 7), 366);
  const from = new Date(`${today}T00:00:00Z`); from.setUTCDate(from.getUTCDate() - days + 1);
  const fromDate = from.toISOString().slice(0,10);
  const [settings, productionToday, salesToday, expenseToday, rangeProduction, rangeSales, rangeExpenses, stock] = await Promise.all([
    getSettings(context.env.DB),
    context.env.DB.prepare('SELECT * FROM daily_production WHERE production_date=?').bind(today).first(),
    context.env.DB.prepare(`SELECT *, (home_weight_kg+shop_weight_kg) total_weight_kg, (home_weight_kg*home_price_per_kg + shop_weight_kg*shop_price_per_kg) total_revenue FROM daily_sales WHERE sale_date=?`).bind(today).first(),
    context.env.DB.prepare('SELECT COALESCE(SUM(amount),0) total FROM expenses WHERE expense_date=?').bind(today).first(),
    context.env.DB.prepare('SELECT production_date date, egg_count, weight_kg FROM daily_production WHERE production_date BETWEEN ? AND ? ORDER BY production_date').bind(fromDate,today).all(),
    context.env.DB.prepare(`SELECT sale_date date, home_weight_kg, shop_weight_kg, (home_weight_kg+shop_weight_kg) total_weight_kg, (home_weight_kg*home_price_per_kg + shop_weight_kg*shop_price_per_kg) total_revenue FROM daily_sales WHERE sale_date BETWEEN ? AND ? ORDER BY sale_date`).bind(fromDate,today).all(),
    context.env.DB.prepare('SELECT expense_date date, SUM(amount) total FROM expenses WHERE expense_date BETWEEN ? AND ? GROUP BY expense_date ORDER BY expense_date').bind(fromDate,today).all(),
    context.env.DB.prepare(`SELECT
      (SELECT opening_stock_kg FROM settings WHERE id=1)
      + COALESCE((SELECT SUM(weight_kg) FROM daily_production),0)
      - COALESCE((SELECT SUM(home_weight_kg+shop_weight_kg) FROM daily_sales),0)
      + COALESCE((SELECT SUM(amount_kg) FROM stock_adjustments),0) AS stock_kg`).first()
  ]);
  return ok({ user: auth.user, settings, today, productionToday, salesToday, expenseToday: Number(expenseToday?.total || 0), stockKg: Number(stock?.stock_kg || 0), series: { production: rangeProduction.results, sales: rangeSales.results, expenses: rangeExpenses.results } });
}

async function upsertProduction(context, date) {
  const auth = await requireUser(context); if (auth.error) return auth.error;
  const data = await body(context.request);
  const eggCount = n(data.eggCount); const weightKg = n(data.weightKg);
  if (!asDate(date) || eggCount === null || weightKg === null) return bad('Data produksi tidak valid.');
  const old = await context.env.DB.prepare('SELECT * FROM daily_production WHERE production_date=?').bind(date).first();
  await context.env.DB.prepare(`INSERT INTO daily_production(production_date,egg_count,weight_kg,notes,created_by,updated_by)
    VALUES(?,?,?,?,?,?) ON CONFLICT(production_date) DO UPDATE SET egg_count=excluded.egg_count,weight_kg=excluded.weight_kg,notes=excluded.notes,updated_by=excluded.updated_by,updated_at=CURRENT_TIMESTAMP`)
    .bind(date, Math.round(eggCount), weightKg, text(data.notes), auth.user.id, auth.user.id).run();
  const current = await context.env.DB.prepare('SELECT * FROM daily_production WHERE production_date=?').bind(date).first();
  await audit(context.env.DB, 'production', date, old ? 'UPDATE' : 'INSERT', old, current, auth.user.id);
  return ok({ record: current, replaced: !!old });
}

async function getProduction(context, date) {
  const auth = await requireUser(context); if (auth.error) return auth.error;
  return ok({ record: await context.env.DB.prepare('SELECT * FROM daily_production WHERE production_date=?').bind(date).first() });
}

async function upsertSales(context, date) {
  const auth = await requireUser(context); if (auth.error) return auth.error;
  const data = await body(context.request);
  const hw = n(data.homeWeightKg), hp = n(data.homePricePerKg), sw = n(data.shopWeightKg), sp = n(data.shopPricePerKg);
  if (!asDate(date) || [hw,hp,sw,sp].some(v => v === null)) return bad('Data penjualan tidak valid.');
  const old = await context.env.DB.prepare('SELECT * FROM daily_sales WHERE sale_date=?').bind(date).first();
  await context.env.DB.prepare(`INSERT INTO daily_sales(sale_date,home_weight_kg,home_price_per_kg,shop_weight_kg,shop_price_per_kg,notes,created_by,updated_by)
    VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(sale_date) DO UPDATE SET home_weight_kg=excluded.home_weight_kg,home_price_per_kg=excluded.home_price_per_kg,shop_weight_kg=excluded.shop_weight_kg,shop_price_per_kg=excluded.shop_price_per_kg,notes=excluded.notes,updated_by=excluded.updated_by,updated_at=CURRENT_TIMESTAMP`)
    .bind(date, hw, Math.round(hp), sw, Math.round(sp), text(data.notes), auth.user.id, auth.user.id).run();
  const current = await context.env.DB.prepare('SELECT * FROM daily_sales WHERE sale_date=?').bind(date).first();
  await audit(context.env.DB, 'sales', date, old ? 'UPDATE' : 'INSERT', old, current, auth.user.id);
  return ok({ record: current, replaced: !!old });
}

async function getSales(context, date) {
  const auth = await requireUser(context); if (auth.error) return auth.error;
  return ok({ record: await context.env.DB.prepare('SELECT * FROM daily_sales WHERE sale_date=?').bind(date).first() });
}

async function expenseRoutes(context, segments) {
  const auth = await requireUser(context); if (auth.error) return auth.error;
  if (context.request.method === 'GET') {
    const url = new URL(context.request.url); const from = asDate(url.searchParams.get('from')) || '2000-01-01'; const to = asDate(url.searchParams.get('to')) || '2999-12-31';
    const rows = await context.env.DB.prepare('SELECT * FROM expenses WHERE expense_date BETWEEN ? AND ? ORDER BY expense_date DESC,id DESC').bind(from,to).all();
    return ok({ records: rows.results });
  }
  if (context.request.method === 'POST') {
    const data = await body(context.request); const date = asDate(data.date); const amount = n(data.amount);
    if (!date || amount === null || !text(data.category,60) || !text(data.description,160)) return bad('Data pengeluaran tidak valid.');
    const result = await context.env.DB.prepare('INSERT INTO expenses(expense_date,category,description,amount,notes,created_by) VALUES(?,?,?,?,?,?)')
      .bind(date,text(data.category,60),text(data.description,160),Math.round(amount),text(data.notes),auth.user.id).run();
    return ok({ id: result.meta.last_row_id });
  }
  if (context.request.method === 'DELETE' && segments[1]) {
    const old = await context.env.DB.prepare('SELECT * FROM expenses WHERE id=?').bind(segments[1]).first();
    if (!old) return bad('Data tidak ditemukan.',404);
    await context.env.DB.prepare('DELETE FROM expenses WHERE id=?').bind(segments[1]).run();
    await audit(context.env.DB,'expense',segments[1],'DELETE',old,null,auth.user.id);
    return ok();
  }
  return bad('Method tidak didukung.',405);
}

async function adjustmentRoutes(context, segments) {
  const auth = await requireUser(context); if (auth.error) return auth.error;
  if (context.request.method === 'GET') {
    const rows = await context.env.DB.prepare('SELECT * FROM stock_adjustments ORDER BY adjustment_date DESC,id DESC LIMIT 200').all();
    return ok({ records: rows.results });
  }
  if (context.request.method === 'POST') {
    const data = await body(context.request); const date = asDate(data.date); const amount = Number(data.amountKg);
    if (!date || !Number.isFinite(amount) || amount === 0 || !text(data.reason,160)) return bad('Data penyesuaian stok tidak valid.');
    const result = await context.env.DB.prepare('INSERT INTO stock_adjustments(adjustment_date,amount_kg,reason,notes,created_by) VALUES(?,?,?,?,?)')
      .bind(date,amount,text(data.reason,160),text(data.notes),auth.user.id).run();
    return ok({ id: result.meta.last_row_id });
  }
  if (context.request.method === 'DELETE' && segments[1]) {
    await context.env.DB.prepare('DELETE FROM stock_adjustments WHERE id=?').bind(segments[1]).run(); return ok();
  }
  return bad('Method tidak didukung.',405);
}

async function settingsRoute(context) {
  const auth = await requireUser(context); if (auth.error) return auth.error;
  if (context.request.method === 'GET') return ok({ settings: await getSettings(context.env.DB) });
  if (context.request.method !== 'PUT') return bad('Method tidak didukung.',405);
  if (auth.user.role !== 'admin') return bad('Hanya admin yang dapat mengubah pengaturan.',403);
  const data = await body(context.request);
  const opening = n(data.openingStockKg), hp = n(data.defaultHomePrice), sp = n(data.defaultShopPrice);
  if (opening === null || hp === null || sp === null || (data.startDate && !asDate(data.startDate))) return bad('Pengaturan tidak valid.');
  await context.env.DB.prepare(`UPDATE settings SET farm_name=?,start_date=?,opening_stock_kg=?,default_home_price=?,default_shop_price=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=1`)
    .bind(text(data.farmName,80)||'Sijas Farm',data.startDate||null,opening,Math.round(hp),Math.round(sp),auth.user.id).run();
  return ok({ settings: await getSettings(context.env.DB) });
}

async function reportRoute(context) {
  const auth = await requireUser(context); if (auth.error) return auth.error;
  const url = new URL(context.request.url); const from = asDate(url.searchParams.get('from')); const to = asDate(url.searchParams.get('to'));
  if (!from || !to) return bad('Periode laporan tidak valid.');
  const [prod,sales,expenses,adjustments] = await Promise.all([
    context.env.DB.prepare('SELECT * FROM daily_production WHERE production_date BETWEEN ? AND ? ORDER BY production_date').bind(from,to).all(),
    context.env.DB.prepare(`SELECT *,home_weight_kg*home_price_per_kg home_revenue,shop_weight_kg*shop_price_per_kg shop_revenue FROM daily_sales WHERE sale_date BETWEEN ? AND ? ORDER BY sale_date`).bind(from,to).all(),
    context.env.DB.prepare('SELECT * FROM expenses WHERE expense_date BETWEEN ? AND ? ORDER BY expense_date,id').bind(from,to).all(),
    context.env.DB.prepare('SELECT * FROM stock_adjustments WHERE adjustment_date BETWEEN ? AND ? ORDER BY adjustment_date,id').bind(from,to).all()
  ]);
  return ok({ production:prod.results,sales:sales.results,expenses:expenses.results,adjustments:adjustments.results });
}

export async function onRequest(context) {
  try {
    const path = getPath(context); const segments = path.split('/').filter(Boolean); const method = context.request.method;
    if (method === 'OPTIONS') return new Response(null,{status:204});
    if (path === 'setup/status' && method === 'GET') return handleSetupStatus(context);
    if (path === 'setup' && method === 'POST') return handleSetup(context);
    if (path === 'login' && method === 'POST') return handleLogin(context);
    if (path === 'logout' && method === 'POST') return handleLogout(context);
    if (path === 'me' && method === 'GET') { const a=await requireUser(context); return a.error||ok({user:a.user}); }
    if (path === 'dashboard' && method === 'GET') return getDashboard(context);
    if (segments[0] === 'production' && segments[1]) return method === 'GET' ? getProduction(context,segments[1]) : method === 'PUT' ? upsertProduction(context,segments[1]) : bad('Method tidak didukung.',405);
    if (segments[0] === 'sales' && segments[1]) return method === 'GET' ? getSales(context,segments[1]) : method === 'PUT' ? upsertSales(context,segments[1]) : bad('Method tidak didukung.',405);
    if (segments[0] === 'expenses') return expenseRoutes(context,segments);
    if (segments[0] === 'adjustments') return adjustmentRoutes(context,segments);
    if (path === 'settings') return settingsRoute(context);
    if (path === 'report' && method === 'GET') return reportRoute(context);
    return bad('Endpoint tidak ditemukan.',404);
  } catch (error) {
    console.error(error);
    return bad('Terjadi kesalahan pada server.',500);
  }
}
