const PIN_HASH_ITERATIONS = 10_000;
const SESSION_DURATION_SECONDS = 60 * 60 * 24 * 14;

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...headers
    }
  });

const bad = (message, status = 400) =>
  json({ ok: false, message }, status);

const ok = (data = {}) =>
  json({ ok: true, ...data });

function getPath(context) {
  const path = context.params.path;

  return Array.isArray(path)
    ? path.join('/')
    : (path || '');
}

function bytesToHex(bytes) {
  return [...bytes]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) {
    throw new Error('Salt PIN tidak valid.');
  }

  const output = new Uint8Array(hex.length / 2);

  for (let index = 0; index < output.length; index += 1) {
    const parsed = Number.parseInt(
      hex.slice(index * 2, index * 2 + 2),
      16
    );

    if (!Number.isFinite(parsed)) {
      throw new Error('Salt PIN tidak valid.');
    }

    output[index] = parsed;
  }

  return output;
}

async function sha256(value) {
  const encoded = new TextEncoder().encode(String(value));

  const digest = await crypto.subtle.digest(
    'SHA-256',
    encoded
  );

  return bytesToHex(new Uint8Array(digest));
}

async function hashPin(pin, saltHex) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(String(pin)),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: hexToBytes(saltHex),
      iterations: PIN_HASH_ITERATIONS,
      hash: 'SHA-256'
    },
    key,
    256
  );

  return bytesToHex(new Uint8Array(bits));
}

function randomHex(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);

  return bytesToHex(bytes);
}

function cookieValue(request, name) {
  const rawCookie = request.headers.get('cookie') || '';

  for (const part of rawCookie.split(';')) {
    const [key, ...values] = part.trim().split('=');

    if (key === name) {
      return decodeURIComponent(values.join('='));
    }
  }

  return null;
}

function sessionCookie(
  token,
  maxAge = SESSION_DURATION_SECONDS
) {
  return [
    `sijas_session=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Strict',
    `Max-Age=${maxAge}`
  ].join('; ');
}

async function currentUser(context) {
  const token = cookieValue(
    context.request,
    'sijas_session'
  );

  if (!token) {
    return null;
  }

  const tokenHash = await sha256(token);

  const row = await context.env.DB.prepare(`
    SELECT
      u.id,
      u.name,
      u.username,
      u.role
    FROM sessions s
    JOIN users u
      ON u.id = s.user_id
    WHERE s.token_hash = ?
      AND s.expires_at > datetime('now')
      AND u.is_active = 1
  `)
    .bind(tokenHash)
    .first();

  return row || null;
}

async function requireUser(context, role) {
  const user = await currentUser(context);

  if (!user) {
    return {
      error: bad(
        'Sesi tidak valid. Silakan masuk kembali.',
        401
      )
    };
  }

  if (role && user.role !== role) {
    return {
      error: bad('Akses ditolak.', 403)
    };
  }

  return { user };
}

async function body(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function asDate(value) {
  const date = String(value || '');

  return /^\d{4}-\d{2}-\d{2}$/.test(date)
    ? date
    : null;
}

function numberValue(value, min = 0) {
  const parsed = Number(value);

  return Number.isFinite(parsed) && parsed >= min
    ? parsed
    : null;
}

function text(value, max = 500) {
  return String(value ?? '')
    .trim()
    .slice(0, max);
}

function ensureEnvironment(context) {
  if (!context.env.DB) {
    return bad(
      'Binding database DB belum dikonfigurasi.',
      500
    );
  }

  return null;
}

async function audit(
  db,
  type,
  key,
  action,
  oldData,
  newData,
  userId
) {
  await db.prepare(`
    INSERT INTO audit_log (
      entity_type,
      entity_key,
      action,
      old_data,
      new_data,
      changed_by
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `)
    .bind(
      type,
      String(key),
      action,
      oldData ? JSON.stringify(oldData) : null,
      newData ? JSON.stringify(newData) : null,
      userId
    )
    .run();
}

async function handleSetupStatus(context) {
  const row = await context.env.DB.prepare(`
    SELECT COUNT(*) AS count
    FROM users
  `).first();

  return ok({
    configured: Number(row?.count || 0) > 0
  });
}

async function handleSetup(context) {
  const data = await body(context.request);

  const configuredSetupKey = String(
    context.env.SETUP_KEY || ''
  ).trim();

  const submittedSetupKey = String(
    data.setupKey || ''
  ).trim();

  if (!configuredSetupKey) {
    return bad(
      'SETUP_KEY belum dikonfigurasi pada environment Production.',
      500
    );
  }

  if (submittedSetupKey !== configuredSetupKey) {
    return bad('Kunci setup tidak sesuai.', 403);
  }

  const count = await context.env.DB.prepare(`
    SELECT COUNT(*) AS count
    FROM users
  `).first();

  if (Number(count?.count || 0) > 0) {
    return bad(
      'Aplikasi sudah dikonfigurasi.',
      409
    );
  }

  const username = text(
    data.username,
    40
  ).toLowerCase();

  const name = text(data.name, 80);
  const pin = String(data.pin || '').trim();

  if (!name) {
    return bad('Nama admin wajib diisi.');
  }

  if (!/^[a-z0-9._-]{3,40}$/.test(username)) {
    return bad(
      'Username harus terdiri dari 3–40 karakter: huruf kecil, angka, titik, garis bawah, atau tanda minus.'
    );
  }

  if (!/^\d{4,8}$/.test(pin)) {
    return bad(
      'PIN harus terdiri dari 4–8 angka.'
    );
  }

  const existingUsername =
    await context.env.DB.prepare(`
      SELECT id
      FROM users
      WHERE username = ?
    `)
      .bind(username)
      .first();

  if (existingUsername) {
    return bad(
      'Username sudah digunakan.',
      409
    );
  }

  const salt = randomHex(16);
  const pinHash = await hashPin(pin, salt);

  await context.env.DB.prepare(`
    INSERT INTO users (
      name,
      username,
      pin_hash,
      pin_salt,
      role
    )
    VALUES (?, ?, ?, ?, 'admin')
  `)
    .bind(
      name,
      username,
      pinHash,
      salt
    )
    .run();

  /*
   * Jangan bergantung pada result.meta.last_row_id.
   * Baca kembali admin berdasarkan username.
   */
  const admin = await context.env.DB.prepare(`
    SELECT
      id,
      name,
      username,
      role
    FROM users
    WHERE username = ?
  `)
    .bind(username)
    .first();

  if (!admin) {
    throw new Error(
      'Admin berhasil dimasukkan tetapi gagal dibaca kembali.'
    );
  }

  await context.env.DB.prepare(`
    UPDATE settings
    SET
      updated_by = ?,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = 1
  `)
    .bind(admin.id)
    .run();

  return ok({
    message: 'Admin Sijas Farm berhasil dibuat.',
    user: admin
  });
}

async function handleLogin(context) {
  const data = await body(context.request);

  const username = text(
    data.username,
    40
  ).toLowerCase();

  const pin = String(data.pin || '').trim();

  if (!username || !/^\d{4,8}$/.test(pin)) {
    return bad(
      'Username atau PIN salah.',
      401
    );
  }

  const user = await context.env.DB.prepare(`
    SELECT *
    FROM users
    WHERE username = ?
      AND is_active = 1
  `)
    .bind(username)
    .first();

  if (!user) {
    return bad(
      'Username atau PIN salah.',
      401
    );
  }

  const submittedPinHash = await hashPin(
    pin,
    user.pin_salt
  );

  if (submittedPinHash !== user.pin_hash) {
    return bad(
      'Username atau PIN salah.',
      401
    );
  }

  const token = randomHex(32);
  const tokenHash = await sha256(token);

  const expiresAt = new Date(
    Date.now() +
      SESSION_DURATION_SECONDS * 1000
  ).toISOString();

  await context.env.DB.batch([
    context.env.DB.prepare(`
      DELETE FROM sessions
      WHERE expires_at <= datetime('now')
    `),

    context.env.DB.prepare(`
      INSERT INTO sessions (
        user_id,
        token_hash,
        expires_at
      )
      VALUES (?, ?, ?)
    `).bind(
      user.id,
      tokenHash,
      expiresAt
    )
  ]);

  return json(
    {
      ok: true,
      user: {
        id: user.id,
        name: user.name,
        username: user.username,
        role: user.role
      }
    },
    200,
    {
      'set-cookie': sessionCookie(token)
    }
  );
}

async function handleLogout(context) {
  const token = cookieValue(
    context.request,
    'sijas_session'
  );

  if (token) {
    await context.env.DB.prepare(`
      DELETE FROM sessions
      WHERE token_hash = ?
    `)
      .bind(await sha256(token))
      .run();
  }

  return json(
    { ok: true },
    200,
    {
      'set-cookie': sessionCookie('', 0)
    }
  );
}

async function getSettings(db) {
  return db.prepare(`
    SELECT *
    FROM settings
    WHERE id = 1
  `).first();
}

async function getDashboard(context) {
  const auth = await requireUser(context);

  if (auth.error) {
    return auth.error;
  }

  const url = new URL(context.request.url);

  const jakartaToday =
    new Intl.DateTimeFormat(
      'en-CA',
      {
        timeZone: 'Asia/Jakarta',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
      }
    ).format(new Date());

  const today =
    asDate(url.searchParams.get('today')) ||
    jakartaToday;

  const requestedDays = Number(
    url.searchParams.get('days') || 30
  );

  const days = Math.min(
    Math.max(
      Number.isFinite(requestedDays)
        ? requestedDays
        : 30,
      7
    ),
    366
  );

  const fromDateObject =
    new Date(`${today}T00:00:00Z`);

  fromDateObject.setUTCDate(
    fromDateObject.getUTCDate() - days + 1
  );

  const fromDate =
    fromDateObject.toISOString().slice(0, 10);

  const [
    settings,
    productionToday,
    salesToday,
    expenseToday,
    rangeProduction,
    rangeSales,
    rangeExpenses,
    stock
  ] = await Promise.all([
    getSettings(context.env.DB),

    context.env.DB.prepare(`
      SELECT *
      FROM daily_production
      WHERE production_date = ?
    `)
      .bind(today)
      .first(),

    context.env.DB.prepare(`
      SELECT
        *,
        (
          home_weight_kg +
          shop_weight_kg
        ) AS total_weight_kg,
        (
          home_weight_kg * home_price_per_kg +
          shop_weight_kg * shop_price_per_kg
        ) AS total_revenue
      FROM daily_sales
      WHERE sale_date = ?
    `)
      .bind(today)
      .first(),

    context.env.DB.prepare(`
      SELECT
        COALESCE(SUM(amount), 0) AS total
      FROM expenses
      WHERE expense_date = ?
    `)
      .bind(today)
      .first(),

    context.env.DB.prepare(`
      SELECT
        production_date AS date,
        egg_count,
        weight_kg
      FROM daily_production
      WHERE production_date BETWEEN ? AND ?
      ORDER BY production_date
    `)
      .bind(fromDate, today)
      .all(),

    context.env.DB.prepare(`
      SELECT
        sale_date AS date,
        home_weight_kg,
        shop_weight_kg,
        (
          home_weight_kg +
          shop_weight_kg
        ) AS total_weight_kg,
        (
          home_weight_kg * home_price_per_kg +
          shop_weight_kg * shop_price_per_kg
        ) AS total_revenue
      FROM daily_sales
      WHERE sale_date BETWEEN ? AND ?
      ORDER BY sale_date
    `)
      .bind(fromDate, today)
      .all(),

    context.env.DB.prepare(`
      SELECT
        expense_date AS date,
        SUM(amount) AS total
      FROM expenses
      WHERE expense_date BETWEEN ? AND ?
      GROUP BY expense_date
      ORDER BY expense_date
    `)
      .bind(fromDate, today)
      .all(),

    context.env.DB.prepare(`
      SELECT
        (
          SELECT opening_stock_kg
          FROM settings
          WHERE id = 1
        )
        +
        COALESCE(
          (
            SELECT SUM(weight_kg)
            FROM daily_production
          ),
          0
        )
        -
        COALESCE(
          (
            SELECT SUM(
              home_weight_kg +
              shop_weight_kg
            )
            FROM daily_sales
          ),
          0
        )
        +
        COALESCE(
          (
            SELECT SUM(amount_kg)
            FROM stock_adjustments
          ),
          0
        ) AS stock_kg
    `).first()
  ]);

  return ok({
    user: auth.user,
    settings,
    today,
    productionToday,
    salesToday,
    expenseToday: Number(
      expenseToday?.total || 0
    ),
    stockKg: Number(
      stock?.stock_kg || 0
    ),
    series: {
      production:
        rangeProduction.results || [],
      sales:
        rangeSales.results || [],
      expenses:
        rangeExpenses.results || []
    }
  });
}

async function upsertProduction(
  context,
  date
) {
  const auth = await requireUser(context);

  if (auth.error) {
    return auth.error;
  }

  const data = await body(context.request);

  const eggCount = numberValue(
    data.eggCount
  );

  const weightKg = numberValue(
    data.weightKg
  );

  if (
    !asDate(date) ||
    eggCount === null ||
    weightKg === null
  ) {
    return bad(
      'Data produksi tidak valid.'
    );
  }

  const old = await context.env.DB.prepare(`
    SELECT *
    FROM daily_production
    WHERE production_date = ?
  `)
    .bind(date)
    .first();

  await context.env.DB.prepare(`
    INSERT INTO daily_production (
      production_date,
      egg_count,
      weight_kg,
      notes,
      created_by,
      updated_by
    )
    VALUES (?, ?, ?, ?, ?, ?)

    ON CONFLICT(production_date)
    DO UPDATE SET
      egg_count = excluded.egg_count,
      weight_kg = excluded.weight_kg,
      notes = excluded.notes,
      updated_by = excluded.updated_by,
      updated_at = CURRENT_TIMESTAMP
  `)
    .bind(
      date,
      Math.round(eggCount),
      weightKg,
      text(data.notes),
      auth.user.id,
      auth.user.id
    )
    .run();

  const current =
    await context.env.DB.prepare(`
      SELECT *
      FROM daily_production
      WHERE production_date = ?
    `)
      .bind(date)
      .first();

  await audit(
    context.env.DB,
    'production',
    date,
    old ? 'UPDATE' : 'INSERT',
    old,
    current,
    auth.user.id
  );

  return ok({
    record: current,
    replaced: Boolean(old)
  });
}

async function getProduction(
  context,
  date
) {
  const auth = await requireUser(context);

  if (auth.error) {
    return auth.error;
  }

  const record =
    await context.env.DB.prepare(`
      SELECT *
      FROM daily_production
      WHERE production_date = ?
    `)
      .bind(date)
      .first();

  return ok({ record });
}

async function upsertSales(
  context,
  date
) {
  const auth = await requireUser(context);

  if (auth.error) {
    return auth.error;
  }

  const data = await body(context.request);

  const homeWeightKg = numberValue(
    data.homeWeightKg
  );

  const homePricePerKg = numberValue(
    data.homePricePerKg
  );

  const shopWeightKg = numberValue(
    data.shopWeightKg
  );

  const shopPricePerKg = numberValue(
    data.shopPricePerKg
  );

  if (
    !asDate(date) ||
    [
      homeWeightKg,
      homePricePerKg,
      shopWeightKg,
      shopPricePerKg
    ].some((value) => value === null)
  ) {
    return bad(
      'Data penjualan tidak valid.'
    );
  }

  const old = await context.env.DB.prepare(`
    SELECT *
    FROM daily_sales
    WHERE sale_date = ?
  `)
    .bind(date)
    .first();

  await context.env.DB.prepare(`
    INSERT INTO daily_sales (
      sale_date,
      home_weight_kg,
      home_price_per_kg,
      shop_weight_kg,
      shop_price_per_kg,
      notes,
      created_by,
      updated_by
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)

    ON CONFLICT(sale_date)
    DO UPDATE SET
      home_weight_kg =
        excluded.home_weight_kg,
      home_price_per_kg =
        excluded.home_price_per_kg,
      shop_weight_kg =
        excluded.shop_weight_kg,
      shop_price_per_kg =
        excluded.shop_price_per_kg,
      notes = excluded.notes,
      updated_by = excluded.updated_by,
      updated_at = CURRENT_TIMESTAMP
  `)
    .bind(
      date,
      homeWeightKg,
      Math.round(homePricePerKg),
      shopWeightKg,
      Math.round(shopPricePerKg),
      text(data.notes),
      auth.user.id,
      auth.user.id
    )
    .run();

  const current =
    await context.env.DB.prepare(`
      SELECT *
      FROM daily_sales
      WHERE sale_date = ?
    `)
      .bind(date)
      .first();

  await audit(
    context.env.DB,
    'sales',
    date,
    old ? 'UPDATE' : 'INSERT',
    old,
    current,
    auth.user.id
  );

  return ok({
    record: current,
    replaced: Boolean(old)
  });
}

async function getSales(
  context,
  date
) {
  const auth = await requireUser(context);

  if (auth.error) {
    return auth.error;
  }

  const record =
    await context.env.DB.prepare(`
      SELECT *
      FROM daily_sales
      WHERE sale_date = ?
    `)
      .bind(date)
      .first();

  return ok({ record });
}

async function expenseRoutes(
  context,
  segments
) {
  const auth = await requireUser(context);

  if (auth.error) {
    return auth.error;
  }

  if (context.request.method === 'GET') {
    const url = new URL(
      context.request.url
    );

    const from =
      asDate(url.searchParams.get('from')) ||
      '2000-01-01';

    const to =
      asDate(url.searchParams.get('to')) ||
      '2999-12-31';

    const rows =
      await context.env.DB.prepare(`
        SELECT *
        FROM expenses
        WHERE expense_date BETWEEN ? AND ?
        ORDER BY expense_date DESC, id DESC
      `)
        .bind(from, to)
        .all();

    return ok({
      records: rows.results || []
    });
  }

  if (context.request.method === 'POST') {
    const data = await body(
      context.request
    );

    const date = asDate(data.date);
    const amount = numberValue(
      data.amount
    );

    const category = text(
      data.category,
      60
    );

    const description = text(
      data.description,
      160
    );

    if (
      !date ||
      amount === null ||
      !category ||
      !description
    ) {
      return bad(
        'Data pengeluaran tidak valid.'
      );
    }

    const result =
      await context.env.DB.prepare(`
        INSERT INTO expenses (
          expense_date,
          category,
          description,
          amount,
          notes,
          created_by
        )
        VALUES (?, ?, ?, ?, ?, ?)
      `)
        .bind(
          date,
          category,
          description,
          Math.round(amount),
          text(data.notes),
          auth.user.id
        )
        .run();

    return ok({
      id: result.meta?.last_row_id || null
    });
  }

  if (
    context.request.method === 'DELETE' &&
    segments[1]
  ) {
    const old =
      await context.env.DB.prepare(`
        SELECT *
        FROM expenses
        WHERE id = ?
      `)
        .bind(segments[1])
        .first();

    if (!old) {
      return bad(
        'Data tidak ditemukan.',
        404
      );
    }

    await context.env.DB.prepare(`
      DELETE FROM expenses
      WHERE id = ?
    `)
      .bind(segments[1])
      .run();

    await audit(
      context.env.DB,
      'expense',
      segments[1],
      'DELETE',
      old,
      null,
      auth.user.id
    );

    return ok();
  }

  return bad(
    'Method tidak didukung.',
    405
  );
}

async function adjustmentRoutes(
  context,
  segments
) {
  const auth = await requireUser(context);

  if (auth.error) {
    return auth.error;
  }

  if (context.request.method === 'GET') {
    const rows =
      await context.env.DB.prepare(`
        SELECT *
        FROM stock_adjustments
        ORDER BY adjustment_date DESC, id DESC
        LIMIT 200
      `).all();

    return ok({
      records: rows.results || []
    });
  }

  if (context.request.method === 'POST') {
    const data = await body(
      context.request
    );

    const date = asDate(data.date);
    const amount = Number(
      data.amountKg
    );

    const reason = text(
      data.reason,
      160
    );

    if (
      !date ||
      !Number.isFinite(amount) ||
      amount === 0 ||
      !reason
    ) {
      return bad(
        'Data penyesuaian stok tidak valid.'
      );
    }

    const result =
      await context.env.DB.prepare(`
        INSERT INTO stock_adjustments (
          adjustment_date,
          amount_kg,
          reason,
          notes,
          created_by
        )
        VALUES (?, ?, ?, ?, ?)
      `)
        .bind(
          date,
          amount,
          reason,
          text(data.notes),
          auth.user.id
        )
        .run();

    return ok({
      id: result.meta?.last_row_id || null
    });
  }

  if (
    context.request.method === 'DELETE' &&
    segments[1]
  ) {
    const old =
      await context.env.DB.prepare(`
        SELECT *
        FROM stock_adjustments
        WHERE id = ?
      `)
        .bind(segments[1])
        .first();

    if (!old) {
      return bad(
        'Data tidak ditemukan.',
        404
      );
    }

    await context.env.DB.prepare(`
      DELETE FROM stock_adjustments
      WHERE id = ?
    `)
      .bind(segments[1])
      .run();

    await audit(
      context.env.DB,
      'stock_adjustment',
      segments[1],
      'DELETE',
      old,
      null,
      auth.user.id
    );

    return ok();
  }

  return bad(
    'Method tidak didukung.',
    405
  );
}

async function settingsRoute(context) {
  const auth = await requireUser(context);

  if (auth.error) {
    return auth.error;
  }

  if (context.request.method === 'GET') {
    return ok({
      settings: await getSettings(
        context.env.DB
      )
    });
  }

  if (context.request.method !== 'PUT') {
    return bad(
      'Method tidak didukung.',
      405
    );
  }

  if (auth.user.role !== 'admin') {
    return bad(
      'Hanya admin yang dapat mengubah pengaturan.',
      403
    );
  }

  const data = await body(
    context.request
  );

  const openingStockKg = numberValue(
    data.openingStockKg
  );

  const defaultHomePrice = numberValue(
    data.defaultHomePrice
  );

  const defaultShopPrice = numberValue(
    data.defaultShopPrice
  );

  if (
    openingStockKg === null ||
    defaultHomePrice === null ||
    defaultShopPrice === null ||
    (
      data.startDate &&
      !asDate(data.startDate)
    )
  ) {
    return bad(
      'Pengaturan tidak valid.'
    );
  }

  await context.env.DB.prepare(`
    UPDATE settings
    SET
      farm_name = ?,
      start_date = ?,
      opening_stock_kg = ?,
      default_home_price = ?,
      default_shop_price = ?,
      updated_by = ?,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = 1
  `)
    .bind(
      text(data.farmName, 80) ||
        'Sijas Farm',
      data.startDate || null,
      openingStockKg,
      Math.round(defaultHomePrice),
      Math.round(defaultShopPrice),
      auth.user.id
    )
    .run();

  return ok({
    settings: await getSettings(
      context.env.DB
    )
  });
}

async function reportRoute(context) {
  const auth = await requireUser(context);

  if (auth.error) {
    return auth.error;
  }

  const url = new URL(
    context.request.url
  );

  const from = asDate(
    url.searchParams.get('from')
  );

  const to = asDate(
    url.searchParams.get('to')
  );

  if (!from || !to || from > to) {
    return bad(
      'Periode laporan tidak valid.'
    );
  }

  const [
    production,
    sales,
    expenses,
    adjustments
  ] = await Promise.all([
    context.env.DB.prepare(`
      SELECT *
      FROM daily_production
      WHERE production_date BETWEEN ? AND ?
      ORDER BY production_date
    `)
      .bind(from, to)
      .all(),

    context.env.DB.prepare(`
      SELECT
        *,
        (
          home_weight_kg *
          home_price_per_kg
        ) AS home_revenue,
        (
          shop_weight_kg *
          shop_price_per_kg
        ) AS shop_revenue
      FROM daily_sales
      WHERE sale_date BETWEEN ? AND ?
      ORDER BY sale_date
    `)
      .bind(from, to)
      .all(),

    context.env.DB.prepare(`
      SELECT *
      FROM expenses
      WHERE expense_date BETWEEN ? AND ?
      ORDER BY expense_date, id
    `)
      .bind(from, to)
      .all(),

    context.env.DB.prepare(`
      SELECT *
      FROM stock_adjustments
      WHERE adjustment_date BETWEEN ? AND ?
      ORDER BY adjustment_date, id
    `)
      .bind(from, to)
      .all()
  ]);

  return ok({
    production:
      production.results || [],
    sales:
      sales.results || [],
    expenses:
      expenses.results || [],
    adjustments:
      adjustments.results || []
  });
}

export async function onRequest(context) {
  try {
    const environmentError =
      ensureEnvironment(context);

    if (environmentError) {
      return environmentError;
    }

    const path = getPath(context);

    const segments = path
      .split('/')
      .filter(Boolean);

    const method =
      context.request.method.toUpperCase();

    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204
      });
    }

    if (
      path === 'setup/status' &&
      method === 'GET'
    ) {
      return handleSetupStatus(context);
    }

    if (
      path === 'setup' &&
      method === 'POST'
    ) {
      return handleSetup(context);
    }

    if (
      path === 'login' &&
      method === 'POST'
    ) {
      return handleLogin(context);
    }

    if (
      path === 'logout' &&
      method === 'POST'
    ) {
      return handleLogout(context);
    }

    if (
      path === 'me' &&
      method === 'GET'
    ) {
      const auth =
        await requireUser(context);

      return auth.error ||
        ok({ user: auth.user });
    }

    if (
      path === 'dashboard' &&
      method === 'GET'
    ) {
      return getDashboard(context);
    }

    if (
      segments[0] === 'production' &&
      segments[1]
    ) {
      if (method === 'GET') {
        return getProduction(
          context,
          segments[1]
        );
      }

      if (method === 'PUT') {
        return upsertProduction(
          context,
          segments[1]
        );
      }

      return bad(
        'Method tidak didukung.',
        405
      );
    }

    if (
      segments[0] === 'sales' &&
      segments[1]
    ) {
      if (method === 'GET') {
        return getSales(
          context,
          segments[1]
        );
      }

      if (method === 'PUT') {
        return upsertSales(
          context,
          segments[1]
        );
      }

      return bad(
        'Method tidak didukung.',
        405
      );
    }

    if (segments[0] === 'expenses') {
      return expenseRoutes(
        context,
        segments
      );
    }

    if (segments[0] === 'adjustments') {
      return adjustmentRoutes(
        context,
        segments
      );
    }

    if (path === 'settings') {
      return settingsRoute(context);
    }

    if (
      path === 'report' &&
      method === 'GET'
    ) {
      return reportRoute(context);
    }

    return bad(
      'Endpoint tidak ditemukan.',
      404
    );
  } catch (error) {
    console.error('Sijas Farm API error:', {
      name: error?.name,
      message: error?.message,
      stack: error?.stack
    });

    return bad(
      'Terjadi kesalahan pada server.',
      500
    );
  }
}