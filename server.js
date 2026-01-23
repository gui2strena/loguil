// Loguil Backend – Users + Orders (Postgres)
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 10000;

// =========================
// PLAN LIMITS (server-side)
// =========================
const PLAN_LIMITS = {
  trial: 999,
  starter: 100,
  pro: 1000,
  growth: 999999
};

// helper: current month range in UTC
function monthRangeUTC() {
  const now = new Date();
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0));
  const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1, 0, 0, 0));
  return { start, end };
}

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "*";
app.use(
  cors({
    origin: FRONTEND_ORIGIN === "*" ? true : FRONTEND_ORIGIN,
  })
);
app.use(express.json());

// --- Postgres pool ---
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error("❌ Missing DATABASE_URL env var");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  // Render/managed postgres often needs SSL for external URLs.
  // Internal DB URL usually works without, but this is safe.
  ssl: DATABASE_URL && DATABASE_URL.includes("render.com")
    ? { rejectUnauthorized: false }
    : undefined,
});

// --- Minimal migrations (create tables if not exist) ---
async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      store_name TEXT NOT NULL,
      currency TEXT NOT NULL DEFAULT 'EUR',
      plan TEXT NOT NULL DEFAULT 'trial',
      trial_ends TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '14 days'),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      order_id TEXT,
      order_date DATE,
      customer_name TEXT,
      product_name TEXT,
      revenue NUMERIC(12,2) NOT NULL DEFAULT 0,
      product_cost NUMERIC(12,2) NOT NULL DEFAULT 0,
      shipping_cost NUMERIC(12,2) NOT NULL DEFAULT 0,
      platform_fee NUMERIC(12,2) NOT NULL DEFAULT 0,
      other_costs NUMERIC(12,2) NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'pending',
      notes TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log("✅ Migration OK (users + orders)");
}

migrate().catch((e) => {
  console.error("❌ Migration failed:", e);
});

// --- Health check ---
app.get("/", (req, res) => {
  res.json({ status: "ok", app: "Loguil", message: "Backend is running" });
});

// --- AUTH ---
app.post("/signup", async (req, res) => {
  try {
    const { email, password, storeName, currency } = req.body;
    if (!email || !password || !storeName) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const existing = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (existing.rows.length) {
      return res.status(400).json({ error: "This email is already registered" });
    }

    const password_hash = await bcrypt.hash(password, 10);

    const created = await pool.query(
      `INSERT INTO users (email, password_hash, store_name, currency)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email, store_name, currency, plan, trial_ends`,
      [email, password_hash, storeName, currency || "EUR"]
    );

    return res.json({ success: true, user: created.rows[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Signup failed" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Missing credentials" });
    }

    const userQ = await pool.query(
      "SELECT id, email, password_hash, store_name, currency, plan, trial_ends FROM users WHERE email=$1",
      [email]
    );

    if (!userQ.rows.length) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = userQ.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Incorrect password" });

    // Don't return password_hash
    const safeUser = {
      id: user.id,
      email: user.email,
      store_name: user.store_name,
      currency: user.currency,
      plan: user.plan,
      trial_ends: user.trial_ends,
    };

    return res.json({ success: true, user: safeUser });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Login failed" });
  }
});

// --- ORDERS CRUD ---
// IMPORTANT: for now we use userId from the client (simple prototype).
// Later we add real auth token/session.

app.get("/orders", async (req, res) => {
  try {
    const userId = Number(req.query.userId);
    if (!userId) return res.status(400).json({ error: "Missing userId" });

    const q = await pool.query(
      `SELECT
        id,
        user_id,
        order_id,
        order_date,
        customer_name,
        product_name,
        revenue,
        product_cost,
        shipping_cost,
        platform_fee,
        other_costs,
        status,
        notes,
        created_at,
        updated_at
      FROM orders
      WHERE user_id=$1
      ORDER BY order_date DESC NULLS LAST, id DESC`,
      [userId]
    );

    return res.json({ success: true, orders: q.rows });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to load orders" });
  }
});

app.post("/orders", async (req, res) => {
  try {
    const { userId, order } = req.body;
    const uid = Number(userId);
    if (!uid || !order) return res.status(400).json({ error: "Missing userId/order" });

    // --- enforce monthly limits by plan ---
const userRes = await pool.query(
  "SELECT plan FROM users WHERE id = $1",
  [user_id]
);

if (userRes.rowCount === 0) {
  return res.status(404).json({ error: "User not found" });
}

const plan = userRes.rows[0].plan || "trial";
const limit = PLAN_LIMITS[plan] ?? 999;

if (limit !== 999999) {
  const { start, end } = monthRangeUTC();

  const countRes = await pool.query(
    `SELECT COUNT(*)::int AS count
     FROM orders
     WHERE user_id = $1
       AND created_at >= $2
       AND created_at < $3`,
    [user_id, start.toISOString(), end.toISOString()]
  );

  const used = countRes.rows[0].count;

  if (used >= limit) {
    return res.status(403).json({
      error: `Plan limit reached (${used}/${limit} orders this month). Please upgrade.`
    });
  }
}
// --- end enforce ---


    const created = await pool.query(
      `INSERT INTO orders (
        user_id, order_id, order_date, customer_name, product_name,
        revenue, product_cost, shipping_cost, platform_fee, other_costs,
        status, notes
      )
      VALUES (
        $1,$2,$3,$4,$5,
        $6,$7,$8,$9,$10,
        $11,$12
      )
      RETURNING *`,
      [
        uid,
        order.order_id || null,
        order.order_date || null,
        order.customer_name || null,
        order.product_name || null,
        Number(order.revenue || 0),
        Number(order.product_cost || 0),
        Number(order.shipping_cost || 0),
        Number(order.platform_fee || 0),
        Number(order.other_costs || 0),
        order.status || "pending",
        order.notes || null,
      ]
    );

    return res.json({ success: true, order: created.rows[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to create order" });
  }
});

app.put("/orders/:id", async (req, res) => {
  try {
    const orderDbId = Number(req.params.id);
    const { userId, order } = req.body;
    const uid = Number(userId);
    if (!uid || !orderDbId || !order) return res.status(400).json({ error: "Missing data" });

    const updated = await pool.query(
      `UPDATE orders SET
        order_id=$1,
        order_date=$2,
        customer_name=$3,
        product_name=$4,
        revenue=$5,
        product_cost=$6,
        shipping_cost=$7,
        platform_fee=$8,
        other_costs=$9,
        status=$10,
        notes=$11,
        updated_at=NOW()
      WHERE id=$12 AND user_id=$13
      RETURNING *`,
      [
        order.order_id || null,
        order.order_date || null,
        order.customer_name || null,
        order.product_name || null,
        Number(order.revenue || 0),
        Number(order.product_cost || 0),
        Number(order.shipping_cost || 0),
        Number(order.platform_fee || 0),
        Number(order.other_costs || 0),
        order.status || "pending",
        order.notes || null,
        orderDbId,
        uid,
      ]
    );

    if (!updated.rows.length) {
      return res.status(404).json({ error: "Order not found" });
    }

    return res.json({ success: true, order: updated.rows[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to update order" });
  }
});

app.delete("/orders/:id", async (req, res) => {
  try {
    const orderDbId = Number(req.params.id);
    const userId = Number(req.query.userId);
    if (!orderDbId || !userId) return res.status(400).json({ error: "Missing userId" });

    const del = await pool.query(
      "DELETE FROM orders WHERE id=$1 AND user_id=$2 RETURNING id",
      [orderDbId, userId]
    );

    if (!del.rows.length) return res.status(404).json({ error: "Order not found" });

    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to delete order" });
  }
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`Loguil backend running on port ${PORT}`);
});
