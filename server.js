// Loguil Backend – Users + Orders (Postgres)
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");

let Pool;
try { ({ Pool } = require("pg")); } catch {}

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || "*",
  credentials: false
}));
app.use(express.json());

// -------------------- DB (optional but preferred) --------------------
const hasDb = !!process.env.DATABASE_URL && !!Pool;
const pool = hasDb ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }) : null;

// fallback memory (if DB missing)
const mem = {
  users: [],    // {id,email,password_hash,store_name,currency,plan,trial_ends}
  orders: []    // {id,user_id,...}
};

async function ensureTables() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      store_name TEXT NOT NULL,
      currency TEXT NOT NULL,
      plan TEXT NOT NULL DEFAULT 'trial',
      trial_ends TIMESTAMPTZ NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      order_id TEXT NOT NULL,
      order_date DATE NOT NULL,
      customer_name TEXT,
      product_name TEXT,
      revenue NUMERIC DEFAULT 0,
      product_cost NUMERIC DEFAULT 0,
      shipping_cost NUMERIC DEFAULT 0,
      platform_fee NUMERIC DEFAULT 0,
      other_costs NUMERIC DEFAULT 0,
      status TEXT DEFAULT 'pending',
      notes TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

// run at startup
ensureTables().catch(err => console.error("DB init error:", err.message));

// -------------------- health --------------------
app.get("/", (req, res) => {
  res.json({ status: "ok", app: "Loguil", db: !!pool });
});

// -------------------- debug (DB test) --------------------
app.get("/debug", async (req, res) => {
  try {
    const users = await pool.query("SELECT COUNT(*)::int AS count FROM users");
    const orders = await pool.query("SELECT COUNT(*)::int AS count FROM orders");

    res.json({
      status: "ok",
      app: "Loguil",
      db: "connected",
      users: users.rows[0].count,
      orders: orders.rows[0].count
    });
  } catch (err) {
    res.status(500).json({
      status: "error",
      app: "Loguil",
      db: "failed",
      message: err.message
    });
  }
});

// -------------------- auth --------------------
app.post("/signup", async (req, res) => {
  try {
    const { email, password, storeName, currency } = req.body;
    if (!email || !password || !storeName || !currency) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const password_hash = await bcrypt.hash(password, 10);
    const trial_ends = new Date(Date.now() + 14 * 86400000).toISOString();

    if (pool) {
      const existing = await pool.query("SELECT id FROM users WHERE email=$1", [email.toLowerCase()]);
      if (existing.rows.length) return res.status(400).json({ error: "Email already registered" });

      const created = await pool.query(
        `INSERT INTO users (email, password_hash, store_name, currency, plan, trial_ends)
         VALUES ($1,$2,$3,$4,'trial',$5)
         RETURNING id,email,store_name,currency,plan,trial_ends`,
        [email.toLowerCase(), password_hash, storeName, currency, trial_ends]
      );

      return res.json({ success: true, user: created.rows[0] });
    }

    // fallback memory
    const exists = mem.users.find(u => u.email === email.toLowerCase());
    if (exists) return res.status(400).json({ error: "Email already registered" });

    const user = {
      id: mem.users.length + 1,
      email: email.toLowerCase(),
      password_hash,
      store_name: storeName,
      currency,
      plan: "trial",
      trial_ends
    };
    mem.users.push(user);
    return res.json({ success: true, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Missing credentials" });

    if (pool) {
      const found = await pool.query(
        "SELECT id,email,password_hash,store_name,currency,plan,trial_ends FROM users WHERE email=$1",
        [email.toLowerCase()]
      );
      if (!found.rows.length) return res.status(404).json({ error: "User not found" });

      const user = found.rows[0];
      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).json({ error: "Incorrect password" });

      delete user.password_hash;
      return res.json({ success: true, user });
    }

    // fallback memory
    const user = mem.users.find(u => u.email === email.toLowerCase());
    if (!user) return res.status(404).json({ error: "User not found" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Incorrect password" });

    const safe = { ...user };
    delete safe.password_hash;
    return res.json({ success: true, user: safe });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Server error" });
  }
});

// -------------------- orders --------------------
// contract: POST /orders { userId, order }
app.post("/orders", async (req, res) => {
  try {
    const userIdRaw = (req.body?.userId ?? "").toString().trim();
    const order = req.body?.order;

    if (!userIdRaw) return res.status(400).json({ error: "Missing userId" });

    const userIdNum = Number(userIdRaw);
    if (!Number.isFinite(userIdNum)) {
      return res.status(400).json({ error: "Invalid userId" });
    }

    if (!order || typeof order !== "object") {
      return res.status(400).json({ error: "Missing order" });
    }

    if (!order.order_id || !String(order.order_id).trim()) {
      return res.status(400).json({ error: "Missing order_id" });
    }

    if (!order.order_date || !String(order.order_date).trim()) {
      return res.status(400).json({ error: "Missing order_date" });
    }

    // revenue & product_cost are required for your UI calculations
    if (order.revenue === undefined || order.revenue === null) {
      return res.status(400).json({ error: "Missing revenue" });
    }
    if (order.product_cost === undefined || order.product_cost === null) {
      return res.status(400).json({ error: "Missing product_cost" });
    }

    // If DB connected, persist in Postgres
    if (pool) {
      const created = await pool.query(
        `INSERT INTO orders (
          user_id, order_id, order_date, customer_name, product_name,
          revenue, product_cost, shipping_cost, platform_fee, other_costs,
          status, notes
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        RETURNING *`,
        [
          userIdNum,
          String(order.order_id).trim(),
          String(order.order_date).trim(),
          (order.customer_name || "").toString(),
          (order.product_name || "").toString(),
          Number(order.revenue || 0),
          Number(order.product_cost || 0),
          Number(order.shipping_cost || 0),
          Number(order.platform_fee || 0),
          Number(order.other_costs || 0),
          (order.status || "pending").toString(),
          (order.notes || "").toString()
        ]
      );

      return res.json({ success: true, order: created.rows[0] });
    }

    // Fallback (no DB): still respond OK to keep the app usable
    return res.json({
      success: true,
      order: {
        id: Date.now(),
        user_id: userIdNum,
        ...order
      }
    });

  } catch (err) {
    console.error("POST /orders error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

    // fallback memory
    const newOrder = { id: Date.now(), user_id: userId, ...order, created_at: new Date().toISOString() };
    mem.orders.push(newOrder);
    return res.json({ success: true, order: newOrder });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Server error" });
  }
});

app.get("/orders", async (req, res) => {
  try {
    const userId = String(req.query.userId || "").trim();
    if (!userId) return res.status(400).json({ error: "Missing userId" });

    if (pool) {
      const rows = await pool.query("SELECT * FROM orders WHERE user_id=$1 ORDER BY created_at DESC", [Number(userId)]);
      return res.json({ success: true, orders: rows.rows });
    }

    const orders = mem.orders.filter(o => String(o.user_id) === userId);
    return res.json({ success: true, orders });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Server error" });
  }
});

app.put("/orders/:id", async (req, res) => {
  try {
    const userId = String(req.body.userId || "").trim();
    const order = req.body.order;
    const id = String(req.params.id);

    if (!userId) return res.status(400).json({ error: "Missing userId" });
    if (!order) return res.status(400).json({ error: "Missing order" });

    if (pool) {
      const updated = await pool.query(
        `UPDATE orders
         SET order_id=$1, order_date=$2, customer_name=$3, product_name=$4, revenue=$5, product_cost=$6, shipping_cost=$7,
             platform_fee=$8, other_costs=$9, status=$10, notes=$11
         WHERE id=$12 AND user_id=$13
         RETURNING *`,
        [
          order.order_id,
          order.order_date,
          order.customer_name || "",
          order.product_name || "",
          Number(order.revenue || 0),
          Number(order.product_cost || 0),
          Number(order.shipping_cost || 0),
          Number(order.platform_fee || 0),
          Number(order.other_costs || 0),
          order.status || "pending",
          order.notes || "",
          Number(id),
          Number(userId)
        ]
      );
      if (!updated.rows.length) return res.status(404).json({ error: "Order not found" });
      return res.json({ success: true, order: updated.rows[0] });
    }

    // fallback memory
    const idx = mem.orders.findIndex(o => String(o.id) === id && String(o.user_id) === userId);
    if (idx === -1) return res.status(404).json({ error: "Order not found" });
    mem.orders[idx] = { ...mem.orders[idx], ...order };
    return res.json({ success: true, order: mem.orders[idx] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Server error" });
  }
});

app.delete("/orders/:id", async (req, res) => {
  try {
    const userId = String(req.query.userId || "").trim();
    const id = String(req.params.id);

    if (!userId) return res.status(400).json({ error: "Missing userId" });

    if (pool) {
      const del = await pool.query("DELETE FROM orders WHERE id=$1 AND user_id=$2 RETURNING id", [Number(id), Number(userId)]);
      if (!del.rows.length) return res.status(404).json({ error: "Order not found" });
      return res.json({ success: true });
    }

    const before = mem.orders.length;
    mem.orders = mem.orders.filter(o => !(String(o.id) === id && String(o.user_id) === userId));
    if (mem.orders.length === before) return res.status(404).json({ error: "Order not found" });
    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Server error" });
  }
});

app.listen(PORT, () => console.log(`Loguil backend running on port ${PORT}`));
