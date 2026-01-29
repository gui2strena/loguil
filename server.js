// server.js — Loguil Backend (Users + Orders + Password + Stripe Billing)
// Postgres (optional) + Memory fallback

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const Stripe = require("stripe");

let Pool;
try {
  ({ Pool } = require("pg"));
} catch {
  /* pg optional */
}

const app = express();
const PORT = process.env.PORT || 10000;

// -------------------- CORS --------------------
app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN || "*",
    credentials: false,
  })
);

// -------------------- STRIPE (Webhook needs raw body) --------------------
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// -------------------- DB (optional but preferred) --------------------
const hasDb = !!process.env.DATABASE_URL && !!Pool;

const pool = hasDb
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
    })
  : null;

// fallback memory (if DB missing)
const mem = {
  users: [], // {id,email,password_hash,store_name,currency,plan,trial_ends,subscription_status,stripe_customer_id,stripe_subscription_id}
  orders: [], // {id,user_id,...,created_at}
};

// -------------------- helpers --------------------
function toInt(value) {
  const n = Number(String(value ?? "").trim());
  return Number.isFinite(n) ? n : null;
}

async function userExists(userIdNum) {
  if (!Number.isFinite(userIdNum)) return false;

  if (pool) {
    const r = await pool.query("SELECT 1 FROM users WHERE id=$1 LIMIT 1", [userIdNum]);
    return r.rows.length > 0;
  }

  return mem.users.some((u) => Number(u.id) === userIdNum);
}

function assertAuthMatches(req, res, userIdNum) {
  if (!req.auth || !Number.isFinite(Number(req.auth.userId))) {
    res.status(401).json({ error: "Invalid token" });
    return false;
  }
  if (Number(req.auth.userId) !== userIdNum) {
    res.status(403).json({ error: "Forbidden" });
    return false;
  }
  return true;
}

// -------------------- billing helpers --------------------
async function updateUserBillingFromStripe({
  userId,
  plan,
  subscription_status,
  stripe_customer_id,
  stripe_subscription_id,
}) {
  if (!Number.isFinite(Number(userId))) return;

  if (pool) {
    await pool.query(
      `UPDATE users
       SET plan=$1,
           subscription_status=$2,
           stripe_customer_id=$3,
           stripe_subscription_id=$4
       WHERE id=$5`,
      [
        String(plan),
        String(subscription_status || "active"),
        String(stripe_customer_id || ""),
        String(stripe_subscription_id || ""),
        Number(userId),
      ]
    );
    return;
  }

  const u = mem.users.find((x) => Number(x.id) === Number(userId));
  if (!u) return;
  u.plan = String(plan);
  u.subscription_status = String(subscription_status || "active");
  u.stripe_customer_id = String(stripe_customer_id || "");
  u.stripe_subscription_id = String(stripe_subscription_id || "");
}

async function updateUserBillingByCustomerId({
  stripe_customer_id,
  subscription_status,
  stripe_subscription_id,
}) {
  if (!stripe_customer_id) return;

  if (pool) {
    await pool.query(
      `UPDATE users
       SET subscription_status=$1,
           stripe_subscription_id=$2
       WHERE stripe_customer_id=$3`,
      [
        String(subscription_status || "active"),
        String(stripe_subscription_id || ""),
        String(stripe_customer_id || ""),
      ]
    );
    return;
  }

  const u = mem.users.find((x) => x.stripe_customer_id === stripe_customer_id);
  if (!u) return;
  u.subscription_status = String(subscription_status || "active");
  u.stripe_subscription_id = String(stripe_subscription_id || "");
}

// -------------------- STRIPE WEBHOOK (MUST be BEFORE express.json) --------------------
app.post("/stripe/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    if (!stripe) return res.status(400).send("Stripe not configured");
    if (!STRIPE_WEBHOOK_SECRET) return res.status(400).send("Webhook secret missing");

    const sig = req.headers["stripe-signature"];
    if (!sig) return res.status(400).send("Missing stripe-signature");

    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      return res.status(400).send(`Webhook signature verification failed: ${err.message}`);
    }

    // Handle events
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;

      const userId = Number(session?.metadata?.userId);
      const plan = (session?.metadata?.plan || "").toString();
      const customerId = session.customer;
      const subscriptionId = session.subscription;

      if (Number.isFinite(userId) && plan) {
        await updateUserBillingFromStripe({
          userId,
          plan,
          subscription_status: "active",
          stripe_customer_id: customerId || "",
          stripe_subscription_id: subscriptionId || "",
        });
      }
    }

    if (
      event.type === "customer.subscription.updated" ||
      event.type === "customer.subscription.deleted"
    ) {
      const sub = event.data.object;
      const customerId = sub.customer;
      const status = sub.status; // active, trialing, past_due, canceled, unpaid, etc.

      const subscription_status =
        status === "active" || status === "trialing" ? "active" : "inactive";

      await updateUserBillingByCustomerId({
        stripe_customer_id: customerId || "",
        subscription_status,
        stripe_subscription_id: sub.id || "",
      });
    }

    return res.json({ received: true });
  } catch (err) {
    return res.status(500).send(err.message || "Webhook error");
  }
});

// Now we can parse JSON normally for the rest of the app
app.use(express.json());

// -------------------- JWT --------------------
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const JWT_EXPIRES_IN = "7d";

function signToken(user) {
  return jwt.sign({ userId: Number(user.id), email: user.email }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });
}

function requireAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const [type, token] = auth.split(" ");

    if (type !== "Bearer" || !token) {
      return res.status(401).json({ error: "Missing token" });
    }

    const payload = jwt.verify(token, JWT_SECRET);
    req.auth = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// -------------------- DB init --------------------
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

  // Add billing columns safely (for existing DBs)
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_status TEXT DEFAULT 'active';`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT DEFAULT '';`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT DEFAULT '';`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_orders_user_created
    ON orders (user_id, created_at DESC);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_password_resets_user
    ON password_resets (user_id);
  `);
}

// run at startup
ensureTables().catch((err) => console.error("DB init error:", err.message || err));

// -------------------- health --------------------
app.get("/", (req, res) => {
  res.json({ status: "ok", app: "Loguil", db: !!pool });
});

// -------------------- debug --------------------
app.get("/debug", async (req, res) => {
  try {
    if (!pool) {
      return res.json({
        status: "ok",
        app: "Loguil",
        db: "disabled",
        users: mem.users.length,
        orders: mem.orders.length,
      });
    }

    const users = await pool.query("SELECT COUNT(*)::int AS count FROM users");
    const orders = await pool.query("SELECT COUNT(*)::int AS count FROM orders");

    return res.json({
      status: "ok",
      app: "Loguil",
      db: "connected",
      users: users.rows[0].count,
      orders: orders.rows[0].count,
    });
  } catch (err) {
    return res.status(500).json({
      status: "error",
      app: "Loguil",
      db: "failed",
      message: err.message,
    });
  }
});

// -------------------- auth: signup --------------------
app.post("/signup", async (req, res) => {
  try {
    const { email, password, storeName, currency } = req.body || {};
    if (!email || !password || !storeName || !currency) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const emailNorm = String(email).toLowerCase().trim();
    const password_hash = await bcrypt.hash(String(password), 10);
    const trial_ends = new Date(Date.now() + 14 * 86400000).toISOString();

    if (pool) {
      const existing = await pool.query("SELECT id FROM users WHERE email=$1", [emailNorm]);
      if (existing.rows.length) return res.status(400).json({ error: "Email already registered" });

      const created = await pool.query(
        `INSERT INTO users (email, password_hash, store_name, currency, plan, trial_ends, subscription_status, stripe_customer_id, stripe_subscription_id)
         VALUES ($1,$2,$3,$4,'trial',$5,'active','','')
         RETURNING id,email,store_name,currency,plan,trial_ends,subscription_status,stripe_customer_id,stripe_subscription_id`,
        [emailNorm, password_hash, String(storeName), String(currency), trial_ends]
      );

      const user = created.rows[0];
      const token = signToken(user);
      return res.json({ success: true, user, token });
    }

    // memory fallback
    const exists = mem.users.find((u) => u.email === emailNorm);
    if (exists) return res.status(400).json({ error: "Email already registered" });

    const user = {
      id: mem.users.length + 1,
      email: emailNorm,
      password_hash,
      store_name: String(storeName),
      currency: String(currency),
      plan: "trial",
      trial_ends,
      subscription_status: "active",
      stripe_customer_id: "",
      stripe_subscription_id: "",
    };
    mem.users.push(user);

    const safe = { ...user };
    delete safe.password_hash;
    const token = signToken(safe);
    return res.json({ success: true, user: safe, token });
  } catch (err) {
    console.error("POST /signup error:", err);
    return res.status(500).json({ error: err.message || "Server error" });
  }
});

// -------------------- auth: login --------------------
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Missing credentials" });

    const emailNorm = String(email).toLowerCase().trim();

    if (pool) {
      const found = await pool.query(
        "SELECT id,email,password_hash,store_name,currency,plan,trial_ends,subscription_status,stripe_customer_id,stripe_subscription_id FROM users WHERE email=$1",
        [emailNorm]
      );
      if (!found.rows.length) return res.status(404).json({ error: "User not found" });

      const user = found.rows[0];
      const ok = await bcrypt.compare(String(password), user.password_hash);
      if (!ok) return res.status(401).json({ error: "Incorrect password" });

      delete user.password_hash;
      const token = signToken(user);
      return res.json({ success: true, user, token });
    }

    // memory fallback
    const user = mem.users.find((u) => u.email === emailNorm);
    if (!user) return res.status(404).json({ error: "User not found" });

    const ok = await bcrypt.compare(String(password), user.password_hash);
    if (!ok) return res.status(401).json({ error: "Incorrect password" });

    const safe = { ...user };
    delete safe.password_hash;
    const token = signToken(safe);
    return res.json({ success: true, user: safe, token });
  } catch (err) {
    console.error("POST /login error:", err);
    return res.status(500).json({ error: err.message || "Server error" });
  }
});

// -------------------- change password --------------------
app.post("/change-password", requireAuth, async (req, res) => {
  try {
    const userIdNum = toInt(req.body?.userId);
    const currentPassword = (req.body?.currentPassword ?? "").toString();
    const newPassword = (req.body?.newPassword ?? "").toString();

    if (!userIdNum) return res.status(400).json({ error: "Missing/invalid userId" });
    if (!assertAuthMatches(req, res, userIdNum)) return;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: "Missing password fields" });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: "New password must be at least 6 characters" });
    }

    if (pool) {
      const found = await pool.query("SELECT id, password_hash FROM users WHERE id=$1", [userIdNum]);
      if (!found.rows.length) return res.status(404).json({ error: "User not found" });

      const ok = await bcrypt.compare(currentPassword, found.rows[0].password_hash);
      if (!ok) return res.status(401).json({ error: "Incorrect current password" });

      const newHash = await bcrypt.hash(newPassword, 10);
      await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2", [newHash, userIdNum]);
      return res.json({ success: true });
    }

    const u = mem.users.find((x) => Number(x.id) === userIdNum);
    if (!u) return res.status(404).json({ error: "User not found" });

    const ok = await bcrypt.compare(currentPassword, u.password_hash);
    if (!ok) return res.status(401).json({ error: "Incorrect current password" });

    u.password_hash = await bcrypt.hash(newPassword, 10);
    return res.json({ success: true });
  } catch (err) {
    console.error("POST /change-password error:", err);
    return res.status(500).json({ error: err.message || "Server error" });
  }
});

// -------------------- forgot/reset password (DB only) --------------------
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: "Missing email" });

    const emailNorm = String(email).toLowerCase().trim();
    if (!pool) return res.status(400).json({ error: "Password reset requires DB" });

    const found = await pool.query("SELECT id FROM users WHERE email=$1", [emailNorm]);
    if (!found.rows.length) return res.status(404).json({ error: "User not found" });

    const userId = found.rows[0].id;
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // 30 min

    await pool.query("DELETE FROM password_resets WHERE user_id=$1", [userId]);
    await pool.query(
      "INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1,$2,$3)",
      [userId, token, expiresAt]
    );

    return res.json({ success: true, token });
  } catch (err) {
    console.error("POST /forgot-password error:", err);
    return res.status(500).json({ error: err.message || "Server error" });
  }
});

app.post("/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword) return res.status(400).json({ error: "Missing token or newPassword" });
    if (!pool) return res.status(400).json({ error: "Password reset requires DB" });
    if (String(newPassword).length < 6) return res.status(400).json({ error: "New password must be at least 6 characters" });

    const tokenNorm = String(token).trim();
    const row = await pool.query(
      `SELECT user_id, expires_at FROM password_resets WHERE token=$1 LIMIT 1`,
      [tokenNorm]
    );
    if (!row.rows.length) return res.status(400).json({ error: "Invalid token" });

    const { user_id, expires_at } = row.rows[0];
    if (Date.now() > new Date(expires_at).getTime()) return res.status(400).json({ error: "Token expired" });

    const password_hash = await bcrypt.hash(String(newPassword), 10);
    await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2", [password_hash, user_id]);
    await pool.query("DELETE FROM password_resets WHERE token=$1", [tokenNorm]);

    return res.json({ success: true });
  } catch (err) {
    console.error("POST /reset-password error:", err);
    return res.status(500).json({ error: err.message || "Server error" });
  }
});

// -------------------- STRIPE: checkout --------------------
// contract: POST /create-checkout-session  { userId, plan }
// Requires Bearer token
app.post("/create-checkout-session", requireAuth, async (req, res) => {
  try {
    if (!stripe) return res.status(400).json({ error: "Stripe not configured" });

    const userIdNum = toInt(req.body?.userId);
    const plan = (req.body?.plan || "").toString().trim(); // starter | pro | growth

    if (!userIdNum) return res.status(400).json({ error: "Missing/invalid userId" });
    if (!assertAuthMatches(req, res, userIdNum)) return;
    if (!plan) return res.status(400).json({ error: "Missing plan" });

    const PRICE_STARTER =
      process.env.STRIPE_PRICE_STARTER || process.env.STRIPE_PRICE_BASIC || "";
    const PRICE_PRO = process.env.STRIPE_PRICE_PRO || "";
    const PRICE_GROWTH = process.env.STRIPE_PRICE_GROWTH || "";

    const priceId =
      plan === "starter" ? PRICE_STARTER :
      plan === "pro" ? PRICE_PRO :
      plan === "growth" ? PRICE_GROWTH :
      "";

    if (!priceId) return res.status(400).json({ error: "Price not configured for this plan" });

    const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${FRONTEND_URL}?checkout=success`,
      cancel_url: `${FRONTEND_URL}?checkout=cancel`,
      metadata: {
        userId: String(userIdNum),
        plan: String(plan),
      },
    });

    return res.json({ success: true, url: session.url });
  } catch (err) {
    console.error("POST /create-checkout-session error:", err);
    return res.status(500).json({ error: err.message || "Server error" });
  }
});

// -------------------- STRIPE: cancel subscription --------------------
// contract: POST /cancel-subscription  { userId }
// Requires Bearer token
app.post("/cancel-subscription", requireAuth, async (req, res) => {
  try {
    if (!stripe) return res.status(400).json({ error: "Stripe not configured" });

    const userIdNum = toInt(req.body?.userId);
    if (!userIdNum) return res.status(400).json({ error: "Missing/invalid userId" });
    if (!assertAuthMatches(req, res, userIdNum)) return;

    // Load user from DB
    if (!pool) return res.status(400).json({ error: "Cancel requires DB enabled" });

    const found = await pool.query(
      "SELECT stripe_subscription_id, stripe_customer_id FROM users WHERE id=$1",
      [userIdNum]
    );
    if (!found.rows.length) return res.status(404).json({ error: "User not found" });

    const subId = String(found.rows[0].stripe_subscription_id || "");
    if (!subId) return res.status(400).json({ error: "No active subscription on user" });

    // Cancel now (simple). If you prefer end of period: use { cancel_at_period_end: true }
    await stripe.subscriptions.cancel(subId);

    // Update DB immediately (webhook will also sync later)
    await pool.query(
      `UPDATE users
       SET subscription_status='inactive',
           plan='trial'
       WHERE id=$1`,
      [userIdNum]
    );

    return res.json({ success: true });
  } catch (err) {
    console.error("POST /cancel-subscription error:", err);
    return res.status(500).json({ error: err.message || "Server error" });
  }
});

// -------------------- orders --------------------
// POST /orders   body: { userId, order }
app.post("/orders", requireAuth, async (req, res) => {
  try {
    const userIdNum = toInt(req.body?.userId);
    if (!userIdNum) return res.status(400).json({ error: "Missing/invalid userId" });
    if (!assertAuthMatches(req, res, userIdNum)) return;

    const okUser = await userExists(userIdNum);
    if (!okUser) return res.status(404).json({ error: "User not found" });

    const order = req.body?.order;
    if (!order || typeof order !== "object") return res.status(400).json({ error: "Missing order" });
    if (!order.order_id || !String(order.order_id).trim()) return res.status(400).json({ error: "Missing order_id" });
    if (!order.order_date || !String(order.order_date).trim()) return res.status(400).json({ error: "Missing order_date" });

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
          (order.notes || "").toString(),
        ]
      );
      return res.json({ success: true, order: created.rows[0] });
    }

    const newOrder = {
      id: Date.now(),
      user_id: userIdNum,
      ...order,
      created_at: new Date().toISOString(),
    };
    mem.orders.push(newOrder);
    return res.json({ success: true, order: newOrder });
  } catch (err) {
    console.error("POST /orders error:", err);
    return res.status(500).json({ error: err.message || "Server error" });
  }
});

// GET /orders?userId=123
app.get("/orders", requireAuth, async (req, res) => {
  try {
    const userIdNum = toInt(req.query.userId);
    if (!userIdNum) return res.status(400).json({ error: "Missing/invalid userId" });
    if (!assertAuthMatches(req, res, userIdNum)) return;

    const okUser = await userExists(userIdNum);
    if (!okUser) return res.status(404).json({ error: "User not found" });

    if (pool) {
      const rows = await pool.query(
        "SELECT * FROM orders WHERE user_id=$1 ORDER BY created_at DESC",
        [userIdNum]
      );
      return res.json({ success: true, orders: rows.rows });
    }

    const orders = mem.orders.filter((o) => Number(o.user_id) === userIdNum);
    return res.json({ success: true, orders });
  } catch (err) {
    console.error("GET /orders error:", err);
    return res.status(500).json({ error: err.message || "Server error" });
  }
});

// PUT /orders/:id  body: { userId, order }
app.put("/orders/:id", requireAuth, async (req, res) => {
  try {
    const userIdNum = toInt(req.body?.userId);
    const idNum = toInt(req.params.id);
    const order = req.body?.order;

    if (!userIdNum) return res.status(400).json({ error: "Missing/invalid userId" });
    if (!idNum) return res.status(400).json({ error: "Missing/invalid id" });
    if (!assertAuthMatches(req, res, userIdNum)) return;
    if (!order || typeof order !== "object") return res.status(400).json({ error: "Missing order" });

    const okUser = await userExists(userIdNum);
    if (!okUser) return res.status(404).json({ error: "User not found" });

    if (pool) {
      const updated = await pool.query(
        `UPDATE orders
         SET order_id=$1, order_date=$2, customer_name=$3, product_name=$4,
             revenue=$5, product_cost=$6, shipping_cost=$7, platform_fee=$8,
             other_costs=$9, status=$10, notes=$11
         WHERE id=$12 AND user_id=$13
         RETURNING *`,
        [
          String(order.order_id || "").trim(),
          String(order.order_date || "").trim(),
          (order.customer_name || "").toString(),
          (order.product_name || "").toString(),
          Number(order.revenue || 0),
          Number(order.product_cost || 0),
          Number(order.shipping_cost || 0),
          Number(order.platform_fee || 0),
          Number(order.other_costs || 0),
          (order.status || "pending").toString(),
          (order.notes || "").toString(),
          idNum,
          userIdNum,
        ]
      );
      if (!updated.rows.length) return res.status(404).json({ error: "Order not found" });
      return res.json({ success: true, order: updated.rows[0] });
    }

    const idx = mem.orders.findIndex(
      (o) => Number(o.id) === idNum && Number(o.user_id) === userIdNum
    );
    if (idx === -1) return res.status(404).json({ error: "Order not found" });

    mem.orders[idx] = { ...mem.orders[idx], ...order };
    return res.json({ success: true, order: mem.orders[idx] });
  } catch (err) {
    console.error("PUT /orders/:id error:", err);
    return res.status(500).json({ error: err.message || "Server error" });
  }
});

// DELETE /orders/:id?userId=123
app.delete("/orders/:id", requireAuth, async (req, res) => {
  try {
    const userIdNum = toInt(req.query.userId);
    const idNum = toInt(req.params.id);

    if (!userIdNum) return res.status(400).json({ error: "Missing/invalid userId" });
    if (!idNum) return res.status(400).json({ error: "Missing/invalid id" });
    if (!assertAuthMatches(req, res, userIdNum)) return;

    const okUser = await userExists(userIdNum);
    if (!okUser) return res.status(404).json({ error: "User not found" });

    if (pool) {
      const del = await pool.query(
        "DELETE FROM orders WHERE id=$1 AND user_id=$2 RETURNING id",
        [idNum, userIdNum]
      );
      if (!del.rows.length) return res.status(404).json({ error: "Order not found" });
      return res.json({ success: true });
    }

    const before = mem.orders.length;
    mem.orders = mem.orders.filter(
      (o) => !(Number(o.id) === idNum && Number(o.user_id) === userIdNum)
    );
    if (mem.orders.length === before) return res.status(404).json({ error: "Order not found" });

    return res.json({ success: true });
  } catch (err) {
    console.error("DELETE /orders/:id error:", err);
    return res.status(500).json({ error: err.message || "Server error" });
  }
});

app.listen(PORT, () => console.log(`Loguil backend running on port ${PORT}`));
