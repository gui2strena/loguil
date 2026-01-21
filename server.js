// Loguil Backend – Postgres Auth (MVP)
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "*";
app.use(cors({
  origin: FRONTEND_ORIGIN === "*" ? "*" : [FRONTEND_ORIGIN],
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : undefined
});

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      store_name TEXT NOT NULL,
      currency TEXT NOT NULL DEFAULT 'EUR',
      plan TEXT NOT NULL DEFAULT 'trial',
      trial_ends TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

app.get("/", (req, res) => {
  res.json({ status: "ok", app: "Loguil", message: "Backend is running" });
});

app.post("/signup", async (req, res) => {
  try {
    const { email, password, storeName, currency } = req.body;

    if (!email || !password || !storeName) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const normalizedEmail = String(email).toLowerCase().trim();

    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [normalizedEmail]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "This email is already registered" });
    }

    const password_hash = await bcrypt.hash(String(password), 10);

    const trialEnd = new Date();
    trialEnd.setDate(trialEnd.getDate() + 14);

    const inserted = await pool.query(
      `INSERT INTO users (email, password_hash, store_name, currency, plan, trial_ends)
       VALUES ($1, $2, $3, $4, 'trial', $5)
       RETURNING id, email, store_name, currency, plan, trial_ends`,
      [normalizedEmail, password_hash, storeName, currency || "EUR", trialEnd.toISOString()]
    );

    return res.json({
      success: true,
      message: "Account created",
      user: inserted.rows[0]
    });
  } catch (err) {
    console.error("signup error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Missing credentials" });
    }

    const normalizedEmail = String(email).toLowerCase().trim();

    const result = await pool.query(
      "SELECT id, email, password_hash, store_name, currency, plan, trial_ends FROM users WHERE email = $1",
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = result.rows[0];
    const ok = await bcrypt.compare(String(password), user.password_hash);
    if (!ok) return res.status(401).json({ error: "Incorrect password" });

    return res.json({
      success: true,
      message: "Login successful",
      user: {
        id: user.id,
        email: user.email,
        store_name: user.store_name,
        currency: user.currency,
        plan: user.plan,
        trial_ends: user.trial_ends
      }
    });
  } catch (err) {
    console.error("login error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

(async () => {
  await ensureSchema();
  app.listen(PORT, () => console.log(`Loguil backend running on port ${PORT}`));
})();
