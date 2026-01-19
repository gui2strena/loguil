// Loguil Backend – Minimal SaaS Server
const express = require("express");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(cors());
app.use(express.json());

// Health check (test if backend is running)
app.get("/", (req, res) => {
  res.json({
    status: "ok",
    app: "Loguil",
    message: "Backend is running"
  });
});

// Signup (mock – next step we connect Postgres)
app.post("/signup", (req, res) => {
  const { email, password, storeName, currency } = req.body;

  if (!email || !password || !storeName) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  return res.json({
    success: true,
    message: "User registered (mock)",
    user: {
      email,
      storeName,
      currency,
      plan: "trial"
    }
  });
});

// Login (mock)
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Missing credentials" });
  }

  return res.json({
    success: true,
    message: "Login successful (mock)",
    user: {
      email,
      plan: "trial"
    }
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Loguil backend running on port ${PORT}`);
});
