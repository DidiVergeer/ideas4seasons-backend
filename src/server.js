const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();

/* =======================
   CORS (BELANGRIJK)
   ======================= */
app.use(
  cors({
    origin: [
      "http://localhost:3000", // frontend lokaal
      "https://ideas4seasons-frontend.onrender.com", // straks productie
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());

const PORT = process.env.PORT || 3000;

/* =======================
   Database
   ======================= */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/* =======================
   AUTH MIDDLEWARE
   ======================= */
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

/* =======================
   Health check
   ======================= */
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    time: new Date().toISOString(),
  });
});

/* =======================
   DB test
   ======================= */
app.get("/db-test", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ db: "connected" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ db: "error" });
  }
});

/* =======================
   ADMIN SETUP (1x)
   ======================= */
app.post("/admin/setup", async (req, res) => {
  const setupKey = req.query.key;

  if (!setupKey || setupKey !== process.env.SETUP_KEY) {
    return res.status(401).json({ error: "Invalid setup key" });
  }

  const { agentId, pin } = req.body;

  if (!agentId || !pin) {
    return res.status(400).json({ error: "agentId and pin required" });
  }

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS agents (
        id SERIAL PRIMARY KEY,
        agent_id TEXT UNIQUE NOT NULL,
        pin_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    const pinHash = await bcrypt.hash(pin, 10);

    await pool.query(
      `
      INSERT INTO agents (agent_id, pin_hash)
      VALUES ($1, $2)
      ON CONFLICT (agent_id) DO NOTHING
      `,
      [agentId, pinHash]
    );

    res.json({
      status: "setup complete",
      agentId,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "setup failed" });
  }
});

/* =======================
   AUTH LOGIN
   ======================= */
app.post("/auth/login", async (req, res) => {
  const { agentId, pin } = req.body;

  if (!agentId || !pin) {
    return res.status(400).json({ error: "agentId and pin required" });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM agents WHERE agent_id = $1",
      [agentId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const agent = result.rows[0];
    const isValid = await bcrypt.compare(pin, agent.pin_hash);

    if (!isValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { agentId: agent.agent_id },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({
      token,
      agentId: agent.agent_id,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "login failed" });
  }
});

/* =======================
   ME (protected)
   ======================= */
app.get("/me", authMiddleware, (req, res) => {
  res.json({
    status: "ok",
    user: req.user,
  });
});

/* =======================
   START SERVER
   ======================= */
app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
});
