const express = require("express");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// =======================
// Database
// =======================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// =======================
// Health check
// =======================
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    time: new Date().toISOString(),
  });
});

// =======================
// DB test
// =======================
app.get("/db-test", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ db: "connected" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ db: "error" });
  }
});

// =======================
// ADMIN SETUP (1x)
// =======================
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
    // agents table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS agents (
        id SERIAL PRIMARY KEY,
        agent_id TEXT UNIQUE NOT NULL,
        pin_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // hash pin
    const pinHash = await bcrypt.hash(pin, 10);

    // insert agent
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

// =======================
// AUTH LOGIN
// =======================
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

// =======================
app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
});
