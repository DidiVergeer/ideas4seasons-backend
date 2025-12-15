const crypto = require("crypto");
const jwt = require("jsonwebtoken");

// Helper: hash PIN met salt (veilig genoeg voor V1)
function hashPin(pin, salt) {
  return crypto.pbkdf2Sync(pin, salt, 100000, 64, "sha512").toString("hex");
}

/**
 * 1) Setup endpoint (beveiligd met SETUP_KEY)
 * Gebruik: POST /admin/setup?key=JOUW_SETUP_KEY
 * Body: { "agentId": "A100", "pin": "1234" }
 */
app.post("/admin/setup", async (req, res) => {
  try {
    const key = req.query.key;
    if (!key || key !== process.env.SETUP_KEY) {
      return res.status(401).json({ error: "invalid_setup_key" });
    }

    const { agentId, pin } = req.body || {};
    if (!agentId || !pin) return res.status(400).json({ error: "missing_agentId_or_pin" });

    // Table aanmaken (1x)
    await pool.query(`
      create table if not exists agents (
        agent_id text primary key,
        pin_salt text not null,
        pin_hash text not null,
        active boolean not null default true,
        created_at timestamptz not null default now()
      );
    `);

    // Agent upsert
    const salt = crypto.randomBytes(16).toString("hex");
    const pinHash = hashPin(pin, salt);

    await pool.query(
      `
      insert into agents(agent_id, pin_salt, pin_hash, active)
      values ($1, $2, $3, true)
      on conflict (agent_id)
      do update set pin_salt = excluded.pin_salt, pin_hash = excluded.pin_hash, active = true
      `,
      [agentId, salt, pinHash]
    );

    res.json({ ok: true, agentId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "server_error" });
  }
});

/**
 * 2) Login endpoint
 * POST /auth/login
 * Body: { "agentId": "A100", "pin": "1234" }
 */
app.post("/auth/login", async (req, res) => {
  try {
    const { agentId, pin } = req.body || {};
    if (!agentId || !pin) return res.status(400).json({ error: "missing_agentId_or_pin" });

    const r = await pool.query(
      "select agent_id, pin_salt, pin_hash, active from agents where agent_id = $1",
      [agentId]
    );

    if (r.rowCount === 0) return res.status(401).json({ error: "invalid_login" });
    const row = r.rows[0];
    if (!row.active) return res.status(403).json({ error: "inactive" });

    const computed = hashPin(pin, row.pin_salt);
    if (computed !== row.pin_hash) return res.status(401).json({ error: "invalid_login" });

    const token = jwt.sign({ agentId: row.agent_id }, process.env.JWT_SECRET, { expiresIn: "8h" });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "server_error" });
  }
});
