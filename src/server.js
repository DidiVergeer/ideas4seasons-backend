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
      "https://ideas4seasons-frontend.onrender.com", // productie
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
   AFAS HELPERS
   ======================= */
function buildAfasAuthHeaderFromData(dataToken) {
  // AFAS classic token: base64 van XML token wrapper
  const xmlToken = `<token><version>1</version><data>${dataToken}</data></token>`;
  const b64 = Buffer.from(xmlToken, "utf8").toString("base64");
  return `AfasToken ${b64}`;
}

async function fetchAfas(connectorId, { skip = 0, take = 1 } = {}) {
  const env = process.env.AFAS_ENV; // "82610"
  const dataToken = process.env.AFAS_TOKEN_DATA; // 60-tekens data string

  if (!env || !dataToken || !connectorId) {
    throw new Error(
      "Missing AFAS env vars (AFAS_ENV / AFAS_TOKEN_DATA / AFAS_CONNECTOR)"
    );
  }

  const url = `https://${env}.rest.afas.online/ProfitRestServices/connectors/${connectorId}?skip=${skip}&take=${take}`;

  const res = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: buildAfasAuthHeaderFromData(dataToken),
      Accept: "application/json",
    },
  });

  const text = await res.text();
  if (!res.ok) throw new Error(`AFAS ${res.status}: ${text}`);

  return JSON.parse(text);
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
   AFAS health check
   ======================= */
app.get("/health/afas", async (req, res) => {
  try {
    const connectorId = process.env.AFAS_CONNECTOR; // "Items_Core"
    const data = await fetchAfas(connectorId, { skip: 0, take: 1 });

    res.json({
      ok: true,
      env: process.env.AFAS_ENV,
      connectorId,
      sample: data?.rows?.[0] ?? null,
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: err.message || String(err),
    });
  }
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
   PRODUCTS TABLE SETUP (A1)
   ======================= */
app.post("/db/setup-products", async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS products (
        itemcode TEXT PRIMARY KEY,
        type_item TEXT NULL,
        description_eng TEXT NULL,
        unit TEXT NULL,
        price NUMERIC NULL,
        outercarton TEXT NULL,
        innercarton TEXT NULL,
        ean TEXT NULL,
        available_stock NUMERIC NULL,
        ecommerce_available BOOLEAN NULL,
        raw JSONB NULL,
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    res.json({ ok: true, message: "products table ready" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* =======================
   SYNC PRODUCTS (A2)
   ======================= */
app.post("/sync/products", async (req, res) => {
  // beveiliging met dezelfde setup key als admin/setup
  const key = req.query.key;
  if (!key || key !== process.env.SETUP_KEY) {
    return res.status(401).json({ ok: false, error: "Invalid setup key" });
  }

  const connectorId = process.env.AFAS_CONNECTOR; // Items_Core
  const take = Number(req.query.take || 100);

  let skip = 0;
  let pages = 0;
  let totalUpserted = 0;

  try {
    while (true) {
      const data = await fetchAfas(connectorId, { skip, take });
      const rows = data?.rows || [];

      if (rows.length === 0) break;

      for (const r of rows) {
        // itemcode is leidend
        const itemcode = r.Itemcode ?? null;
        if (!itemcode) continue;

        await pool.query(
          `
          INSERT INTO products (
            itemcode,
            type_item,
            description_eng,
            unit,
            price,
            outercarton,
            innercarton,
            ean,
            available_stock,
            ecommerce_available,
            raw,
            updated_at
          ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, NOW()
          )
          ON CONFLICT (itemcode) DO UPDATE SET
            type_item = EXCLUDED.type_item,
            description_eng = EXCLUDED.description_eng,
            unit = EXCLUDED.unit,
            price = EXCLUDED.price,
            outercarton = EXCLUDED.outercarton,
            innercarton = EXCLUDED.innercarton,
            ean = EXCLUDED.ean,
            available_stock = EXCLUDED.available_stock,
            ecommerce_available = EXCLUDED.ecommerce_available,
            raw = EXCLUDED.raw,
            updated_at = NOW()
          `,
          [
            itemcode,
            r.Type_item ?? null,
            r.OMSCHRIJVING_ENG ?? null,
            r.UNIT ?? null,
            r.Prijs ?? null,
            r.OUTERCARTON ?? null,
            r.INNERCARTON ?? null,
            r["EAN_product__Opgeschoonde_barcode_"] ?? null,
            r.Beschikbare_voorraad ?? null,
            r["E-commerce_beschikbaar"] ?? null,
            r, // raw JSONB
          ]
        );

        totalUpserted += 1;
      }

      pages += 1;
      skip += rows.length;

      if (rows.length < take) break;
    }

    res.json({ ok: true, pages, upserted: totalUpserted });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
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

    const token = jwt.sign({ agentId: agent.agent_id }, process.env.JWT_SECRET, {
      expiresIn: "8h",
    });

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
