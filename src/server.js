// src/server.js
/* eslint-disable no-console */
"use strict";

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");
const { S3Client, PutObjectCommand, HeadObjectCommand } = require("@aws-sdk/client-s3");

// Node 18+ has global fetch
const fetchFn =
  typeof fetch !== "undefined"
    ? fetch
    : (...args) => import("node-fetch").then(({ default: f }) => f(...args));

/* =========================================================
   ENV
   =========================================================
   DATABASE_URL
   SETUP_KEY

   AFAS_ENV
   AFAS_TOKEN_DATA
   (optional) AFAS_TAKE_DEFAULT=100

   R2_BUCKET
   R2_ENDPOINT
   R2_PUBLIC_BASE_URL
   R2_ACCESS_KEY_ID
   R2_SECRET_ACCESS_KEY

   (optional) EXCLUDE_A_CODES=true|false
   ========================================================= */

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "1mb" })); // no base64 via API

/* =======================
   CORS
   ======================= */
const ALLOWED_ORIGINS = [
  "http://localhost:3000",
  "http://localhost:8081",
  "http://127.0.0.1:8081",
  "https://ideas4seasons-frontend.onrender.com",
];

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      if (/^http:\/\/192\.168\.\d{1,3}\.\d{1,3}:8081$/.test(origin)) return cb(null, true);
      return cb(new Error(`CORS blocked for origin: ${origin}`));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-setup-key"],
    credentials: true,
  })
);
app.options("*", cors());

/* =======================
   DB
   ======================= */
if (!process.env.DATABASE_URL) throw new Error("Missing DATABASE_URL");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/* =======================
   R2 (S3 compatible)
   ======================= */
const R2_BUCKET = process.env.R2_BUCKET;
const R2_ENDPOINT = process.env.R2_ENDPOINT;
const R2_PUBLIC_BASE_URL = process.env.R2_PUBLIC_BASE_URL;
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;

const r2 =
  R2_BUCKET && R2_ENDPOINT && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY
    ? new S3Client({
        region: "auto",
        endpoint: R2_ENDPOINT,
        credentials: {
          accessKeyId: R2_ACCESS_KEY_ID,
          secretAccessKey: R2_SECRET_ACCESS_KEY,
        },
      })
    : null;

function publicUrlForKey(key) {
  if (!R2_PUBLIC_BASE_URL) throw new Error("Missing R2_PUBLIC_BASE_URL");
  return `${R2_PUBLIC_BASE_URL.replace(/\/$/, "")}/${String(key).replace(/^\//, "")}`;
}

/* =======================
   Helpers
   ======================= */
const EXCLUDE_A_CODES = String(process.env.EXCLUDE_A_CODES || "true").toLowerCase() === "true";

function requireSetupKey(req, res) {
  const key = req.headers["x-setup-key"] || req.query.key || (req.body && req.body.key);
  if (!key || key !== process.env.SETUP_KEY) {
    res.status(401).json({ ok: false, error: "Invalid setup key" });
    return false;
  }
  return true;
}

function sha1(input) {
  return crypto.createHash("sha1").update(String(input), "utf8").digest("hex");
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function jitter(ms, pct = 0.25) {
  const delta = ms * pct;
  return Math.max(0, Math.round(ms - delta + Math.random() * (2 * delta)));
}

function normalizeBase64(v) {
  if (!v || typeof v !== "string") return null;
  const s = v.trim();
  if (!s) return null;
  const idx = s.indexOf("base64,");
  if (idx >= 0) return s.slice(idx + "base64,".length).trim();
  return s;
}

function guessMimeFromFilename(name) {
  if (!name) return null;
  const s = String(name).toLowerCase();
  if (s.endsWith(".png")) return "image/png";
  if (s.endsWith(".gif")) return "image/gif";
  if (s.endsWith(".webp")) return "image/webp";
  if (s.endsWith(".jpg") || s.endsWith(".jpeg")) return "image/jpeg";
  return null;
}

function guessMimeFromBase64(b64) {
  if (!b64) return "image/jpeg";
  if (b64.startsWith("/9j")) return "image/jpeg";
  if (b64.startsWith("iVBOR")) return "image/png";
  if (b64.startsWith("R0lGOD")) return "image/gif";
  if (b64.startsWith("UklGR")) return "image/webp";
  return "image/jpeg";
}

function extFromMime(mime) {
  if (mime === "image/png") return "png";
  if (mime === "image/gif") return "gif";
  if (mime === "image/webp") return "webp";
  return "jpg";
}

async function runWithConcurrency(items, concurrency, handler) {
  const results = new Array(items.length);
  let idx = 0;

  async function worker() {
    while (true) {
      const my = idx++;
      if (my >= items.length) break;
      results[my] = await handler(items[my], my);
    }
  }

  const n = Math.max(1, Number(concurrency) || 1);
  await Promise.all(Array.from({ length: n }, () => worker()));
  return results;
}

function parseBool(v) {
  if (typeof v === "boolean") return v;
  const s = String(v ?? "").trim().toLowerCase();
  return ["true", "1", "yes", "ja"].includes(s);
}

function toNumberOrNull(v) {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function toDateOrNull(v) {
  if (!v) return null;
  // AFAS sometimes returns "YYYY-MM-DD" or ISO; PG DATE accepts both
  return String(v);
}

/* =========================================================
   Field mapping (must exist before SFEER code uses it)
   ========================================================= */
const KIND_TO_AFAS_B64_FIELD = {
  MAIN: "Afbeelding",
  SFEER_1: "Afbeelding_1",
  SFEER_2: "Afbeelding_2",
  SFEER_3: "Afbeelding_3",
  SFEER_4: "Afbeelding_4",
  SFEER_5: "Afbeelding_5",
};

/* =======================
   AFAS (GetConnector)
   ======================= */
function buildAfasAuthHeaderFromData(dataToken) {
  const xmlToken = `<token><version>1</version><data>${dataToken}</data></token>`;
  const b64 = Buffer.from(xmlToken, "utf8").toString("base64");
  return `AfasToken ${b64}`;
}

function isRetryableAfasStatus(status) {
  return [429, 500, 502, 503, 504].includes(status);
}

async function fetchAfas(connectorId, { skip = 0, take = 100, extraQuery = "" } = {}) {
  const env = process.env.AFAS_ENV;
  const dataToken = process.env.AFAS_TOKEN_DATA;

  if (!env || !dataToken) throw new Error("Missing AFAS_ENV or AFAS_TOKEN_DATA");
  if (!connectorId) throw new Error("Missing connectorId");

  const baseUrl = `https://${env}.rest.afas.online/ProfitRestServices/connectors/${encodeURIComponent(connectorId)}`;
  const url = `${baseUrl}?skip=${skip}&take=${take}${extraQuery || ""}`;

  const res = await fetchFn(url, {
    method: "GET",
    headers: {
      Authorization: buildAfasAuthHeaderFromData(dataToken),
      Accept: "application/json",
    },
  });

  const text = await res.text();
  if (!res.ok) {
    const err = new Error(`AFAS ${res.status}: ${text}`);
    err.status = res.status;
    err.body = text;
    err.url = url;
    throw err;
  }

  return JSON.parse(text);
}

async function fetchAfasWithRetry(connectorId, opts = {}, retry = {}) {
  const { attempts = 6, baseDelayMs = 500, maxDelayMs = 8000 } = retry;
  let lastErr = null;

  for (let i = 0; i < attempts; i++) {
    try {
      return await fetchAfas(connectorId, opts);
    } catch (e) {
      lastErr = e;
      const status = e?.status;
      const retryable = status ? isRetryableAfasStatus(status) : true;
      if (!retryable || i === attempts - 1) throw e;

      const delay = Math.min(maxDelayMs, baseDelayMs * Math.pow(2, i));
      await sleep(jitter(delay));
    }
  }
  throw lastErr || new Error("AFAS fetch failed");
}

/**
 * Items_Pictures_app per-item lookup. Filtering can be flaky.
 * We try Itemcode + Code, with/without operatortypes=1.
 */
async function fetchAfasPicturesRowByItemcode(itemcode) {
  const connectorId = "Items_Pictures_app";
  const encoded = encodeURIComponent(String(itemcode));

  const tries = [
    `&filterfieldids=Itemcode&filtervalues=${encoded}`,
    `&filterfieldids=Itemcode&filtervalues=${encoded}&operatortypes=1`,
    `&filterfieldids=Code&filtervalues=${encoded}`,
    `&filterfieldids=Code&filtervalues=${encoded}&operatortypes=1`,
  ];

  for (const extraQuery of tries) {
    try {
      const data = await fetchAfasWithRetry(connectorId, { skip: 0, take: 1, extraQuery });
      const row = data?.rows?.[0] || null;
      if (row) return row;
    } catch {}
  }

  return null;
}

/* =======================
   R2 helpers
   ======================= */
async function headR2(key) {
  if (!r2) throw new Error("R2 not configured");
  try {
    await r2.send(new HeadObjectCommand({ Bucket: R2_BUCKET, Key: key }));
    return true;
  } catch {
    return false;
  }
}

async function uploadToR2({ key, body, contentType }) {
  if (!r2) throw new Error("R2 not configured");
  if (!R2_PUBLIC_BASE_URL) throw new Error("Missing R2_PUBLIC_BASE_URL");

  await r2.send(
    new PutObjectCommand({
      Bucket: R2_BUCKET,
      Key: key,
      Body: body,
      ContentType: contentType || "image/jpeg",
      CacheControl: "public, max-age=31536000, immutable",
    })
  );

  return publicUrlForKey(key);
}

async function uploadToR2WithRetry({ key, body, contentType }, retry = {}) {
  const { attempts = 5, baseDelayMs = 500, maxDelayMs = 8000 } = retry;
  let lastErr = null;

  for (let i = 0; i < attempts; i++) {
    try {
      return await uploadToR2({ key, body, contentType });
    } catch (e) {
      lastErr = e;
      if (i === attempts - 1) throw e;
      const delay = Math.min(maxDelayMs, baseDelayMs * Math.pow(2, i));
      await sleep(jitter(delay));
    }
  }
  throw lastErr || new Error("R2 upload failed");
}

/* =========================================================
   DB setup
   ========================================================= */
app.post("/db/setup-products", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS products (
        itemcode TEXT PRIMARY KEY,
        description_eng TEXT NULL,
        ean TEXT NULL,
        price NUMERIC NULL,
        available_stock NUMERIC NULL,
        ecommerce_available BOOLEAN NULL,

        outercarton TEXT NULL,
        innercarton TEXT NULL,
        unit TEXT NULL,

        raw JSONB NULL,
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      ALTER TABLE products
        ADD COLUMN IF NOT EXISTS outercarton TEXT NULL,
        ADD COLUMN IF NOT EXISTS innercarton TEXT NULL,
        ADD COLUMN IF NOT EXISTS unit TEXT NULL;
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_products_ean ON products(ean);`);
    await pool.query(
      `CREATE INDEX IF NOT EXISTS idx_products_ecom ON products(ecommerce_available) WHERE ecommerce_available = true;`
    );

    res.json({ ok: true, message: "products table ready" });
  } catch (err) {
    console.error("db/setup-products:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

app.post("/db/setup-afas-extra", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  try {
    // pictures
    await pool.query(`
      CREATE TABLE IF NOT EXISTS product_pictures (
        itemcode TEXT NOT NULL,
        picture_id TEXT NOT NULL,
        kind TEXT NOT NULL, -- MAIN, SFEER_1..5
        filename TEXT NULL,
        original_file TEXT NULL,
        location TEXT NULL,
        mime TEXT NULL,
        cdn_url TEXT NULL,
        needs_fetch BOOLEAN NOT NULL DEFAULT true,
        sort_order INT NOT NULL DEFAULT 0,
        raw JSONB NULL,
        updated_at TIMESTAMP DEFAULT NOW(),
        PRIMARY KEY (itemcode, picture_id)
      );
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_product_pictures_item_kind_sort
      ON product_pictures (itemcode, kind, sort_order, picture_id);
    `);

    // stock
    await pool.query(`
      CREATE TABLE IF NOT EXISTS product_stock (
        itemcode TEXT PRIMARY KEY,
        available_stock NUMERIC NULL,
        economic_stock NUMERIC NULL,
        on_order NUMERIC NULL,
        arrival_date DATE NULL,
        updated_at TIMESTAMP DEFAULT NOW(),
        raw JSONB NULL
      );
    `);

    // 1) verwijder dubbele itemcodes (houd nieuwste)
await pool.query(`
  WITH ranked AS (
    SELECT
      ctid,
      itemcode,
      updated_at,
      ROW_NUMBER() OVER (PARTITION BY itemcode ORDER BY updated_at DESC) AS rn
    FROM product_stock
  )
  DELETE FROM product_stock ps
  USING ranked r
  WHERE ps.ctid = r.ctid
    AND r.rn > 1;
`);

// 2) voeg UNIQUE constraint toe op itemcode (als die nog niet bestaat)
await pool.query(`
  DO $$
  BEGIN
    IF NOT EXISTS (
      SELECT 1
      FROM pg_constraint
      WHERE conname = 'product_stock_itemcode_unique'
    ) THEN
      ALTER TABLE product_stock
      ADD CONSTRAINT product_stock_itemcode_unique UNIQUE (itemcode);
    END IF;
  END $$;
`);


    // in case table existed with missing columns (this prevents your "column does not exist" issue)
    await pool.query(`
      ALTER TABLE product_stock
        ADD COLUMN IF NOT EXISTS economic_stock NUMERIC NULL,
        ADD COLUMN IF NOT EXISTS on_order NUMERIC NULL,
        ADD COLUMN IF NOT EXISTS arrival_date DATE NULL;
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_product_stock_updated_at
      ON product_stock(updated_at);
    `);

    res.json({ ok: true, message: "product_pictures + product_stock ready" });
  } catch (err) {
    console.error("db/setup-afas-extra:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =========================================================
   One-time cleanup: remove duplicates per (itemcode, kind) for SFEER
   ========================================================= */
app.post("/db/cleanup-sfeer-duplicates", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  try {
    const before = await pool.query(`
      SELECT COUNT(*)::int AS total
      FROM product_pictures
      WHERE kind LIKE 'SFEER_%'
    `);

    await pool.query(`
      WITH ranked AS (
        SELECT
          ctid,
          itemcode,
          kind,
          cdn_url,
          updated_at,
          ROW_NUMBER() OVER (
            PARTITION BY itemcode, kind
            ORDER BY (cdn_url IS NOT NULL) DESC, updated_at DESC
          ) AS rn
        FROM product_pictures
        WHERE kind LIKE 'SFEER_%'
      )
      DELETE FROM product_pictures p
      USING ranked r
      WHERE p.ctid = r.ctid
        AND r.rn > 1;
    `);

    const after = await pool.query(`
      SELECT COUNT(*)::int AS total
      FROM product_pictures
      WHERE kind LIKE 'SFEER_%'
    `);

    res.json({ ok: true, before: before.rows[0].total, after: after.rows[0].total });
  } catch (err) {
    console.error("db/cleanup-sfeer-duplicates:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =========================================================
   Health
   ========================================================= */
app.get("/health", (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

/* =========================================================
   Sync products (Items_Core)
   ========================================================= */
app.post("/sync/products", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const connectorId = req.query.connectorId || "Items_Core";
  const take = Number(req.query.take || process.env.AFAS_TAKE_DEFAULT || 100);

  let upserted = 0;

  try {
    let skip = 0;
    while (true) {
      const data = await fetchAfasWithRetry(connectorId, { skip, take });
      const rows = data?.rows || [];
      if (!rows.length) break;

      for (const r of rows) {
        const itemcode = r.Itemcode ?? r.itemcode ?? r.Code ?? r.code ?? null;
        if (!itemcode) continue;

        const ecommerce_available = parseBool(
          r["E-commerce_beschikbaar"] ?? r.Ecommerce ?? r.ecommerce_available
        );

        await pool.query(
          `
          INSERT INTO products (
            itemcode, description_eng, ean, price, available_stock,
            ecommerce_available,
            outercarton, innercarton, unit,
            raw, updated_at
          )
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
          ON CONFLICT (itemcode) DO UPDATE SET
            description_eng = EXCLUDED.description_eng,
            ean = EXCLUDED.ean,
            price = EXCLUDED.price,
            available_stock = EXCLUDED.available_stock,
            ecommerce_available = EXCLUDED.ecommerce_available,
            outercarton = EXCLUDED.outercarton,
            innercarton = EXCLUDED.innercarton,
            unit = EXCLUDED.unit,
            raw = EXCLUDED.raw,
            updated_at = NOW()
          `,
          [
            String(itemcode),
            r.OMSCHRIJVING_ENG ?? r.DescriptionENG ?? null,
            r["EAN_product__Opgeschoonde_barcode_"] ?? r.EAN ?? r.ean ?? null,
            r.Prijs ?? r.Price ?? null,
            r.Beschikbare_voorraad ?? r.AvailableStock ?? null,
            ecommerce_available,
            r.OUTERCARTON ?? r.outercarton ?? null,
            r.INNERCARTON ?? r.innercarton ?? null,
            r.UNIT ?? r.unit ?? null,
            r,
          ]
        );

        upserted += 1;
      }

      skip += rows.length;
      if (rows.length < take) break;
    }

    res.json({ ok: true, connectorId, upserted });
  } catch (err) {
    console.error("sync/products:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =========================================================
   Sync stock (Items_stock_app)
   AFAS fields (from your screenshot):
   - Beschik_vrrd
   - In_bestelling
   - Aankomst_datum
   - Eco_vrrd
   ========================================================= */
app.post("/sync/stock", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const connectorId = req.query.connectorId || "Items_stock_app";
  const take = Number(req.query.take || process.env.AFAS_TAKE_DEFAULT || 200);

  let upserted = 0;
  let skippedNoItemcode = 0;

  try {
    let skip = 0;
    while (true) {
      const data = await fetchAfasWithRetry(connectorId, { skip, take });
      const rows = data?.rows || [];
      if (!rows.length) break;

      for (const r of rows) {
        const itemcode = r.Itemcode ?? r.itemcode ?? r.Itemcode ?? r.Code ?? r.code ?? null;
        if (!itemcode) {
          skippedNoItemcode += 1;
          continue;
        }

        await pool.query(
          `
          INSERT INTO product_stock (
            itemcode,
            available_stock,
            economic_stock,
            on_order,
            arrival_date,
            raw,
            updated_at
          )
          VALUES ($1,$2,$3,$4,$5,$6,NOW())
          ON CONFLICT (itemcode) DO UPDATE SET
            available_stock = EXCLUDED.available_stock,
            economic_stock  = EXCLUDED.economic_stock,
            on_order        = EXCLUDED.on_order,
            arrival_date    = EXCLUDED.arrival_date,
            raw             = EXCLUDED.raw,
            updated_at      = NOW()
          `,
          [
            String(itemcode),
            toNumberOrNull(r.Beschik_vrrd ?? r.Beschik_vrrd ?? null),
            toNumberOrNull(r.Eco_vrrd ?? null),
            toNumberOrNull(r.In_bestelling ?? null),
            toDateOrNull(r.Aankomst_datum ?? null),
            r,
          ]
        );

        upserted += 1;
      }

      skip += rows.length;
      if (rows.length < take) break;
    }

    res.json({ ok: true, connectorId, upserted, skippedNoItemcode });
  } catch (err) {
    console.error("sync/stock:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =========================================================
   STEP 1 — MAIN manifest (unchanged)
   ========================================================= */
async function upsertMainPictureManifest(itemcode, afasRow) {
  const filename = afasRow?.Bestandsnaam_MAIN ?? null;

  const original_file =
    afasRow?.Origineel_bestand_MAIN ??
    afasRow?.Originele_Afbeelding_MAIN ??
    afasRow?.OrigineleAfbeelding_MAIN ??
    afasRow?.["Originele Afbeelding_MAIN"] ??
    null;

  const location =
    afasRow?.Bestandslocatie_MAIN ??
    afasRow?.Locatie_MAIN ??
    afasRow?.LocatieMAIN ??
    afasRow?.["Locatie_MAIN"] ??
    null;

  if (!filename && !original_file && !location) {
    return { ok: false, reason: "no_main_fields" };
  }

  const mime = guessMimeFromFilename(filename);
  const stableId = String(original_file || location || `${itemcode}-MAIN`);
  const picture_id = sha1(stableId);

  await pool.query(
    `
    INSERT INTO product_pictures (
      itemcode, picture_id, kind,
      filename, original_file, location, mime,
      cdn_url, needs_fetch, sort_order, raw, updated_at
    )
    VALUES ($1,$2,'MAIN',$3,$4,$5,$6,NULL,true,0,$7,NOW())
    ON CONFLICT (itemcode, picture_id) DO UPDATE SET
      kind='MAIN',
      filename=EXCLUDED.filename,
      original_file=EXCLUDED.original_file,
      location=EXCLUDED.location,
      mime=EXCLUDED.mime,
      raw=EXCLUDED.raw,
      updated_at=NOW(),
      needs_fetch =
        (product_pictures.original_file IS DISTINCT FROM EXCLUDED.original_file)
        OR (product_pictures.location IS DISTINCT FROM EXCLUDED.location)
        OR (product_pictures.filename IS DISTINCT FROM EXCLUDED.filename)
        OR (product_pictures.mime IS DISTINCT FROM EXCLUDED.mime)
        OR (product_pictures.cdn_url IS NULL)
    `,
    [
      String(itemcode),
      String(picture_id),
      filename ? String(filename) : null,
      original_file ? String(original_file) : null,
      location ? String(location) : null,
      mime,
      afasRow,
    ]
  );

  return { ok: true, picture_id };
}

app.post("/sync/pictures-main-from-products", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const limit = Math.min(2000, Math.max(1, Number(req.query.limit || 200)));
  const offset = Math.max(0, Number(req.query.offset || 0));

  try {
    const pr = await pool.query(
      `
      SELECT itemcode
      FROM products
      WHERE ecommerce_available = true
      ORDER BY itemcode
      LIMIT $1 OFFSET $2
      `,
      [limit, offset]
    );

    let processed = 0;
    let skippedA = 0;
    let foundAfas = 0;
    let upserted = 0;
    let missingInAfas = 0;
    let noMainFields = 0;

    for (const row of pr.rows) {
      const itemcode = row.itemcode;
      if (!itemcode) continue;

      if (EXCLUDE_A_CODES && String(itemcode).startsWith("A")) {
        skippedA += 1;
        continue;
      }

      processed += 1;

      const afasRow = await fetchAfasPicturesRowByItemcode(itemcode);
      if (!afasRow) {
        missingInAfas += 1;
        continue;
      }

      foundAfas += 1;

      const r = await upsertMainPictureManifest(itemcode, afasRow);
      if (r.ok) upserted += 1;
      else noMainFields += 1;
    }

    res.json({
      ok: true,
      limit,
      offset,
      processed,
      skippedA,
      foundAfas,
      upserted,
      missingInAfas,
      noMainFields,
    });
  } catch (err) {
    console.error("sync/pictures-main-from-products:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =========================================================
   STEP 1B — SFEER manifest (slot-stable, no duplicates)
   ========================================================= */
async function upsertSfeerSlotManifest(itemcode, kind, sort_order, afasRow) {
  const b64Field = KIND_TO_AFAS_B64_FIELD[kind];
  if (!b64Field) return { ok: false, reason: "unknown_kind" };

  const b64 = normalizeBase64(afasRow?.[b64Field]);
  if (!b64) return { ok: false, reason: "no_b64" };

  const content_hash = sha1(b64);
  const picture_id = sha1(`${itemcode}:${kind}`); // SLOT-STABLE

  const rawMeta = {
    source_field: b64Field,
    content_hash,
  };

  await pool.query(
    `
    INSERT INTO product_pictures (
      itemcode, picture_id, kind,
      filename, original_file, location, mime,
      cdn_url, needs_fetch, sort_order, raw, updated_at
    )
    VALUES ($1,$2,$3,NULL,NULL,NULL,NULL,NULL,true,$4,$5,NOW())
    ON CONFLICT (itemcode, picture_id) DO UPDATE SET
      kind = EXCLUDED.kind,
      sort_order = EXCLUDED.sort_order,
      raw = EXCLUDED.raw,
      updated_at = NOW(),
      needs_fetch =
        (product_pictures.cdn_url IS NULL)
        OR (product_pictures.raw->>'content_hash' IS DISTINCT FROM EXCLUDED.raw->>'content_hash')
        OR (product_pictures.raw->>'uploaded_hash' IS DISTINCT FROM EXCLUDED.raw->>'content_hash')
    `,
    [String(itemcode), String(picture_id), String(kind), Number(sort_order) || 0, rawMeta]
  );

  return { ok: true, picture_id, content_hash };
}

async function handleSfeerManifest(req, res) {
  if (!requireSetupKey(req, res)) return;

  const limit = Math.min(2000, Math.max(1, Number(req.query.limit || 200)));
  const offset = Math.max(0, Number(req.query.offset || 0));

  try {
    const pr = await pool.query(
      `
      SELECT itemcode
      FROM products
      WHERE ecommerce_available = true
      ORDER BY itemcode
      LIMIT $1 OFFSET $2
      `,
      [limit, offset]
    );

    let processed = 0;
    let skippedA = 0;
    let missingInAfas = 0;
    let foundAfas = 0;

    let slotsWithB64 = 0;
    let slotsNoB64 = 0;
    let upserts = 0;

    for (const row of pr.rows) {
      const itemcode = row.itemcode;
      if (!itemcode) continue;

      if (EXCLUDE_A_CODES && String(itemcode).startsWith("A")) {
        skippedA += 1;
        continue;
      }

      processed += 1;

      const afasRow = await fetchAfasPicturesRowByItemcode(itemcode);
      if (!afasRow) {
        missingInAfas += 1;
        continue;
      }

      foundAfas += 1;

      const slots = [
        { kind: "SFEER_1", sort: 1 },
        { kind: "SFEER_2", sort: 2 },
        { kind: "SFEER_3", sort: 3 },
        { kind: "SFEER_4", sort: 4 },
        { kind: "SFEER_5", sort: 5 },
      ];

      for (const s of slots) {
        const b64Field = KIND_TO_AFAS_B64_FIELD[s.kind];
        const b64 = normalizeBase64(afasRow?.[b64Field]);
        if (!b64) {
          slotsNoB64 += 1;
          continue;
        }
        slotsWithB64 += 1;

        const r = await upsertSfeerSlotManifest(itemcode, s.kind, s.sort, afasRow);
        if (r.ok) upserts += 1;
      }
    }

    res.json({
      ok: true,
      limit,
      offset,
      processed,
      skippedA,
      foundAfas,
      missingInAfas,
      sfeerSlotsWithB64: slotsWithB64,
      sfeerSlotsNoB64: slotsNoB64,
      sfeerUpserts: upserts,
    });
  } catch (err) {
    console.error("sync/pictures-sfeer-manifest:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
}

app.post("/sync/pictures-sfeer-manifest", handleSfeerManifest);
app.get("/sync/pictures-sfeer-manifest", handleSfeerManifest);

/* =========================================================
   STEP 2 — Upload job (base64 from Items_Pictures_app -> R2)
   ========================================================= */
function parseKindsParam(kindsParam) {
  if (!kindsParam) return ["MAIN"];
  return String(kindsParam)
    .split(",")
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);
}

app.post("/sync/upload-pictures-to-r2", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const limit = Math.min(500, Math.max(1, Number(req.query.limit || 50)));
  const concurrency = Math.min(4, Math.max(1, Number(req.query.concurrency || 1)));
  const kinds = parseKindsParam(req.query.kinds || "MAIN");

  try {
    if (!r2) throw new Error("R2 not configured");
    if (!R2_PUBLIC_BASE_URL) throw new Error("Missing R2_PUBLIC_BASE_URL");

    const { rows } = await pool.query(
      `
      SELECT itemcode, picture_id, kind, filename, mime, raw, cdn_url
      FROM product_pictures
      WHERE needs_fetch = true
        AND kind = ANY($1)
      ORDER BY updated_at ASC
      LIMIT $2
      `,
      [kinds, limit]
    );

    let uploaded = 0;
    let skippedNoAfas = 0;
    let skippedNoB64 = 0;
    let usedExisting = 0;
    let failed = 0;

    await runWithConcurrency(rows, concurrency, async (pic) => {
      const itemcode = pic.itemcode;
      const kind = String(pic.kind || "").toUpperCase();
      const b64Field = KIND_TO_AFAS_B64_FIELD[kind];

      try {
        if (!b64Field) {
          await pool.query(
            `UPDATE product_pictures SET needs_fetch=false, updated_at=NOW() WHERE itemcode=$1 AND picture_id=$2`,
            [itemcode, pic.picture_id]
          );
          return;
        }

        const afasRow = await fetchAfasPicturesRowByItemcode(itemcode);
        if (!afasRow) {
          skippedNoAfas += 1;
          return;
        }

        const b64 = normalizeBase64(afasRow[b64Field]);
        if (!b64) {
          skippedNoB64 += 1;
          await pool.query(
            `UPDATE product_pictures SET needs_fetch=false, cdn_url=NULL, updated_at=NOW() WHERE itemcode=$1 AND picture_id=$2`,
            [itemcode, pic.picture_id]
          );
          return;
        }

        const content_hash = sha1(b64);
        const uploaded_hash = pic?.raw?.uploaded_hash ?? null;

        const mime =
          pic.mime || guessMimeFromFilename(pic.filename) || guessMimeFromBase64(b64) || "image/jpeg";
        const ext = extFromMime(mime);
        const buf = Buffer.from(b64, "base64");

        const key = `products/${itemcode}/${kind.toLowerCase()}_${pic.picture_id}.${ext}`;

        let cdnUrl = null;

        if (uploaded_hash && uploaded_hash === content_hash) {
          const exists = await headR2(key);
          if (exists) {
            cdnUrl = publicUrlForKey(key);
            usedExisting += 1;
          }
        }

        if (!cdnUrl) {
          cdnUrl = await uploadToR2WithRetry({ key, body: buf, contentType: mime });
          uploaded += 1;
        }

        const newRaw = {
          ...(pic.raw || {}),
          uploaded_hash: content_hash,
          content_hash,
          source_field: b64Field,
        };

        await pool.query(
          `
          UPDATE product_pictures
          SET cdn_url=$1, needs_fetch=false, raw=$4, updated_at=NOW()
          WHERE itemcode=$2 AND picture_id=$3
          `,
          [cdnUrl, itemcode, pic.picture_id, newRaw]
        );
      } catch (e) {
        failed += 1;
        console.error("upload failed:", { itemcode, kind, err: e?.message || String(e) });
      }
    });

    res.json({
      ok: true,
      kinds,
      limit,
      concurrency,
      queued: rows.length,
      uploaded,
      usedExisting,
      skippedNoAfas,
      skippedNoB64,
      failed,
    });
  } catch (err) {
    console.error("sync/upload-pictures-to-r2:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =========================================================
   API
   ========================================================= */

// products list (kept as-is, stock can be added later)
app.get("/products", async (req, res) => {
  const limit = Math.min(200, Math.max(1, Number(req.query.limit || 50)));
  const offset = Math.max(0, Number(req.query.offset || 0));

  try {
    const q = `
      SELECT
        p.itemcode,
        p.description_eng,
        p.ean,
        p.price,
        p.available_stock,
        p.outercarton,
        p.innercarton,
        p.unit,
        COALESCE((
          SELECT pp.cdn_url
          FROM product_pictures pp
          WHERE pp.itemcode = p.itemcode
            AND pp.cdn_url IS NOT NULL
          ORDER BY
            CASE WHEN pp.kind='MAIN' THEN 0 ELSE 1 END,
            COALESCE(pp.sort_order, 999),
            pp.picture_id
          LIMIT 1
        ), '') AS image_url
      FROM products p
      WHERE p.ecommerce_available = true
      ORDER BY p.itemcode
      LIMIT $1 OFFSET $2
    `;
    const { rows } = await pool.query(q, [limit, offset]);
    res.json({ ok: true, limit, offset, count: rows.length, data: rows });
  } catch (err) {
    console.error("GET /products:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =========================================================
   Debug
   ========================================================= */

app.get("/debug/pictures/sfeer-counts", async (req, res) => {
  try {
    const a = await pool.query(`
      SELECT
        COUNT(*)::int AS sfeer_records_total,
        COUNT(*) FILTER (WHERE cdn_url IS NOT NULL)::int AS sfeer_with_cdn,
        COUNT(*) FILTER (WHERE cdn_url IS NULL)::int AS sfeer_missing_cdn,
        COUNT(DISTINCT (itemcode, kind))::int AS sfeer_unique_slots
      FROM product_pictures
      WHERE kind LIKE 'SFEER_%'
    `);

    const b = await pool.query(`
      SELECT COUNT(DISTINCT p.itemcode)::int AS ecommerce_products_with_sfeer_cdn
      FROM products p
      JOIN product_pictures pp
        ON pp.itemcode = p.itemcode
       AND pp.kind LIKE 'SFEER_%'
       AND pp.cdn_url IS NOT NULL
      WHERE p.ecommerce_available = true
    `);

    res.json({ ok: true, ...a.rows[0], ...b.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

// GET /debug/stock-schema?key=...
app.get("/debug/stock-schema", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  try {
    const r = await pool.query(`
      SELECT column_name, data_type
      FROM information_schema.columns
      WHERE table_name = 'product_stock'
      ORDER BY ordinal_position
    `);
    res.json({ ok: true, columns: r.rows });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =========================================================
   Error handler
   ========================================================= */
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ ok: false, error: err?.message || String(err) });
});

/* =========================================================
   Start + graceful shutdown
   ========================================================= */
const server = app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
});

async function shutdown(signal) {
  console.log(`Received ${signal}. Shutting down...`);
  server.close(async () => {
    try {
      await pool.end();
    } catch (e) {
      console.error("Error closing pool:", e);
    }
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
