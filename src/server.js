// src/server.js
/* eslint-disable no-console */

"use strict";

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");

// Node 18+ heeft fetch global. Fallback voor oudere node:
const fetchFn =
  typeof fetch !== "undefined"
    ? fetch
    : (...args) => import("node-fetch").then(({ default: f }) => f(...args));

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================================================
   CONFIG / ENV (names only)
   =========================================================
   DATABASE_URL
   SETUP_KEY
   JWT_SECRET

   AFAS_ENV
   AFAS_TOKEN_DATA
   (optioneel) AFAS_TAKE_DEFAULT

   R2_BUCKET
   R2_ENDPOINT
   R2_PUBLIC_BASE_URL
   R2_ACCESS_KEY_ID
   R2_SECRET_ACCESS_KEY
   ========================================================= */

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
      // Expo op LAN (bijv. http://192.168.x.x:8081)
      if (/^http:\/\/192\.168\.\d{1,3}\.\d{1,3}:8081$/.test(origin)) return cb(null, true);
      return cb(new Error(`CORS blocked for origin: ${origin}`));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);
app.options("*", cors());

// JSON payload laag houden (geen base64 in API)
app.use(express.json({ limit: "2mb" }));

/* =======================
   DATABASE
   ======================= */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/* =======================
   R2 (S3-compatible)
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

async function uploadToR2({ key, body, contentType }) {
  if (!r2) throw new Error("R2 not configured (missing env vars)");
  if (!R2_PUBLIC_BASE_URL) throw new Error("Missing R2_PUBLIC_BASE_URL");

  await r2.send(
    new PutObjectCommand({
      Bucket: R2_BUCKET,
      Key: key,
      Body: body,
      ContentType: contentType || "image/jpeg",
      // (optioneel) cache headers, afhankelijk van je CDN setup:
      // CacheControl: "public, max-age=31536000, immutable",
    })
  );

  return `${R2_PUBLIC_BASE_URL.replace(/\/$/, "")}/${key}`;
}

/* =======================
   SMALL HELPERS
   ======================= */
function requireSetupKey(req, res) {
  const key = req.query.key;
  if (!key || key !== process.env.SETUP_KEY) {
    res.status(401).json({ ok: false, error: "Invalid setup key" });
    return false;
  }
  return true;
}

function sha1(input) {
  return crypto.createHash("sha1").update(String(input), "utf8").digest("hex");
}

function parseBool(v) {
  if (typeof v === "boolean") return v;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (s === "ja" || s === "yes" || s === "true" || s === "1") return true;
    if (s === "nee" || s === "no" || s === "false" || s === "0") return false;
  }
  return Boolean(v);
}

function getItemcodeFromRow(r) {
  // Cruciaal: jouw AFAS levert soms alleen Code i.p.v. Itemcode
  return r?.Itemcode ?? r?.itemcode ?? r?.Code ?? r?.code ?? null;
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

/* =======================
   BASE64 HELPERS
   ======================= */
function normalizeBase64(v) {
  if (!v) return null;
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (!s) return null;
  const idx = s.indexOf("base64,");
  if (idx >= 0) return s.slice(idx + "base64,".length).trim();
  return s;
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

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function jitter(ms, pct = 0.25) {
  const delta = ms * pct;
  return Math.max(0, Math.round(ms - delta + Math.random() * (2 * delta)));
}

/* =======================
   AUTH MIDDLEWARE
   ======================= */
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "No token provided" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

/* =======================
   AFAS HELPERS (robust)
   ======================= */
function buildAfasAuthHeaderFromData(dataToken) {
  const xmlToken = `<token><version>1</version><data>${dataToken}</data></token>`;
  const b64 = Buffer.from(xmlToken, "utf8").toString("base64");
  return `AfasToken ${b64}`;
}

function isRetryableAfasStatus(status) {
  return status === 429 || status === 500 || status === 502 || status === 503 || status === 504;
}

async function fetchAfas(connectorId, { skip = 0, take = 100, extraQuery = "" } = {}) {
  const env = process.env.AFAS_ENV;
  const dataToken = process.env.AFAS_TOKEN_DATA;

  if (!env || !dataToken || !connectorId) {
    throw new Error("Missing AFAS env vars (AFAS_ENV / AFAS_TOKEN_DATA / connectorId)");
  }

  const baseUrl = `https://${env}.rest.afas.online/ProfitRestServices/connectors/${connectorId}`;
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

  try {
    return JSON.parse(text);
  } catch {
    const err = new Error(`AFAS invalid JSON: ${text}`);
    err.url = url;
    throw err;
  }
}

async function fetchAfasWithRetry(connectorId, opts = {}, retry = {}) {
  const {
    attempts = 6,
    baseDelayMs = 500,
    maxDelayMs = 8000,
  } = retry;

  let lastErr = null;

  for (let i = 0; i < attempts; i++) {
    try {
      return await fetchAfas(connectorId, opts);
    } catch (e) {
      lastErr = e;
      const status = e?.status;
      const retryable = status ? isRetryableAfasStatus(status) : true; // netwerk fouten => true
      if (!retryable || i === attempts - 1) throw e;

      const delay = Math.min(maxDelayMs, baseDelayMs * Math.pow(2, i));
      await sleep(jitter(delay));
    }
  }

  throw lastErr || new Error("AFAS fetch failed");
}

async function forEachAfasRow(connectorId, { take = 200, extraQuery = "" } = {}, onRow) {
  let skip = 0;
  let pages = 0;
  let totalRows = 0;

  while (true) {
    const data = await fetchAfasWithRetry(connectorId, { skip, take, extraQuery });
    const rows = data?.rows || [];
    if (rows.length === 0) break;

    for (const r of rows) {
      totalRows += 1;
      await onRow(r);
    }

    pages += 1;
    skip += rows.length;
    if (rows.length < take) break;
  }

  return { pages, totalRows };
}

/**
 * Stap 2: AFAS row ophalen per product.
 * Proberen:
 *  1) filter op Itemcode
 *  2) filter op Code
 *  met en zonder operatortypes=1
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
      const data = await fetchAfasWithRetry(connectorId, {
        skip: 0,
        take: 1,
        extraQuery,
      });
      const row = data?.rows?.[0];
      if (row) return row;
    } catch (e) {
      // volgende poging
    }
  }

  return null;
}

/* =======================
   HEALTH
   ======================= */
app.get("/health", (req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});

/* =======================
   DB SETUP
   ======================= */
app.post("/db/setup-products", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

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

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_products_ean ON products(ean);`);
    res.json({ ok: true, message: "products table ready" });
  } catch (err) {
    console.error("setup-products:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

app.post("/db/setup-afas-extra", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS product_categories (
        itemcode TEXT NOT NULL,
        category_code TEXT NOT NULL,
        category_name TEXT NULL,
        raw JSONB NULL,
        updated_at TIMESTAMP DEFAULT NOW(),
        PRIMARY KEY (itemcode, category_code)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS product_descriptions (
        itemcode TEXT NOT NULL,
        lang TEXT NOT NULL,
        description TEXT NULL,
        raw JSONB NULL,
        updated_at TIMESTAMP DEFAULT NOW(),
        PRIMARY KEY (itemcode, lang)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS product_pictures (
        itemcode TEXT NOT NULL,
        picture_id TEXT NOT NULL,
        kind TEXT NULL,

        cdn_url TEXT NULL,
        mime TEXT NULL,
        filename TEXT NULL,
        original_file TEXT NULL,
        location TEXT NULL,

        needs_fetch BOOLEAN NOT NULL DEFAULT true,
        sort_order INT NULL,
        raw JSONB NULL,
        updated_at TIMESTAMP DEFAULT NOW(),
        PRIMARY KEY (itemcode, picture_id)
      );
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_product_pictures_item_kind_sort
      ON product_pictures (itemcode, kind, sort_order, picture_id);
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS product_stock (
        itemcode TEXT NOT NULL,
        warehouse TEXT NOT NULL,
        available_stock NUMERIC NULL,
        raw JSONB NULL,
        updated_at TIMESTAMP DEFAULT NOW(),
        PRIMARY KEY (itemcode, warehouse)
      );
    `);

    res.json({ ok: true, message: "extra AFAS tables ready" });
  } catch (err) {
    console.error("setup-afas-extra:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

app.post("/db/migrate-pictures-v5", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  try {
    await pool.query(`
      ALTER TABLE product_pictures
        ADD COLUMN IF NOT EXISTS cdn_url TEXT NULL,
        ADD COLUMN IF NOT EXISTS needs_fetch BOOLEAN NOT NULL DEFAULT true,
        ADD COLUMN IF NOT EXISTS mime TEXT NULL,
        ADD COLUMN IF NOT EXISTS filename TEXT NULL,
        ADD COLUMN IF NOT EXISTS original_file TEXT NULL,
        ADD COLUMN IF NOT EXISTS location TEXT NULL;
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_product_pictures_item_kind_sort
      ON product_pictures (itemcode, kind, sort_order, picture_id);
    `);

    res.json({ ok: true, message: "product_pictures migrated to v5" });
  } catch (err) {
    console.error("migrate-pictures-v5:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =======================
   SYNC: PRODUCTS
   ======================= */
app.post("/sync/products", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const connectorId = req.query.connectorId || process.env.AFAS_CONNECTOR || "Items_Core";
  const take = Number(req.query.take || process.env.AFAS_TAKE_DEFAULT || 100);

  let totalUpserted = 0;

  try {
    const { pages, totalRows } = await forEachAfasRow(connectorId, { take }, async (r) => {
      const itemcode = getItemcodeFromRow(r);
      if (!itemcode) return;

      const ecomBool = parseBool(r["E-commerce_beschikbaar"]);

      await pool.query(
        `
        INSERT INTO products (
          itemcode, type_item, description_eng, unit, price,
          outercarton, innercarton, ean, available_stock,
          ecommerce_available, raw, updated_at
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
          String(itemcode),
          r.Type_item ?? null,
          r.OMSCHRIJVING_ENG ?? null,
          r.UNIT ?? null,
          r.Prijs ?? null,
          r.OUTERCARTON ?? null,
          r.INNERCARTON ?? null,
          r["EAN_product__Opgeschoonde_barcode_"] ?? null,
          r.Beschikbare_voorraad ?? null,
          ecomBool,
          r,
        ]
      );

      totalUpserted += 1;
    });

    res.json({ ok: true, connectorId, pages, rowsFetched: totalRows, upserted: totalUpserted });
  } catch (err) {
    console.error("sync/products:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =======================
   SYNC: categories / descriptions / stock
   ======================= */
app.post("/sync/categories", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const connectorId = req.query.connectorId || "Items_Category_app";
  const take = Number(req.query.take || process.env.AFAS_TAKE_DEFAULT || 200);
  let upserted = 0;

  try {
    const { pages, totalRows } = await forEachAfasRow(connectorId, { take }, async (r) => {
      const itemcode = getItemcodeFromRow(r);
      if (!itemcode) return;

      const category_code = r.CategoryCode ?? r.Category ?? r.CategorieCode ?? r.Categorie ?? null;
      const category_name = r.CategoryName ?? r.CategorieNaam ?? r.Naam ?? null;
      const catCode = (category_code && String(category_code).trim()) || sha1(JSON.stringify(r));

      await pool.query(
        `
        INSERT INTO product_categories (itemcode, category_code, category_name, raw, updated_at)
        VALUES ($1,$2,$3,$4,NOW())
        ON CONFLICT (itemcode, category_code) DO UPDATE SET
          category_name = EXCLUDED.category_name,
          raw = EXCLUDED.raw,
          updated_at = NOW()
        `,
        [String(itemcode), String(catCode), category_name, r]
      );

      upserted += 1;
    });

    res.json({ ok: true, connectorId, pages, rowsFetched: totalRows, upserted });
  } catch (err) {
    console.error("sync/categories:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

app.post("/sync/descriptions", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const connectorId = req.query.connectorId || "Items_Descriptions_app";
  const take = Number(req.query.take || process.env.AFAS_TAKE_DEFAULT || 200);
  let upserted = 0;

  try {
    const { pages, totalRows } = await forEachAfasRow(connectorId, { take }, async (r) => {
      const itemcode = getItemcodeFromRow(r);
      if (!itemcode) return;

      const langRaw = r.Language ?? r.Taal ?? r.Lang ?? "NL";
      const lang = String(langRaw || "NL").toUpperCase().trim();
      const description = r.Description ?? r.Omschrijving ?? r.Tekst ?? r.Text ?? null;

      await pool.query(
        `
        INSERT INTO product_descriptions (itemcode, lang, description, raw, updated_at)
        VALUES ($1,$2,$3,$4,NOW())
        ON CONFLICT (itemcode, lang) DO UPDATE SET
          description = EXCLUDED.description,
          raw = EXCLUDED.raw,
          updated_at = NOW()
        `,
        [String(itemcode), lang, description, r]
      );

      upserted += 1;
    });

    res.json({ ok: true, connectorId, pages, rowsFetched: totalRows, upserted });
  } catch (err) {
    console.error("sync/descriptions:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

app.post("/sync/stock", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const connectorId = req.query.connectorId || "Items_stock_app";
  const take = Number(req.query.take || process.env.AFAS_TAKE_DEFAULT || 200);
  let upserted = 0;

  try {
    const { pages, totalRows } = await forEachAfasRow(connectorId, { take }, async (r) => {
      const itemcode = getItemcodeFromRow(r);
      if (!itemcode) return;

      const warehouseRaw = r.Warehouse ?? r.Magazijn ?? r.WarehouseCode ?? null;
      const warehouse = String(warehouseRaw || "DEFAULT").trim();
      const available_stock = r.Beschikbare_voorraad ?? r.AvailableStock ?? r.Stock ?? null;

      await pool.query(
        `
        INSERT INTO product_stock (itemcode, warehouse, available_stock, raw, updated_at)
        VALUES ($1,$2,$3,$4,NOW())
        ON CONFLICT (itemcode, warehouse) DO UPDATE SET
          available_stock = EXCLUDED.available_stock,
          raw = EXCLUDED.raw,
          updated_at = NOW()
        `,
        [String(itemcode), warehouse, available_stock, r]
      );

      upserted += 1;
    });

    res.json({ ok: true, connectorId, pages, rowsFetched: totalRows, upserted });
  } catch (err) {
    console.error("sync/stock:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =======================
   PICTURES: STAP 1 MANIFEST SYNC (MAIN + SFEER_1..5)
   ======================= */
app.post("/sync/pictures", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const connectorId = req.query.connectorId || "Items_Pictures_app";
  const take = Number(req.query.take || process.env.AFAS_TAKE_DEFAULT || 200);

  let rowsUpserted = 0;
  let picturesUpserted = 0;
  let rowsSkippedNoItemcode = 0;

  const slots = [
    { kind: "MAIN", sort: 0, filenameKey: "Bestandsnaam_MAIN", originalKey: "Origineel_bestand_MAIN", locationKey: "Bestandslocatie_MAIN" },
    { kind: "SFEER_1", sort: 1, filenameKey: "Bestandsnaam_SFEER_1", originalKey: "Origineel_bestand_SFEER_1", locationKey: "Bestandslocatie_SFEER_1" },
    { kind: "SFEER_2", sort: 2, filenameKey: "Bestandsnaam_SFEER_2", originalKey: "Origineel_bestand_SFEER_2", locationKey: "Bestandslocatie_SFEER_2" },
    { kind: "SFEER_3", sort: 3, filenameKey: "Bestandsnaam_SFEER_3", originalKey: "Origineel_bestand_SFEER_3", locationKey: "Bestandslocatie_SFEER_3" },
    { kind: "SFEER_4", sort: 4, filenameKey: "Bestandsnaam_SFEER_4", originalKey: "Origineel_bestand_SFEER_4", locationKey: "Bestandslocatie_SFEER_4" },
    { kind: "SFEER_5", sort: 5, filenameKey: "Bestandsnaam_SFEER_5", originalKey: "Origineel_bestand_SFEER_5", locationKey: "Bestandslocatie_SFEER_5" },
  ];

  try {
    const { pages, totalRows } = await forEachAfasRow(connectorId, { take }, async (r) => {
      const itemcode = getItemcodeFromRow(r);
      if (!itemcode) {
        rowsSkippedNoItemcode += 1;
        return;
      }

      let anyForRow = false;

      for (const s of slots) {
        const filename = r?.[s.filenameKey] ?? null;
        const original_file = r?.[s.originalKey] ?? null;
        const location = r?.[s.locationKey] ?? null;

        if (!filename && !original_file && !location) continue;

        const mime = guessMimeFromFilename(filename);
        const stableId = String(original_file || location || `${itemcode}-${s.kind}`);
        const picture_id = sha1(stableId);

        await pool.query(
          `
          INSERT INTO product_pictures (
            itemcode, picture_id, kind,
            cdn_url, mime, filename, original_file, location,
            needs_fetch, sort_order, raw, updated_at
          )
          VALUES ($1,$2,$3, NULL,$4,$5,$6,$7, true,$8,$9,NOW())
          ON CONFLICT (itemcode, picture_id) DO UPDATE SET
            kind = EXCLUDED.kind,
            mime = EXCLUDED.mime,
            filename = EXCLUDED.filename,
            original_file = EXCLUDED.original_file,
            location = EXCLUDED.location,
            sort_order = EXCLUDED.sort_order,
            raw = EXCLUDED.raw,
            updated_at = NOW(),
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
            s.kind,
            mime,
            filename ? String(filename) : null,
            original_file ? String(original_file) : null,
            location ? String(location) : null,
            s.sort,
            r,
          ]
        );

        picturesUpserted += 1;
        anyForRow = true;
      }

      if (anyForRow) rowsUpserted += 1;
    });

    res.json({
      ok: true,
      connectorId,
      pages,
      rowsFetched: totalRows,
      upsertedRows: rowsUpserted,
      picturesUpserted,
      rowsSkippedNoItemcode,
      note: "manifest-only (no base64). Use upload job to push to R2.",
    });
  } catch (err) {
    console.error("sync/pictures:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =======================
   STAP 2 UPLOAD JOB: AFAS base64 -> R2
   ======================= */
const KIND_TO_AFAS_B64_FIELD = {
  MAIN: "Afbeelding",
  SFEER_1: "Afbeelding_1",
  SFEER_2: "Afbeelding_2",
  SFEER_3: "Afbeelding_3",
  SFEER_4: "Afbeelding_4",
  SFEER_5: "Afbeelding_5",
};

function parseKindsParam(kindsParam) {
  if (!kindsParam) return ["MAIN"];
  return String(kindsParam)
    .split(",")
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);
}

// simpele concurrency helper (geen extra deps)
async function runWithConcurrency(items, concurrency, handler) {
  const results = [];
  let idx = 0;

  async function worker() {
    while (true) {
      const myIdx = idx++;
      if (myIdx >= items.length) break;
      results[myIdx] = await handler(items[myIdx], myIdx);
    }
  }

  const workers = [];
  const n = Math.max(1, Number(concurrency) || 1);
  for (let i = 0; i < n; i++) workers.push(worker());
  await Promise.all(workers);
  return results;
}

async function uploadToR2WithRetry({ key, body, contentType }, retry = {}) {
  const {
    attempts = 5,
    baseDelayMs = 500,
    maxDelayMs = 8000,
  } = retry;

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

// POST /sync/upload-pictures-to-r2?key=...&limit=50&kinds=MAIN,SFEER_1&concurrency=2
app.post("/sync/upload-pictures-to-r2", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const limit = Math.min(500, Math.max(1, Number(req.query.limit || 50)));
  const concurrency = Math.min(4, Math.max(1, Number(req.query.concurrency || 1))); // laag houden ivm Render/AFAS
  const kinds = parseKindsParam(req.query.kinds || "MAIN,SFEER_1,SFEER_2,SFEER_3,SFEER_4,SFEER_5");

  try {
    if (!r2) throw new Error("R2 is not configured (missing env vars)");
    if (!R2_PUBLIC_BASE_URL) throw new Error("Missing R2_PUBLIC_BASE_URL");

    const { rows } = await pool.query(
      `
      SELECT itemcode, picture_id, kind, filename
      FROM product_pictures
      WHERE needs_fetch = true
        AND kind = ANY($1)
      ORDER BY updated_at ASC
      LIMIT $2
      `,
      [kinds, limit]
    );

    let processed = 0;
    let skippedNoAfasRow = 0;
    let skippedNoB64 = 0;
    let failed = 0;

    await runWithConcurrency(rows, concurrency, async (pic) => {
      const itemcode = pic.itemcode;
      const kind = String(pic.kind || "").toUpperCase();
      const b64Field = KIND_TO_AFAS_B64_FIELD[kind];

      try {
        if (!b64Field) {
          await pool.query(
            `UPDATE product_pictures SET needs_fetch = false, updated_at = NOW() WHERE itemcode=$1 AND picture_id=$2`,
            [itemcode, pic.picture_id]
          );
          return;
        }

        const afasRow = await fetchAfasPicturesRowByItemcode(itemcode);
        if (!afasRow) {
          skippedNoAfasRow += 1;
          return;
        }

        const b64 = normalizeBase64(afasRow[b64Field]);
        if (!b64) {
          skippedNoB64 += 1;
          await pool.query(
            `UPDATE product_pictures SET cdn_url = NULL, needs_fetch = false, updated_at = NOW() WHERE itemcode=$1 AND picture_id=$2`,
            [itemcode, pic.picture_id]
          );
          return;
        }

        const mimeFromName = guessMimeFromFilename(pic.filename);
        const mime = mimeFromName || guessMimeFromBase64(b64);
        const ext = extFromMime(mime);

        const buffer = Buffer.from(b64, "base64");
        const key = `products/${itemcode}/${kind.toLowerCase()}.${ext}`;

        const cdnUrl = await uploadToR2WithRetry({ key, body: buffer, contentType: mime });

        await pool.query(
          `
          UPDATE product_pictures
          SET cdn_url = $1, needs_fetch = false, updated_at = NOW()
          WHERE itemcode = $2 AND picture_id = $3
          `,
          [cdnUrl, itemcode, pic.picture_id]
        );

        processed += 1;
      } catch (e) {
        failed += 1;
        console.error("upload-pictures-to-r2 item failed:", { itemcode, kind, err: e?.message || String(e) });
        // Belangrijk: laat needs_fetch true zodat job kan herstarten.
        await pool.query(
          `UPDATE product_pictures SET updated_at = NOW() WHERE itemcode=$1 AND picture_id=$2`,
          [itemcode, pic.picture_id]
        );
      }
    });

    res.json({
      ok: true,
      kinds,
      limit,
      concurrency,
      queued: rows.length,
      processed,
      skippedNoAfasRow,
      skippedNoB64,
      failed,
    });
  } catch (err) {
    console.error("sync/upload-pictures-to-r2:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =======================
   PRODUCTS API
   ======================= */
async function queryProductsWithSafeImage(limit, offset) {
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
        SELECT pic.cdn_url
        FROM product_pictures pic
        WHERE pic.itemcode = p.itemcode
          AND pic.cdn_url IS NOT NULL
        ORDER BY
          CASE WHEN pic.kind = 'MAIN' THEN 0 ELSE 1 END,
          COALESCE(pic.sort_order, 999),
          pic.picture_id
        LIMIT 1
      ), '') AS image_url
    FROM products p
    WHERE p.ecommerce_available = true
    ORDER BY p.itemcode
    LIMIT $1 OFFSET $2
  `;

  const { rows } = await pool.query(q, [limit, offset]);
  return { rows };
}

app.get("/products", async (req, res) => {
  const take = req.query.take != null ? Number(req.query.take) : null;
  const skip = req.query.skip != null ? Number(req.query.skip) : null;

  const limit = Math.min(200, Number(req.query.limit) || take || 50);
  const offset = Math.max(0, Number(req.query.offset) || skip || 0);

  try {
    const result = await queryProductsWithSafeImage(limit, offset);
    res.json({
      ok: true,
      limit,
      offset,
      count: result.rows.length,
      data: result.rows,
    });
  } catch (err) {
    console.error("GET /products DB error:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

app.get("/products/:itemcode", async (req, res) => {
  const { itemcode } = req.params;

  try {
    const q = `
      SELECT
        p.*,
        COALESCE(
          (
            SELECT json_agg(pic.cdn_url ORDER BY
              CASE WHEN pic.kind = 'MAIN' THEN 0 ELSE 1 END,
              COALESCE(pic.sort_order, 999),
              pic.picture_id
            )
            FROM product_pictures pic
            WHERE pic.itemcode = p.itemcode
              AND pic.cdn_url IS NOT NULL
          ),
          '[]'::json
        ) AS image_urls,
        COALESCE((
          SELECT pic.cdn_url
          FROM product_pictures pic
          WHERE pic.itemcode = p.itemcode
            AND pic.cdn_url IS NOT NULL
          ORDER BY
            CASE WHEN pic.kind = 'MAIN' THEN 0 ELSE 1 END,
            COALESCE(pic.sort_order, 999),
            pic.picture_id
          LIMIT 1
        ), '') AS image_url
      FROM products p
      WHERE p.itemcode = $1
        AND p.ecommerce_available = true
      LIMIT 1
    `;

    const { rows } = await pool.query(q, [itemcode]);
    if (!rows || rows.length === 0) return res.status(404).json({ ok: false, error: "Not found" });
    res.json({ ok: true, data: rows[0] });
  } catch (err) {
    console.error("GET /products/:itemcode DB error:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

app.get("/products/by-ean/:ean", async (req, res) => {
  const { ean } = req.params;

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
        COALESCE(pic_main.cdn_url, '') AS image_url
      FROM products p
      LEFT JOIN LATERAL (
        SELECT pp.cdn_url
        FROM product_pictures pp
        WHERE pp.itemcode = p.itemcode
          AND pp.cdn_url IS NOT NULL
        ORDER BY
          CASE WHEN pp.kind = 'MAIN' THEN 0 ELSE 1 END,
          COALESCE(pp.sort_order, 999),
          pp.picture_id
        LIMIT 1
      ) pic_main ON TRUE
      WHERE p.ean = $1
        AND p.ecommerce_available = true
      LIMIT 1
    `;

    const { rows } = await pool.query(q, [ean]);
    if (!rows || rows.length === 0) return res.status(404).json({ ok: false, error: "Unknown EAN" });
    res.json({ ok: true, data: rows[0] });
  } catch (err) {
    console.error("GET /products/by-ean DB error:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =======================
   ADMIN + AUTH
   ======================= */
app.post("/admin/setup", async (req, res) => {
  const setupKey = req.query.key;
  if (!setupKey || setupKey !== process.env.SETUP_KEY) {
    return res.status(401).json({ error: "Invalid setup key" });
  }

  const { agentId, pin } = req.body;
  if (!agentId || !pin) return res.status(400).json({ error: "agentId and pin required" });

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

    res.json({ status: "setup complete", agentId });
  } catch (err) {
    console.error("admin/setup:", err);
    res.status(500).json({ error: err.message || "setup failed" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { agentId, pin } = req.body;
  if (!agentId || !pin) return res.status(400).json({ error: "agentId and pin required" });

  try {
    const result = await pool.query("SELECT * FROM agents WHERE agent_id = $1", [agentId]);
    if (result.rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });

    const agent = result.rows[0];
    const isValid = await bcrypt.compare(pin, agent.pin_hash);
    if (!isValid) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ agentId: agent.agent_id }, process.env.JWT_SECRET, { expiresIn: "8h" });
    res.json({ token, agentId: agent.agent_id });
  } catch (err) {
    console.error("auth/login:", err);
    res.status(500).json({ error: err.message || "login failed" });
  }
});

app.get("/me", authMiddleware, (req, res) => {
  res.json({ status: "ok", user: req.user });
});

/* =======================
   DEBUG (licht)
   ======================= */
app.get("/debug/pictures/db-counts", async (req, res) => {
  try {
    const a = await pool.query(`
      SELECT COUNT(*)::int AS ecommerce_products
      FROM products
      WHERE ecommerce_available = true
    `);

    const b = await pool.query(`
      SELECT
        COUNT(*)::int AS main_records_total,
        COUNT(*) FILTER (WHERE cdn_url IS NOT NULL)::int AS main_with_cdn,
        COUNT(*) FILTER (WHERE cdn_url IS NULL)::int AS main_missing_cdn
      FROM product_pictures
      WHERE kind = 'MAIN'
    `);

    const c = await pool.query(`
      SELECT COUNT(*)::int AS ecommerce_missing_main_record
      FROM products p
      LEFT JOIN product_pictures pp
        ON pp.itemcode = p.itemcode AND pp.kind = 'MAIN'
      WHERE p.ecommerce_available = true
        AND pp.itemcode IS NULL
    `);

    res.json({ ok: true, ...a.rows[0], ...b.rows[0], ...c.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

app.get("/debug/pictures/sample", async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT
        itemcode, picture_id, kind, cdn_url, needs_fetch,
        filename, original_file, location, sort_order, updated_at
      FROM product_pictures
      ORDER BY updated_at DESC
      LIMIT 10
    `);
    res.json({ ok: true, rows: r.rows });
  } catch (err) {
    console.error("debug/pictures/sample:", err);
    res.status(500).json({ ok: false, error: err.message || "db error" });
  }
});

/* =======================
   ERROR HANDLER
   ======================= */
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ ok: false, error: err?.message || String(err) });
});

/* =======================
   START SERVER + GRACEFUL SHUTDOWN
   ======================= */
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

  // Force exit if hanging
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
