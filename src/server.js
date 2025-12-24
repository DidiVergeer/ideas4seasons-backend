// src/server.js
/* eslint-disable no-console */

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

// Node 18+ heeft fetch global. Fallback voor oudere node:
const fetchFn =
  typeof fetch !== "undefined"
    ? fetch
    : (...args) => import("node-fetch").then(({ default: f }) => f(...args));

const app = express();
const PORT = process.env.PORT || 3000;

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
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// base64 afbeeldingen kunnen groot zijn
app.use(express.json({ limit: "50mb" }));

/* =======================
   DATABASE
   ======================= */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

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
   AFAS HELPERS
   ======================= */
function buildAfasAuthHeaderFromData(dataToken) {
  const xmlToken = `<token><version>1</version><data>${dataToken}</data></token>`;
  const b64 = Buffer.from(xmlToken, "utf8").toString("base64");
  return `AfasToken ${b64}`;
}

async function fetchAfas(connectorId, { skip = 0, take = 100 } = {}) {
  const env = process.env.AFAS_ENV;
  const dataToken = process.env.AFAS_TOKEN_DATA;

  if (!env || !dataToken || !connectorId) {
    throw new Error("Missing AFAS env vars (AFAS_ENV / AFAS_TOKEN_DATA / connectorId)");
  }

  const url = `https://${env}.rest.afas.online/ProfitRestServices/connectors/${connectorId}?skip=${skip}&take=${take}`;

  const res = await fetchFn(url, {
    method: "GET",
    headers: {
      Authorization: buildAfasAuthHeaderFromData(dataToken),
      Accept: "application/json",
    },
  });

  const text = await res.text();
  if (!res.ok) throw new Error(`AFAS ${res.status}: ${text}`);

  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`AFAS invalid JSON: ${text}`);
  }
}

async function forEachAfasRow(connectorId, { take = 200 } = {}, onRow) {
  let skip = 0;
  let pages = 0;
  let totalRows = 0;

  while (true) {
    const data = await fetchAfas(connectorId, { skip, take });
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

/* =======================
   IMAGE HELPERS (AFAS base64)
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
  return "image/jpeg";
}

function base64ToDataUrl(b64) {
  const clean = normalizeBase64(b64);
  if (!clean) return null;
  const mime = guessMimeFromBase64(clean);
  return `data:${mime};base64,${clean}`;
}

/* =======================
   DB INTROSPECTION (runtime safety)
   ======================= */
async function tableColumns(tableName) {
  const { rows } = await pool.query(
    `
    SELECT column_name
    FROM information_schema.columns
    WHERE table_name = $1
    `,
    [tableName]
  );
  return new Set(rows.map((r) => r.column_name));
}

/* =======================
   HEALTH
   ======================= */
app.get("/health", (req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});

app.get("/health/afas", async (req, res) => {
  try {
    const connectorId = process.env.AFAS_CONNECTOR;
    const data = await fetchAfas(connectorId, { skip: 0, take: 1 });
    res.json({
      ok: true,
      env: process.env.AFAS_ENV,
      connectorId,
      sample: data?.rows?.[0] ?? null,
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

app.get("/health/afas/:connectorId", async (req, res) => {
  try {
    const connectorId = req.params.connectorId;
    const data = await fetchAfas(connectorId, { skip: 0, take: 3 });
    res.json({
      ok: true,
      env: process.env.AFAS_ENV,
      connectorId,
      count: data?.rows?.length ?? 0,
      sample: data?.rows?.[0] ?? null,
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

app.get("/db-test", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ db: "connected" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ db: "error", error: err.message || String(err) });
  }
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
        url TEXT NULL,
        image_base64 TEXT NULL,
        mime TEXT NULL,
        filename TEXT NULL,
        original_file TEXT NULL,
        location TEXT NULL,
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

app.post("/db/migrate-pictures-v4", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  try {
    await pool.query(`
      ALTER TABLE product_pictures
        ADD COLUMN IF NOT EXISTS kind TEXT NULL,
        ADD COLUMN IF NOT EXISTS image_base64 TEXT NULL,
        ADD COLUMN IF NOT EXISTS mime TEXT NULL,
        ADD COLUMN IF NOT EXISTS filename TEXT NULL,
        ADD COLUMN IF NOT EXISTS original_file TEXT NULL,
        ADD COLUMN IF NOT EXISTS location TEXT NULL;
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_product_pictures_item_kind_sort
      ON product_pictures (itemcode, kind, sort_order, picture_id);
    `);

    res.json({ ok: true, message: "product_pictures migrated to v4" });
  } catch (err) {
    console.error("migrate-pictures-v4:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =======================
   SYNC PRODUCTS
   ======================= */
app.post("/sync/products", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const connectorId = req.query.connectorId || process.env.AFAS_CONNECTOR || "Items_Core";
  const take = Number(req.query.take || 100);

  let totalUpserted = 0;

  try {
    const { pages, totalRows } = await forEachAfasRow(connectorId, { take }, async (r) => {
      const itemcode = r.Itemcode ?? null;
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
   SYNC: categories / descriptions / pictures / stock
   ======================= */
app.post("/sync/categories", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const connectorId = req.query.connectorId || "Items_Category_app";
  const take = Number(req.query.take || 200);
  let upserted = 0;

  try {
    const { pages, totalRows } = await forEachAfasRow(connectorId, { take }, async (r) => {
      const itemcode = r.Itemcode ?? r.itemcode ?? null;
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
  const take = Number(req.query.take || 200);
  let upserted = 0;

  try {
    const { pages, totalRows } = await forEachAfasRow(connectorId, { take }, async (r) => {
      const itemcode = r.Itemcode ?? r.itemcode ?? null;
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

/**
 * PICTURES SYNC
 * Verwachte base64 velden:
 *  - Afbeelding (MAIN)
 *  - Afbeelding_1..Afbeelding_5 (SFEER_1..SFEER_5)
 */
app.post("/sync/pictures", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const connectorId = req.query.connectorId || "Items_Pictures_app";
  const take = Number(req.query.take || 200);
  let rowsUpserted = 0;
  let imagesSaved = 0;

  const slots = [
    { kind: "MAIN", b64Key: "Afbeelding", sort: 0, filenameKey: "Bestandsnaam_MAIN", originalKey: "Origineel_bestand_MAIN", locationKey: "Bestandslocatie_MAIN" },
    { kind: "SFEER_1", b64Key: "Afbeelding_1", sort: 1, filenameKey: "Bestandsnaam_SFEER_1", originalKey: "Origineel_bestand_SFEER_1", locationKey: "Bestandslocatie_SFEER_1" },
    { kind: "SFEER_2", b64Key: "Afbeelding_2", sort: 2, filenameKey: "Bestandsnaam_SFEER_2", originalKey: "Origineel_bestand_SFEER_2", locationKey: "Bestandslocatie_SFEER_2" },
    { kind: "SFEER_3", b64Key: "Afbeelding_3", sort: 3, filenameKey: "Bestandsnaam_SFEER_3", originalKey: "Origineel_bestand_SFEER_3", locationKey: "Bestandslocatie_SFEER_3" },
    { kind: "SFEER_4", b64Key: "Afbeelding_4", sort: 4, filenameKey: "Bestandsnaam_SFEER_4", originalKey: "Origineel_bestand_SFEER_4", locationKey: "Bestandslocatie_SFEER_4" },
    { kind: "SFEER_5", b64Key: "Afbeelding_5", sort: 5, filenameKey: "Bestandsnaam_SFEER_5", originalKey: "Origineel_bestand_SFEER_5", locationKey: "Bestandslocatie_SFEER_5" },
  ];

  try {
    const { pages, totalRows } = await forEachAfasRow(connectorId, { take }, async (r) => {
      const itemcode = r.Itemcode ?? r.itemcode ?? null;
      if (!itemcode) return;

      for (const s of slots) {
        const b64 = normalizeBase64(r[s.b64Key]);
        if (!b64) continue;

        const mime = guessMimeFromBase64(b64);
        const dataUrl = `data:${mime};base64,${b64}`;

        const filename = r[s.filenameKey] ?? null;
        const original_file = r[s.originalKey] ?? null;
        const location = r[s.locationKey] ?? null;

        // ✅ stabiele ID (belangrijk!)
        const stableId = String(original_file || location || `${itemcode}-${s.kind}`);
        const picture_id = sha1(stableId);

        await pool.query(
          `
          INSERT INTO product_pictures (
            itemcode, picture_id, kind,
            url, image_base64, mime,
            filename, original_file, location,
            sort_order, raw, updated_at
          )
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
          ON CONFLICT (itemcode, picture_id) DO UPDATE SET
            kind = EXCLUDED.kind,
            url = EXCLUDED.url,
            image_base64 = EXCLUDED.image_base64,
            mime = EXCLUDED.mime,
            filename = EXCLUDED.filename,
            original_file = EXCLUDED.original_file,
            location = EXCLUDED.location,
            sort_order = EXCLUDED.sort_order,
            raw = EXCLUDED.raw,
            updated_at = NOW()
          `,
          [
            String(itemcode),
            String(picture_id),
            s.kind,
            dataUrl,
            b64,
            mime,
            filename ? String(filename) : null,
            original_file ? String(original_file) : null,
            location ? String(location) : null,
            s.sort,
            r,
          ]
        );

        imagesSaved += 1;
      }

      rowsUpserted += 1;
    });

    res.json({ ok: true, connectorId, pages, rowsFetched: totalRows, upsertedRows: rowsUpserted, imagesSaved });
  } catch (err) {
    console.error("sync/pictures:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

app.post("/sync/stock", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const connectorId = req.query.connectorId || "Items_stock_app";
  const take = Number(req.query.take || 200);
  let upserted = 0;

  try {
    const { pages, totalRows } = await forEachAfasRow(connectorId, { take }, async (r) => {
      const itemcode = r.Itemcode ?? r.itemcode ?? null;
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
   PRODUCTS API
   ======================= */

async function queryProductsWithSafeImage(limit, offset) {
  const qWithImage = `
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
        SELECT pic.url
        FROM product_pictures pic
        WHERE pic.itemcode = p.itemcode
          AND pic.url IS NOT NULL
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

  try {
    const { rows } = await pool.query(qWithImage, [limit, offset]);
    return { rows, usedFallback: false };
  } catch (e) {
    console.error("queryProductsWithSafeImage failed; fallback without images:", e.message || e);

    const qNoImage = `
      SELECT
        p.itemcode,
        p.description_eng,
        p.ean,
        p.price,
        p.available_stock,
        p.outercarton,
        p.innercarton,
        p.unit,
        '' AS image_url
      FROM products p
      WHERE p.ecommerce_available = true
      ORDER BY p.itemcode
      LIMIT $1 OFFSET $2
    `;
    const { rows } = await pool.query(qNoImage, [limit, offset]);
    return { rows, usedFallback: true, error: e.message || String(e) };
  }
}

// GET /products?limit=50&offset=0
app.get("/products", async (req, res) => {
  const limit = Number(req.query.limit) || 50;
  const offset = Number(req.query.offset) || 0;

  try {
    const result = await queryProductsWithSafeImage(limit, offset);
    res.json({
      ok: true,
      limit,
      offset,
      count: result.rows.length,
      usedFallbackNoImages: Boolean(result.usedFallback),
      fallbackReason: result.usedFallback ? result.error : null,
      data: result.rows,
    });
  } catch (err) {
    console.error("GET /products DB error:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

// GET /products/:itemcode
app.get("/products/:itemcode", async (req, res) => {
  const { itemcode } = req.params;

  try {
    const q = `
      SELECT
        p.*,
        COALESCE(
          (
            SELECT json_agg(pic.url ORDER BY
              CASE WHEN pic.kind = 'MAIN' THEN 0 ELSE 1 END,
              COALESCE(pic.sort_order, 999),
              pic.picture_id
            )
            FROM product_pictures pic
            WHERE pic.itemcode = p.itemcode
              AND pic.url IS NOT NULL
          ),
          '[]'::json
        ) AS image_urls,
        COALESCE((
          SELECT pic.url
          FROM product_pictures pic
          WHERE pic.itemcode = p.itemcode
            AND pic.url IS NOT NULL
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

    let rows;
    try {
      ({ rows } = await pool.query(q, [itemcode]));
    } catch (e) {
      console.error("GET /products/:itemcode failed; fallback without images:", e.message || e);
      ({ rows } = await pool.query(
        `
        SELECT p.*, '[]'::json AS image_urls, '' AS image_url
        FROM products p
        WHERE p.itemcode = $1 AND p.ecommerce_available = true
        LIMIT 1
        `,
        [itemcode]
      ));
    }

    if (!rows || rows.length === 0) return res.status(404).json({ ok: false, error: "Not found" });
    res.json({ ok: true, data: rows[0] });
  } catch (err) {
    console.error("GET /products/:itemcode DB error:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

// GET /products/by-ean/:ean
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
        COALESCE(pic_main.url, '') AS image_url
      FROM products p
      LEFT JOIN LATERAL (
        SELECT pp.url
        FROM product_pictures pp
        WHERE pp.itemcode = p.itemcode
          AND pp.url IS NOT NULL
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

    let rows;
    try {
      ({ rows } = await pool.query(q, [ean]));
    } catch (e) {
      console.error("GET /products/by-ean failed; fallback without images:", e.message || e);
      ({ rows } = await pool.query(
        `
        SELECT
          p.itemcode, p.description_eng, p.ean, p.price, p.available_stock,
          p.outercarton, p.innercarton, p.unit,
          '' AS image_url
        FROM products p
        WHERE p.ean = $1 AND p.ecommerce_available = true
        LIMIT 1
        `,
        [ean]
      ));
    }

    if (!rows || rows.length === 0) return res.status(404).json({ ok: false, error: "Unknown EAN" });
    res.json({ ok: true, data: rows[0] });
  } catch (err) {
    console.error("GET /products/by-ean DB error:", err);
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

/* =======================
   AUTH LOGIN
   ======================= */
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

/* =======================
   ME (protected)
   ======================= */
app.get("/me", authMiddleware, (req, res) => {
  res.json({ status: "ok", user: req.user });
});

/* =======================
   DEBUG
   ======================= */

// Products
app.get("/debug/products/count", async (req, res) => {
  try {
    const r = await pool.query("SELECT count(*) FROM products");
    res.json({ ok: true, count: Number(r.rows[0].count) });
  } catch (err) {
    console.error("debug/products/count:", err);
    res.status(500).json({ ok: false, error: err.message || "db error" });
  }
});

app.get("/debug/products/count-ecom", async (req, res) => {
  try {
    const r = await pool.query("SELECT count(*) FROM products WHERE ecommerce_available = true");
    res.json({ ok: true, count: Number(r.rows[0].count) });
  } catch (err) {
    console.error("debug/products/count-ecom:", err);
    res.status(500).json({ ok: false, error: err.message || "db error" });
  }
});

app.get("/debug/products/columns", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT column_name, data_type
      FROM information_schema.columns
      WHERE table_name = 'products'
      ORDER BY ordinal_position
    `);
    res.json({ ok: true, rows });
  } catch (err) {
    console.error("debug/products/columns:", err);
    res.status(500).json({ ok: false, error: err.message || "db error" });
  }
});

// Pictures
app.get("/debug/pictures/columns", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT column_name, data_type
      FROM information_schema.columns
      WHERE table_name = 'product_pictures'
      ORDER BY ordinal_position
    `);
    res.json({ ok: true, rows });
  } catch (err) {
    console.error("debug/pictures/columns:", err);
    res.status(500).json({ ok: false, error: err.message || "db error" });
  }
});

app.get("/debug/pictures/count", async (req, res) => {
  try {
    const r = await pool.query("SELECT count(*) FROM product_pictures");
    res.json({ ok: true, count: Number(r.rows[0].count) });
  } catch (err) {
    console.error("debug/pictures/count:", err);
    res.status(500).json({ ok: false, error: err.message || "db error" });
  }
});

// sample: laat alleen preview zien (niet hele base64)
app.get("/debug/pictures/sample", async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT
        itemcode,
        picture_id,
        kind,
        CASE WHEN url IS NULL THEN NULL ELSE LEFT(url, 60) || '...' END AS url_preview,
        filename,
        original_file,
        location,
        sort_order,
        updated_at
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

app.get("/debug/pictures/:itemcode", async (req, res) => {
  const { itemcode } = req.params;

  try {
    const r = await pool.query(
      `
      SELECT
        itemcode,
        picture_id,
        kind,
        CASE WHEN url IS NULL THEN NULL ELSE LEFT(url, 60) || '...' END AS url_preview,
        filename,
        original_file,
        location,
        sort_order,
        updated_at
      FROM product_pictures
      WHERE itemcode = $1
      ORDER BY
        CASE WHEN kind = 'MAIN' THEN 0 ELSE 1 END,
        COALESCE(sort_order, 999),
        picture_id
      `,
      [itemcode]
    );

    res.json({ ok: true, itemcode, count: r.rows.length, rows: r.rows });
  } catch (err) {
    console.error("debug/pictures/:itemcode:", err);
    res.status(500).json({ ok: false, error: err.message || "db error" });
  }
});

// AFAS pictures sample
app.get("/debug/afas/pictures/sample", async (req, res) => {
  try {
    const connectorId = "Items_Pictures_app";
    const data = await fetchAfas(connectorId, { skip: 0, take: 1 });
    const row = data?.rows?.[0] ?? null;

    res.json({
      ok: true,
      connectorId,
      keys: row ? Object.keys(row) : [],
      sample: row,
    });
  } catch (err) {
    console.error("debug/afas/pictures/sample:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =======================
   DB UTIL: reset pictures (one-time)
   ======================= */
app.post("/db/reset-pictures", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  try {
    await pool.query("TRUNCATE TABLE product_pictures;");
    res.json({ ok: true, message: "product_pictures truncated" });
  } catch (err) {
    console.error("db/reset-pictures:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =======================
   BROWSER TRIGGERS (TEMP)
   - hiermee kun je reset/sync in de browser doen (GET)
   - later weer verwijderen
   ======================= */

// GET reset (browser)
app.get("/debug/reset-pictures", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  try {
    await pool.query("TRUNCATE TABLE product_pictures;");
    res.json({ ok: true, message: "product_pictures truncated" });
  } catch (err) {
    console.error("debug/reset-pictures:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

// GET sync (browser) -> triggert intern POST /sync/pictures
app.get("/debug/run-sync-pictures", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const take = Number(req.query.take || 200);

  try {
    // interne call naar eigen server
    const internalUrl = `http://127.0.0.1:${PORT}/sync/pictures?key=${encodeURIComponent(
      req.query.key
    )}&take=${take}`;

    const r = await fetchFn(internalUrl, { method: "POST" });
    const text = await r.text();
    res.status(r.status).type("application/json").send(text);
  } catch (err) {
    console.error("debug/run-sync-pictures:", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =======================
   START SERVER
   ======================= */
app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
});
