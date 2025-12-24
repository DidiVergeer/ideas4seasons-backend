// src/server.js

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

app.use(express.json());

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
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

/* =======================
   AFAS HELPERS
   ======================= */
function buildAfasAuthHeaderFromData(dataToken) {
  // AFAS verwacht token als base64 XML
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
  } catch (e) {
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

// Test elke connector via backend (handig!)
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
    res.status(500).json({ db: "error" });
  }
});

/* =======================
   DB SETUP (A1)
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

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_products_ean ON products(ean);
    `);

    res.json({ ok: true, message: "products table ready" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ✅ Extra tabellen voor Category/Descriptions/Pictures/Stock
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
        url TEXT NULL,
        sort_order INT NULL,
        raw JSONB NULL,
        updated_at TIMESTAMP DEFAULT NOW(),
        PRIMARY KEY (itemcode, picture_id)
      );
    `);

    // ✅ performance index voor "main image" en carousel
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_product_pictures_item_sort
      ON product_pictures (itemcode, sort_order, picture_id);
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
    console.error(err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =======================
   SYNC PRODUCTS (A2)
   ======================= */
app.post("/sync/products", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const connectorId = req.query.connectorId || process.env.AFAS_CONNECTOR; // default Items_Core
  const take = Number(req.query.take || 100);

  let totalUpserted = 0;

  try {
    const { pages, totalRows } = await forEachAfasRow(connectorId, { take }, async (r) => {
      const itemcode = r.Itemcode ?? null;
      if (!itemcode) return;

      // ✅ FIX: AFAS geeft boolean true/false terug
      const ecomBool = Boolean(r["E-commerce_beschikbaar"]);

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
          ecomBool,
          r,
        ]
      );

      totalUpserted += 1;
    });

    res.json({
      ok: true,
      connectorId,
      pages,
      rowsFetched: totalRows,
      upserted: totalUpserted,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =======================
   SYNC CATEGORIES / DESCRIPTIONS / PICTURES / STOCK
   Best-effort mapping + raw opslaan
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

      const category_code =
        r.CategoryCode ?? r.Category ?? r.CategorieCode ?? r.Categorie ?? null;

      const category_name = r.CategoryName ?? r.CategorieNaam ?? r.Naam ?? null;

      // PK moet gevuld zijn → fallback op hash van row als code ontbreekt
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
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

app.post("/sync/pictures", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const connectorId = req.query.connectorId || "Items_Pictures_app";
  const take = Number(req.query.take || 200);
  let upserted = 0;

  try {
    const { pages, totalRows } = await forEachAfasRow(connectorId, { take }, async (r) => {
      const itemcode = r.Itemcode ?? r.itemcode ?? null;
      if (!itemcode) return;

      const url = r.Url ?? r.URL ?? r.PictureUrl ?? r.AfbeeldingUrl ?? r.Link ?? null;

      const sort_order = Number(r.SortOrder ?? r.Volgorde ?? r.Sort ?? 0);
      const picture_id =
        (r.PictureId ?? r.ID ?? r.Id ?? null) || (url ? sha1(url) : sha1(JSON.stringify(r)));

      await pool.query(
        `
        INSERT INTO product_pictures (itemcode, picture_id, url, sort_order, raw, updated_at)
        VALUES ($1,$2,$3,$4,$5,NOW())
        ON CONFLICT (itemcode, picture_id) DO UPDATE SET
          url = EXCLUDED.url,
          sort_order = EXCLUDED.sort_order,
          raw = EXCLUDED.raw,
          updated_at = NOW()
        `,
        [String(itemcode), String(picture_id), url, Number.isFinite(sort_order) ? sort_order : 0, r]
      );

      upserted += 1;
    });

    res.json({ ok: true, connectorId, pages, rowsFetched: totalRows, upserted });
  } catch (err) {
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

      // Soms per magazijn
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
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

// ✅ 1 knop: alles syncen
app.post("/sync/all", async (req, res) => {
  if (!requireSetupKey(req, res)) return;

  const take = Number(req.query.take || 200);
  const results = {};

  try {
    results.products = await (async () => {
      let upserted = 0;
      const connectorId = process.env.AFAS_CONNECTOR || "Items_Core";

      const { pages, totalRows } = await forEachAfasRow(
        connectorId,
        { take: Number(req.query.takeProducts || 100) },
        async (r) => {
          const itemcode = r.Itemcode ?? null;
          if (!itemcode) return;

          const ecomRaw = r["E-commerce_beschikbaar"] ?? null;
          const ecomBool = ecomRaw === "Ja";

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
              ecomBool,
              r,
            ]
          );

          upserted++;
        }
      );

      return { ok: true, connectorId, pages, rowsFetched: totalRows, upserted };
    })();

    results.categories = await (async () => {
      let upserted = 0;
      const connectorId = "Items_Category_app";
      const { pages, totalRows } = await forEachAfasRow(connectorId, { take }, async (r) => {
        const itemcode = r.Itemcode ?? r.itemcode ?? null;
        if (!itemcode) return;

        const category_code =
          r.CategoryCode ?? r.Category ?? r.CategorieCode ?? r.Categorie ?? null;

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

        upserted++;
      });
      return { ok: true, connectorId, pages, rowsFetched: totalRows, upserted };
    })();

    results.descriptions = await (async () => {
      let upserted = 0;
      const connectorId = "Items_Descriptions_app";
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

        upserted++;
      });
      return { ok: true, connectorId, pages, rowsFetched: totalRows, upserted };
    })();

    results.pictures = await (async () => {
      let upserted = 0;
      const connectorId = "Items_Pictures_app";
      const { pages, totalRows } = await forEachAfasRow(connectorId, { take }, async (r) => {
        const itemcode = r.Itemcode ?? r.itemcode ?? null;
        if (!itemcode) return;

        const url = r.Url ?? r.URL ?? r.PictureUrl ?? r.AfbeeldingUrl ?? r.Link ?? null;

        const sort_order = Number(r.SortOrder ?? r.Volgorde ?? r.Sort ?? 0);
        const picture_id =
          (r.PictureId ?? r.ID ?? r.Id ?? null) || (url ? sha1(url) : sha1(JSON.stringify(r)));

        await pool.query(
          `
          INSERT INTO product_pictures (itemcode, picture_id, url, sort_order, raw, updated_at)
          VALUES ($1,$2,$3,$4,$5,NOW())
          ON CONFLICT (itemcode, picture_id) DO UPDATE SET
            url = EXCLUDED.url,
            sort_order = EXCLUDED.sort_order,
            raw = EXCLUDED.raw,
            updated_at = NOW()
          `,
          [String(itemcode), String(picture_id), url, Number.isFinite(sort_order) ? sort_order : 0, r]
        );

        upserted++;
      });
      return { ok: true, connectorId, pages, rowsFetched: totalRows, upserted };
    })();

    results.stock = await (async () => {
      let upserted = 0;
      const connectorId = "Items_stock_app";
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

        upserted++;
      });
      return { ok: true, connectorId, pages, rowsFetched: totalRows, upserted };
    })();

    res.json({ ok: true, results });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

/* =======================
   PRODUCTS API (A3)
   Alleen ecommerce_available = true
   + images (main + all)
   ======================= */

// GET /products?limit=50&offset=0
app.get("/products", async (req, res) => {
  const limit = Number(req.query.limit) || 50;
  const offset = Number(req.query.offset) || 0;

  try {
    const { rows } = await pool.query(
      `
      SELECT
        p.itemcode,
        p.description_eng,
        p.ean,
        p.price,
        p.available_stock,
        p.outercarton,
        p.innercarton,
        p.unit,

        -- ✅ ALTIJD 1 productfoto als die bestaat
        (
          SELECT pic.url
          FROM product_pictures pic
          WHERE pic.itemcode = p.itemcode
            AND pic.url IS NOT NULL
          ORDER BY
            COALESCE(pic.sort_order, 999),
            pic.picture_id
          LIMIT 1
        ) AS image_url

      FROM products p
      WHERE p.ecommerce_available = true
      ORDER BY p.itemcode
      LIMIT $1 OFFSET $2
      `,
      [limit, offset]
    );

    res.json({
      ok: true,
      limit,
      offset,
      count: rows.length,
      data: rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "DB error" });
  }
});

// GET /products/:itemcode
app.get("/products/:itemcode", async (req, res) => {
  const { itemcode } = req.params;

  try {
    const { rows } = await pool.query(
      `
      SELECT
        p.*,

        -- ✅ array van alle afbeeldingen (voor swipe)
        COALESCE(
          (
            SELECT json_agg(pic.url ORDER BY COALESCE(pic.sort_order, 999), pic.picture_id)
            FROM product_pictures pic
            WHERE pic.itemcode = p.itemcode
              AND pic.url IS NOT NULL
          ),
          '[]'::json
        ) AS image_urls

      FROM products p
      WHERE p.itemcode = $1
        AND p.ecommerce_available = true
      `,
      [itemcode]
    );

    if (rows.length === 0) {
      return res.status(404).json({ ok: false, error: "Not found" });
    }

    res.json({ ok: true, data: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "DB error" });
  }
});

// GET /products/by-ean/:ean
// ✅ includes image_url (main) for scanner result
app.get("/products/by-ean/:ean", async (req, res) => {
  const { ean } = req.params;

  try {
    const { rows } = await pool.query(
      `
      SELECT
        p.itemcode,
        p.description_eng,
        p.ean,
        p.price,
        p.available_stock,
        p.outercarton,
        p.innercarton,
        p.unit,
        pic_main.url AS image_url
      FROM products p
      LEFT JOIN LATERAL (
        SELECT pp.url
        FROM product_pictures pp
        WHERE pp.itemcode = p.itemcode
          AND pp.url IS NOT NULL
        ORDER BY COALESCE(pp.sort_order, 0) ASC, pp.picture_id ASC
        LIMIT 1
      ) pic_main ON TRUE
      WHERE p.ean = $1
        AND p.ecommerce_available = true
      LIMIT 1
      `,
      [ean]
    );

    if (rows.length === 0) {
      return res.status(404).json({ ok: false, error: "Unknown EAN" });
    }

    res.json({ ok: true, data: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "DB error" });
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

    res.json({ status: "setup complete", agentId });
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
    const result = await pool.query("SELECT * FROM agents WHERE agent_id = $1", [agentId]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const agent = result.rows[0];
    const isValid = await bcrypt.compare(pin, agent.pin_hash);
    if (!isValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ agentId: agent.agent_id }, process.env.JWT_SECRET, { expiresIn: "8h" });

    res.json({ token, agentId: agent.agent_id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "login failed" });
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
app.get("/debug/products/count", async (req, res) => {
  try {
    const r = await pool.query("SELECT count(*) FROM products");
    res.json({ count: Number(r.rows[0].count) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "db error" });
  }
});

app.get("/debug/products/count-ecom", async (req, res) => {
  try {
    const r = await pool.query("SELECT count(*) FROM products WHERE ecommerce_available = true");
    res.json({ count: Number(r.rows[0].count) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "db error" });
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
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "db error" });
  }
});

// DEBUG: hoeveel pictures hebben we?
app.get("/debug/pictures/count", async (req, res) => {
  try {
    const r = await pool.query("SELECT count(*) FROM product_pictures");
    res.json({ count: Number(r.rows[0].count) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "db error" });
  }
});

// DEBUG: sample pictures (laatste 10)
app.get("/debug/pictures/sample", async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT itemcode, picture_id, url, sort_order, updated_at
      FROM product_pictures
      ORDER BY updated_at DESC
      LIMIT 10
    `);
    res.json({ rows: r.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "db error" });
  }
});

// DEBUG: pictures voor 1 itemcode
app.get("/debug/pictures/:itemcode", async (req, res) => {
  const { itemcode } = req.params;
  try {
    const r = await pool.query(
      `
      SELECT itemcode, picture_id, url, sort_order, updated_at
      FROM product_pictures
      WHERE itemcode = $1
      ORDER BY COALESCE(sort_order, 999), picture_id
      `,
      [itemcode]
    );
    res.json({ itemcode, count: r.rows.length, rows: r.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "db error" });
  }
});

/* =======================
   START SERVER
   ======================= */
app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
});
