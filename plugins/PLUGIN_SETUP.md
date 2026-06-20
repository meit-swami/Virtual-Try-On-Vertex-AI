# ZAHA CMS Plugins — Setup & Testing Guide

Complete guide to install WordPress/Shopify plugins, manage promo codes, and test with [Indian Virasat — Petaline Pink Cosmos Sharara Set](https://indianvirasat.com/products/petaline-pink-cosmos-sharara-set).

---

## Part 1 — Start the ZAHA server

```bash
cd Virtual-Try-On-Vertex-AI
npm install
npm run build
npm start
```

Server runs at **http://localhost:3000**

On first start you'll see in the console:
- `🎟️ Promo code seeded: MEITANSHI7992 (20 try-ons, up to 100 redemptions)`
- `🔌 Plugin API key: zaha_xxxxxxxx` — **copy this key**

---

## Part 2 — Promo code admin (you control credits)

1. Open **http://localhost:3000/admin-promos.html**
2. Login as superadmin:
   - Email: `superadmin@zaha.ai`
   - Password: `admin123`
3. Create or verify promo code:
   - **Code:** `MEITANSHI7992`
   - **Try-on credits:** `20` (per redemption)
   - **Max redemptions:** `100` (how many people can use the code)

Each customer who redeems `MEITANSHI7992` gets **20 try-ons**.

You can create unlimited promo codes with different credit amounts from this page.

---

## Part 3 — Quick test (no CMS yet)

Open this URL in your browser (replace `YOUR_API_KEY`):

```
http://localhost:3000/embed.html?key=YOUR_API_KEY&productUrl=https://indianvirasat.com/products/petaline-pink-cosmos-sharara-set
```

Steps:
1. Enter promo code `MEITANSHI7992` → **Redeem**
2. Upload your photo
3. Product image loads automatically from the Indian Virasat page
4. Click **Generate Virtual Try-On**

---

## Part 4 — WordPress / WooCommerce plugin

### Install

1. Zip the folder `plugins/wordpress/zaha-virtual-try-on/`
2. WordPress Admin → **Plugins → Add New → Upload Plugin**
3. Activate **ZAHA Virtual Try-On**

### Configure

**Settings → ZAHA Try-On**

| Setting | Value |
|---------|--------|
| API URL | `http://localhost:3000` (or your deployed URL) |
| API Key | From admin-promos.html → Plugin sites |
| Button text | `✨ Virtual Try-On` |

### On product pages

The button appears automatically on WooCommerce product pages below the product summary.

For Indian Virasat (if it were WordPress), the product URL would be auto-detected.

**Shortcode** for any page:
```
[zaha_try_on product_url="https://indianvirasat.com/products/petaline-pink-cosmos-sharara-set"]
```

---

## Part 5 — Shopify plugin

### Option A — Theme block (Shopify CLI)

```bash
cd plugins/shopify
shopify app dev
```

In **Theme Editor → Product page**, add block **ZAHA Virtual Try-On** and enter API URL + API Key.

### Option B — Manual snippet (fastest)

1. Shopify Admin → **Online Store → Themes → Edit code**
2. Open `sections/main-product.liquid` (or your product template)
3. Paste contents of `plugins/shopify/SNIPPET-product-page.liquid` **after** the Add to Cart button
4. Replace:
   - `YOUR_ZAHA_API_URL` → `http://localhost:3000` (or production URL)
   - `YOUR_API_KEY` → your plugin API key

---

## Part 6 — Test with Indian Virasat product

Product: [Petaline Pink Cosmos Sharara Set](https://indianvirasat.com/products/petaline-pink-cosmos-sharara-set) — ₹4,590

Since indianvirasat.com is **Shopify** (not your WordPress), use the Shopify snippet on their theme OR test directly via embed URL:

```
http://localhost:3000/embed.html?key=YOUR_API_KEY&productUrl=https://indianvirasat.com/products/petaline-pink-cosmos-sharara-set
```

The server extracts the product image via `og:image` from the page automatically.

### Customer flow

1. Customer clicks **Virtual Try-On** on product page
2. Modal opens → enter promo code `MEITANSHI7992`
3. Gets 20 credits → uploads photo → generates try-on
4. Each generation uses 1 credit

---

## Part 7 — Production deployment

1. Deploy ZAHA app to Render/Railway with `DATABASE_URL` (Neon Postgres)
2. Run migrations: `psql $DATABASE_URL -f database/schema.pg.sql` then `schema-plugin.pg.sql`
3. Set `PROJECT_ID`, GCP credentials, `SESSION_SECRET`
4. Update WordPress/Shopify plugin **API URL** to production domain (HTTPS)
5. Create production plugin site + API key in admin-promos.html

---

## API reference (for custom integrations)

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `POST /api/plugin/redeem-promo` | `X-Zaha-Api-Key` | Redeem promo → get session token |
| `GET /api/plugin/credits` | API key + `X-Zaha-Session` | Check remaining credits |
| `POST /api/plugin/extract-product` | API key | Get product image from URL |
| `POST /api/plugin/try-on` | API key + session | Generate try-on (multipart) |
| `GET /api/admin/promos` | Superadmin session | List promo codes |
| `POST /api/admin/promos` | Superadmin session | Create promo code |

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Promo invalid | Check code in admin-promos.html, ensure `is_active` |
| No credits | Redeem promo again (new session) or create new promo |
| 403 Vertex AI | Enable billing + Vertex AI User role on GCP project |
| Product image not loading | Use `productImage=` param with direct image URL |
| CORS errors | Ensure API URL matches server; plugin.js loaded from same ZAHA server |
