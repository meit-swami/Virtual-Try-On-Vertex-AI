#### 🚀 Virtual Try-On Web App Using Google Cloud Vertex AI

I built a web app that uses Google Cloud’s Vertex AI to show how a product looks on a person. You upload an image of a person and an image of a product, and the app generates a virtual try-on image.

Virtual Try-On lets you generate images of people modeling clothing products. You provide an image of a person and a sample clothing product, and Virtual Try-On generates images of the person wearing the product.

#### 👉 Links & Resources

- [Vertex AI](https://cloud.google.com/vertex-ai)
- [Virtual Try-On](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/model-reference/virtual-try-on-api)

---

#### 🚀 Clone and Run

```bash
# Clone the repository
git clone https://github.com/Ashot72/Virtual-Try-On-Vertex-AI

# Navigate into the project directory
cd Virtual-Try-On-Vertex-AI

# Copy the example `.env` file and add your project ID
cp .env.example .env

# Place your `service-account-key.json` file in the project root directory.

# Install dependencies
npm install

# Start the development server
npm start

# The app will be available at http://localhost:3000
```

#### Database (login & per-user history)

The app supports **PostgreSQL** (recommended on Render) or **MySQL**.

**Option A – Render PostgreSQL**

1. In [Render Dashboard](https://dashboard.render.com), create a **PostgreSQL** instance and link it to your web service (or note the **Internal Database URL**).
2. In your web service, add the env var **`DATABASE_URL`** (Render often adds it automatically when you connect the DB).
3. Run the schema once: in Render → your PostgreSQL → **Shell**, or use **Connect** → run the SQL from `database/schema.pg.sql`.
4. Redeploy. Use **Test DB connection** on the Login page to confirm.

**Free tier: database expires (e.g. after 90 days)**

Render may delete a free Postgres after the expiry date. To keep using a free instance:

1. Create a **new** free PostgreSQL on Render.
2. Update **`DATABASE_URL`** in one place only: your **Web Service** → Environment → set it to the new **Internal Database URL** (from the new DB’s Connect tab). For local development, paste the **External** URL into your root `.env` and add `?sslmode=require` if it is not already there.
3. Open the new database in Render → **Shell** or **psql**, and run the contents of `database/schema.pg.sql` again so tables exist.
4. Redeploy the web service. Users and history start empty on the new database.
5. **Admin (superadmin):** If the `users` table has **no rows**, the app seeds `superadmin@zaha.ai` with password `admin123` on startup (change the password after first login). If you already ran the schema and inserted users another way, create or promote an admin manually in SQL if needed.

**Option B – MySQL (PlanetScale, Railway, or local)**

1. Leave `DATABASE_URL` **unset**.
2. Set `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` in your environment (see `.env.example`).
3. Run `database/schema.sql` in your MySQL (e.g. PlanetScale Console, phpMyAdmin, or `mysql` CLI).
4. Redeploy and test.

#### Live Try-On (real-time camera)

`/live.html` adds a live mode next to the photo-based try-on: the shopper turns on their camera, picks a garment (upload, drag a product photo from a store page, or paste a product link) and sees it on themselves as they move. Garments can be swapped mid-session.

It runs on [Decart's Lucy VTON realtime model](https://docs.platform.decart.ai/models/realtime/virtual-try-on). Video goes straight from the browser to Decart over WebRTC; this server only issues short-lived session tokens and fetches garment images.

**Turn it on**

1. Create an API key at [platform.decart.ai](https://platform.decart.ai) and set `DECART_API_KEY` in `.env` (see `.env.example`).
2. `npm run build && npm start` — the build now also bundles the browser SDK into `public/vendor/`.
3. Log in and open **Live Try-On** in the nav.

Without `DECART_API_KEY` the page explains that live mode is off and everything else works as before.

**Requirements**

- **HTTPS.** Browsers only allow camera access on `https://` (or `localhost`). Live mode will not work on a plain `http://` deployment.
- A logged-in ZAHA user — tokens are only issued to authenticated sessions.

**Cost controls**

Decart bills per second of live video, so every session is capped:

| Setting | Default | What it does |
|---|---|---|
| `LIVE_MAX_SESSION_SECONDS` | `120` | Hard cap per session, enforced by Decart on the token |
| `LIVE_SESSIONS_PER_HOUR` | `6` | Sessions each user may start per hour (superadmin is exempt) |
| `LIVE_ALLOWED_ORIGINS` | unset | Restrict tokens to your own site origin(s) |
| `LIVE_FAST_MODE` | `false` | Lower latency at twice the per-second price |

The page also stops the session when the tab is closed or left in the background for 20 seconds. The hourly limit is held in memory, so it resets on restart and assumes a single server process.

**Endpoints**

- `GET /api/live/config` — whether live mode is enabled, plus the session limits
- `POST /api/live/token` — (login required) one-session client token
- `GET /api/live/garment?url=` — (login required) fetches a garment image for the browser; refuses private/internal addresses

Deep links work for store buttons: `/live.html?productUrl=<product page>` or `/live.html?productImage=<image URL>`.
