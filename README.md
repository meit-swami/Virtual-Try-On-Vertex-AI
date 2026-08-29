# ZAHA AI — Virtual Try-On Web App

A full-stack web application that uses **Google Cloud Vertex AI** to generate virtual try-on images. Upload a photo of a person and a clothing/accessory product, and the AI generates a realistic image of the person wearing that product.

> **Live Demo:** Deployed on [Render](https://render.com) with PostgreSQL backend.

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [Database Setup](#database-setup)
- [Deployment (Render)](#deployment-render)
- [API Reference](#api-reference)
- [Links & Resources](#links--resources)

---

## Features

### Core — Virtual Try-On Generation
- Upload a **person image** and a **product image** (clothing, jewellery, eyewear, etc.)
- AI generates a photorealistic image of the person wearing the product using Google Vertex AI's `virtual-try-on-001` model
- Supports generating **1–4 sample outputs** per request
- Accepts images via file upload **or** direct URL (for product images)

### E-Commerce Product Extraction
- Paste any e-commerce product page URL (Myntra, Meesho, Flipkart, Amazon, etc.)
- The server scrapes the page and extracts the main product image automatically
- Uses multiple extraction strategies: Open Graph meta tags, JSON-LD structured data, site-specific selectors, and generic fallback heuristics
- Extracted image is used directly for virtual try-on

### Sample Closet (Landing Page)
- Browse pre-curated sample product images organized by category:
  - 👗 Sarees
  - ✨ Lehengas, Kurti & Ethnics
  - 💎 Jewellery
  - 👔 Shorts, Shirts, T-shirts & Formals (Men's Wear)
  - 🕶️ Eyewear
  - 🎩 Accessories (Belts, Ties, Hats, Brooch)
  - ⌚ Watches
  - 💄 Makeup Shades
- Click any sample to pre-fill it as the product image for try-on

### User Authentication & Accounts
- Email + password registration and login
- Passwords hashed with **bcrypt** (10 rounds)
- Session-based authentication using `express-session`
- Sessions persisted in PostgreSQL (via `connect-pg-simple`) for production reliability
- Role-based access: `user` and `superadmin`
- Auto-seeds a superadmin account (`superadmin@zaha.ai` / `admin123`) on first run if no users exist

### Try-On History
- Every generation is saved to the database with person image, product image, and result filenames
- Users can view their own past try-on results
- **Superadmin** can view all users' history (with creator email displayed)
- Delete individual results (removes files from disk and database record)
- Only owners or superadmin can delete results

### Subscription Plans (UI)
- Three-tier pricing page with monthly/yearly toggle:
  - **Small Enterprises** — ₹1,500/mo or ₹15,000/year (5 try-ons/month)
  - **Medium Enterprises** — ₹2,000/mo or ₹21,500/year (unlimited try-ons, HD output, e-commerce extraction)
  - **Large Enterprises** — ₹4,000/mo or ₹45,000/year (API access, bulk processing, dedicated support)
- eNach system noted for monthly billing

### Frontend UI/UX
- Single-page application with client-side routing (Home, Try On, Subscription, Login)
- Responsive design — works on desktop, tablet, and mobile
- Drag-and-drop image upload with preview
- Full-size image modal with zoom in/out controls
- In-progress spinner for background generation
- Real-time error display and status messages
- DB connection test button on login page (for debugging deployments)

### Image Handling
- Supports JPG, JPEG, PNG, GIF, WEBP formats
- Max file size: 10 MB
- Images stored on disk in `uploads/` (inputs) and `outputs/` (results)
- Files named with generation timestamp for uniqueness

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Node.js, Express 5, TypeScript |
| AI Model | Google Cloud Vertex AI (`virtual-try-on-001`) |
| Database | PostgreSQL (primary) or MySQL (alternative) |
| Auth | bcrypt, express-session, connect-pg-simple |
| File Upload | Multer |
| Web Scraping | Cheerio |
| Frontend | Vanilla HTML/CSS/JS (single-page app) |
| Deployment | Render (render.yaml blueprint) |

---

## Project Structure

```
├── public/
│   └── index.html          # Frontend SPA (HTML + CSS + JS)
├── src/
│   ├── index.ts            # Express server, API routes, Vertex AI integration
│   └── db.ts               # Database layer (PostgreSQL + MySQL dual support)
├── database/
│   ├── schema.pg.sql       # PostgreSQL schema
│   └── schema.sql          # MySQL schema
├── assets/                 # Sample person & product images
├── uploads/                # User-uploaded images (runtime)
├── outputs/                # AI-generated result images (runtime)
├── .env.example            # Environment variable template
├── render.yaml             # Render deployment blueprint
├── package.json
└── tsconfig.json
```

---

## Getting Started

```bash
# Clone the repository
git clone https://github.com/Ashot72/Virtual-Try-On-Vertex-AI
cd Virtual-Try-On-Vertex-AI

# Install dependencies
npm install

# Copy and configure environment variables
cp .env.example .env
# Edit .env with your Google Cloud project ID, database URL, etc.

# Place your Google Cloud service account key in the project root
# (or set GOOGLE_SERVICE_ACCOUNT_JSON env var for production)

# Build TypeScript
npm run build

# Start the server
npm start

# Or run in development mode (ts-node)
npm run dev
```

The app will be available at **http://localhost:3000**.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PROJECT_ID` | Google Cloud project ID |
| `LOCATION` | Vertex AI region (e.g. `us-central1`) |
| `DATABASE_URL` | PostgreSQL connection string (recommended) |
| `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` | MySQL config (alternative to DATABASE_URL) |
| `SESSION_SECRET` | Secret for express-session cookie signing |
| `GOOGLE_SERVICE_ACCOUNT_JSON` | Full JSON key content (for production/Render) |
| `SERVICE_ACCOUNT_KEY_PATH` | Path to service account key file (local dev) |
| `GOOGLE_APPLICATION_CREDENTIALS` | Absolute path to key file (alternative) |
| `PORT` | Server port (default: 3000) |
| `NODE_ENV` | Set to `production` for secure cookies |

---

## Database Setup

The app supports **PostgreSQL** (recommended) or **MySQL**.

### Option A — PostgreSQL (Render / Railway / Neon)

1. Create a PostgreSQL instance on your hosting provider.
2. Set `DATABASE_URL` in your environment.
3. Run the schema: `psql $DATABASE_URL -f database/schema.pg.sql`
4. On first startup with an empty `users` table, the app auto-creates `superadmin@zaha.ai` (password: `admin123`).

### Option B — MySQL

1. Leave `DATABASE_URL` unset.
2. Set `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`.
3. Run `database/schema.sql` in your MySQL instance.

### Free-Tier Postgres on Render

Render free Postgres instances expire after ~90 days. When that happens:
1. Create a new free PostgreSQL on Render.
2. Update `DATABASE_URL` on your web service to the new Internal Database URL.
3. Run `database/schema.pg.sql` on the new database.
4. Redeploy. Users and history start fresh.

---

## Deployment (Render)

The project includes a `render.yaml` blueprint:

```yaml
services:
  - type: web
    name: zaha-ai
    env: node
    buildCommand: npm install && npm run build
    startCommand: npm start
```

1. Push to GitHub.
2. Connect the repo on Render.
3. Add environment variables (PROJECT_ID, LOCATION, DATABASE_URL, SESSION_SECRET, GOOGLE_SERVICE_ACCOUNT_JSON).
4. Create a PostgreSQL instance and link it.
5. Run the schema SQL once, then deploy.

---

## API Reference

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register a new user (email + password) |
| POST | `/api/auth/login` | Login with email + password |
| GET | `/api/auth/me` | Get current authenticated user |
| POST | `/api/auth/logout` | Destroy session and logout |

### Virtual Try-On

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/virtual-try-on` | Generate try-on (multipart: personImage + productImage or productImageUrl) |
| POST | `/api/extract-product` | Extract product image URL from an e-commerce page |

### Results / History

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/results` | Get user's try-on history (superadmin sees all) |
| DELETE | `/api/results/:id` | Delete a try-on result by generation ID |

### Utility

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/test-db` | Test database connectivity |

---

## Links & Resources

- [Google Cloud Vertex AI](https://cloud.google.com/vertex-ai)
- [Virtual Try-On API Reference](https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/virtual-try-on-api)
- [Render Deployment Docs](https://docs.render.com)

---

## Credits

Made by **Brandzaha** with ❤️  
Designed and developed by **HIMANSHI SHRIVASTAV**
