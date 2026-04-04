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
