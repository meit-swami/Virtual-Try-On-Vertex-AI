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
cp env.example .env

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

**Option B – MySQL (PlanetScale, Railway, or local)**

1. Leave `DATABASE_URL` **unset**.
2. Set `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` in your environment (see `.env.example`).
3. Run `database/schema.sql` in your MySQL (e.g. PlanetScale Console, phpMyAdmin, or `mysql` CLI).
4. Redeploy and test.

📺 **Video:** [Watch on YouTube](https://youtu.be/CE-kl2thPXg)
