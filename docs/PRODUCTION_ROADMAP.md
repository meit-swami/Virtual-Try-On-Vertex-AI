# ZAHA AI — Production Roadmap (Shopify App Store + WordPress.org)

This document tracks the plan to take ZAHA Virtual Try-On from a working demo to
a production, publicly-distributable system: a **Shopify App Store** app and a
**WordPress.org**-listed plugin, with a **full-fidelity 4K** try-on pipeline and
**per-merchant billing**.

## Guiding reality check

The try-on itself is done by **Google Vertex AI `virtual-try-on-001`**, a
*generative* model. It **cannot guarantee a literal 100%, pixel-perfect**
preservation of face, body, posture, expression, and background — no current
AI try-on can. Our fidelity pipeline gets as close as tooling allows
("visually identical"), and we set that expectation honestly with merchants.

---

## Phase 1 — Shared foundation ✅ (this PR)

Everything below is backend-shared by both plugins, so it comes first.

- **4K enhancement pipeline** (`src/enhance.ts`, `src/save-result.ts`)
  - Stage A: 4K super-resolution. Built-in sharp/Lanczos upscaler (always works)
    + optional Replicate Real-ESRGAN provider (detail-generating, face-enhance).
  - Graceful fallback: if the external provider fails, fall back to sharp, then
    to the raw image — a try-on never hard-fails on enhancement.
  - Wired into both the main app and plugin try-on routes.
- **Security hardening**
  - `helmet` security headers (configured to keep the embed iframe working).
  - Rate limiting (general + auth + try-on).
  - Configurable CORS allow-list (`ALLOWED_ORIGINS`).
  - Configurable DB TLS verification (`DATABASE_SSL_STRICT`).
  - Opt-in per-site domain enforcement for plugin API keys.
  - Production env validation warnings at startup.
- **Secret hygiene**: `.env` untracked from git (done earlier).

## Phase 2 — Fidelity pipeline: background & face lock-in ✅ (this PR)

Raise fidelity from "visually identical" toward "background/face preserved".

- **Shared Replicate client** (`src/replicate.ts`) — run/poll/download; used by
  all provider-backed stages. `enhance.ts` refactored onto it.
- **Stage B — background lock-in** (`src/fidelity.ts`): segment the person out
  of the generated result and composite them back onto the **original photo's
  background**, so the real background is preserved. Sharp compositing mechanics
  unit-tested.
- **Stage C — face restoration** (`src/fidelity.ts`): CodeFormer over the result
  to counter identity/expression drift (`FACE_RESTORE_FIDELITY` tunable).
- Pipeline order wired in `save-result.ts`: **bg-lock → face-restore → 4K**.
- Both stages require `REPLICATE_API_TOKEN`, are OFF by default, and degrade
  gracefully (each failure falls back to the previous best image).

### Phase 2 follow-ups (later)
- Clothing-region masking (SAM) for garment-only replacement as an alternative
  to full-person compositing.
- Quality gate: auto-reject/regenerate outputs that drift too far (face-embedding
  similarity + background diff thresholds).

## Phase 3 — Shopify App Store app

The current Shopify integration is a theme snippet only. A store-listed app needs:

- **Embedded app** (Remix/Node) with **OAuth** install, App Bridge, session
  tokens, Polaris admin UI.
- **Theme App Extension** (app block) — replaces the manual snippet; merchant
  adds the block in the theme editor, no code editing.
- **Shopify Billing API** — recurring subscription + usage charges (per-merchant
  billing).
- **Mandatory GDPR webhooks** (`customers/data_request`, `customers/redact`,
  `shop/redact`) and app/uninstall webhooks.
- Automatic per-shop **API key provisioning** at install (replaces manual key
  creation in admin-promos).
- App listing assets, privacy policy, and **App Store review** submission.

## Phase 4 — WordPress.org plugin

The current plugin is a functional single file. A .org-listed plugin needs:

- Split into proper structure (admin, public, includes), **i18n** (text domain +
  `.pot`), and WP coding standards.
- **Security**: nonces, capability checks, input sanitization/escaping, settings
  API best practices, a built-in "Test connection" button.
- **Block editor (Gutenberg) block** + shortcode + WooCommerce hook placement
  options.
- **Freemius or WooCommerce Subscriptions**-based billing for the paid tier.
- `readme.txt` (WordPress format), assets/screenshots, and **.org review**
  submission.

## Phase 5 — Billing & multi-tenant SaaS

- Merchant accounts, plans, metering of try-ons, invoices.
- Usage dashboards (per merchant + superadmin).
- Cost controls: quota enforcement, per-merchant Vertex spend caps.
- Keep the **promo-code credit** system for demos/trials alongside billing.

## Phase 6 — Scale & reliability

- Move `uploads/`/`outputs/` to object storage (S3/GCS) + CDN (Render disk is
  ephemeral and not multi-instance safe).
- Background job queue for try-on + enhancement (avoid long request timeouts).
- Observability: structured logging, error tracking, uptime/latency metrics.
- Automated tests + CI (GitHub Actions).

---

## New environment variables (Phase 1)

See `.env.example`. Summary: `NODE_ENV`, `COOKIE_SECURE`, `ALLOWED_ORIGINS`,
`RATE_LIMIT_PER_MIN`, `AUTH_RATE_LIMIT`, `TRYON_RATE_LIMIT_PER_MIN`,
`DATABASE_SSL_STRICT`, `DATABASE_CA_CERT`, `PLUGIN_DOMAIN_ENFORCEMENT`,
`UPSCALE_ENABLED`, `UPSCALE_PROVIDER`, `REPLICATE_API_TOKEN`,
`REPLICATE_UPSCALE_VERSION`.
