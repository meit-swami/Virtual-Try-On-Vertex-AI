# ZAHA Shopify App — Setup & Submission Guide

This app is served by the main ZAHA Express server (routes under `/shopify/*`),
so you deploy one app, not two. It handles OAuth install, mandatory webhooks
(GDPR + uninstall), the Billing API, and a signed App Proxy that feeds the theme
block its API key automatically.

## 1. Create the app in the Partner Dashboard

1. partners.shopify.com → **Apps → Create app → Create app manually**.
2. Copy the **Client ID** and **Client secret** into your ZAHA env as
   `SHOPIFY_API_KEY` and `SHOPIFY_API_SECRET`.
3. Set `SHOPIFY_APP_URL` to your deployed HTTPS URL (e.g.
   `https://your-zaha-app.onrender.com`).

## 2. App URLs

- **App URL:** `{SHOPIFY_APP_URL}/shopify/auth`
- **Allowed redirection URL(s):** `{SHOPIFY_APP_URL}/shopify/auth/callback`

## 3. App Proxy (so merchants never paste an API key)

App setup → **App proxy**:

- **Subpath prefix:** `apps`
- **Subpath:** `zaha`  (must match the block's "App Proxy subpath" setting)
- **Proxy URL:** `{SHOPIFY_APP_URL}/shopify/proxy`

The theme block then calls `/apps/zaha/config`, Shopify signs it, and the ZAHA
server returns that shop's `apiKey` + `apiUrl`.

## 4. Mandatory compliance webhooks

These are auto-registered at install, but also declare them in the Partner
Dashboard (GDPR section) pointing at:

- `{SHOPIFY_APP_URL}/shopify/webhooks/customers-data-request`
- `{SHOPIFY_APP_URL}/shopify/webhooks/customers-redact`
- `{SHOPIFY_APP_URL}/shopify/webhooks/shop-redact`

App uninstall is handled at `{SHOPIFY_APP_URL}/shopify/webhooks/app-uninstalled`.

## 5. Billing (optional but required for a paid app)

Set `SHOPIFY_BILLING_ENABLED=true` plus `SHOPIFY_PLAN_PRICE` etc. After OAuth the
merchant is redirected to approve a recurring charge; on approval it is
activated. Use `SHOPIFY_BILLING_TEST=true` while developing so no real money
moves.

## 6. Theme App Extension (the on-storefront widget)

```bash
cd plugins/shopify
shopify app dev      # to develop
shopify app deploy   # to publish the extension version
```

Merchants add **ZAHA Virtual Try-On** as a block on the product page in the
Theme Editor. No key entry needed — it uses the App Proxy.

## 7. Install / test flow

Visit `{SHOPIFY_APP_URL}/shopify/auth?shop=your-dev-store.myshopify.com` to run
the OAuth install against a development store.

## 8. Submission checklist (App Store review)

- [ ] OAuth works and requests only the scopes it needs (`read_products`).
- [ ] All three GDPR webhooks + `app/uninstalled` respond 200 and verify HMAC.
- [ ] Billing flow works (test charge) if the app is paid.
- [ ] App Proxy returns config only for installed shops (signature verified).
- [ ] Listing assets, privacy policy URL, and support contact prepared.
- [ ] Test on a fresh development store end-to-end (install → block → try-on).
