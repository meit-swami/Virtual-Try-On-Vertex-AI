/**
 * ZAHA Virtual Try-On — CMS embed loader
 * Usage: ZahaTryOn.init({ apiUrl, apiKey, productUrl, productImage, buttonText })
 */
(function () {
    'use strict';

    function init(config) {
        if (!config.apiUrl || !config.apiKey) {
            console.error('[ZAHA] apiUrl and apiKey are required');
            return;
        }

        const btn = document.createElement('button');
        btn.type = 'button';
        btn.textContent = config.buttonText || '✨ Virtual Try-On';
        btn.style.cssText =
            'padding:14px 24px;background:#38C1B7;color:#fff;border:none;border-radius:8px;font-weight:700;font-size:16px;cursor:pointer;width:100%;margin:12px 0;font-family:inherit;';
        btn.onmouseover = () => { btn.style.background = '#2da69a'; };
        btn.onmouseout = () => { btn.style.background = '#38C1B7'; };

        const params = new URLSearchParams({
            key: config.apiKey,
            api: config.apiUrl.replace(/\/$/, ''),
        });
        if (config.productUrl) params.set('productUrl', config.productUrl);
        if (config.productImage) {
            const img = String(config.productImage).trim();
            params.set('productImage', img.startsWith('//') ? 'https:' + img : img);
        }

        const embedUrl = config.apiUrl.replace(/\/$/, '') + '/embed.html?' + params.toString();

        btn.onclick = () => {
            const overlay = document.createElement('div');
            overlay.style.cssText =
                'position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:999999;display:flex;align-items:center;justify-content:center;padding:16px;';
            const frame = document.createElement('iframe');
            frame.src = embedUrl;
            frame.style.cssText =
                'width:min(720px,96vw);height:min(920px,94vh);border:none;border-radius:16px;background:#fff;box-shadow:0 24px 48px rgba(0,0,0,0.25);';
            const close = document.createElement('button');
            close.textContent = '×';
            close.style.cssText =
                'position:absolute;top:20px;right:20px;background:#fff;border:none;font-size:28px;cursor:pointer;width:40px;height:40px;border-radius:50%;';
            close.onclick = () => overlay.remove();
            overlay.appendChild(close);
            overlay.appendChild(frame);
            overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
            document.body.appendChild(overlay);
        };

        const target = config.target
            ? document.querySelector(config.target)
            : document.querySelector('[data-zaha-try-on]') || document.querySelector('.product-form') || document.querySelector('form[action*="/cart/add"]');

        if (target) {
            target.insertAdjacentElement(config.position === 'before' ? 'beforebegin' : 'afterend', btn);
        } else {
            console.warn('[ZAHA] No target found — append button manually');
            document.body.appendChild(btn);
        }
    }

    window.ZahaTryOn = { init };
})();
