// Renders the project wordmark (logo mark + "EUDI Dev Wallet") into
// docs/assets as PNGs: a banner card, the bare wordmark on a transparent
// background, and a 1200x630 card for social posts. Light and dark of each.
// The README uses the mark alone (docs/assets/logo-mark.svg), not these.
//
// Run it with `node scripts/render-logo.js`. It borrows the Playwright
// installed for the end-to-end tests (`cd e2e && npm install` if missing).
//
// The source of truth stays docs/assets/logo-mark.svg. Re-run this after
// changing it.
const { createRequire } = require('module');
const fs = require('fs');
const path = require('path');

const { chromium } = createRequire(path.join(__dirname, '../e2e/'))('@playwright/test');

const repo = path.resolve(__dirname, '..');
const out = path.join(repo, 'docs/assets');
const rawMark = fs.readFileSync(path.join(out, 'logo-mark.svg'), 'utf8');
const mark = (w) =>
  rawMark.replace(/width="46"\s+height="51"/, `width="${w}" height="${Math.round((w * 51) / 46)}"`);

function page({ text, bg, cardBg, cardBorder, radius, markWidth, nameSize, gap, pad }) {
  return `<!doctype html><html><head><meta charset="utf-8"><style>
    * { margin:0; padding:0; box-sizing:border-box; }
    html, body { background: ${bg}; height:100%; }
    body { display:flex; align-items:center; justify-content:center; }
    /* The light card needs an edge, otherwise it dissolves into a white page. */
    .wrap { display:flex; align-items:center; gap:${gap}px; padding:${pad};
      background:${cardBg || 'transparent'}; border-radius:${radius || 0}px;
      border:${cardBorder && cardBorder !== 'transparent' ? `2px solid ${cardBorder}` : 'none'}; }
    .mark { flex:0 0 auto; display:flex; }
    /* Centring on the mark's box puts the word too high: the wallet body is
       the visual mass, the card above it is an accent. The nudge drops the
       word onto the body, and covers the descender space "EUDI Dev Wallet"
       never uses. */
    .name { font-family:"SF Mono","Menlo","Cascadia Code",monospace; font-size:${nameSize}px;
      font-weight:600; letter-spacing:-1px; color:${text}; line-height:1; white-space:nowrap;
      position:relative; top:${Math.round(nameSize * 0.1)}px; }
  </style></head><body>
    <div class="wrap" id="shot">
      <div class="mark">${mark(markWidth)}</div>
      <div class="name">EUDI Dev Wallet</div>
    </div>
  </body></html>`;
}

const wordmark = { markWidth: 220, nameSize: 104, gap: 40 };

// The wallet UI's two themes, so the logo matches the product either way.
const dark = { text: '#c0caf5', surface: '#1a1b26', border: 'transparent' };
const light = { text: '#24283b', surface: '#ffffff', border: '#d0d0d0' };

(async () => {
  const browser = await chromium.launch();

  for (const variant of [
    // Banner cards, content-sized with rounded corners. The README uses the
    // bare mark, these are for posts and slides.
    { file: 'logo-banner-dark.png', theme: dark, card: true },
    { file: 'logo-banner-light.png', theme: light, card: true },
    // The same wordmark without a card, to drop on your own background.
    { file: 'logo-wordmark-dark.png', theme: dark, card: false },
    { file: 'logo-wordmark-light.png', theme: light, card: false },
  ]) {
    const p = await browser.newPage({ viewport: { width: 1800, height: 600 }, deviceScaleFactor: 2 });
    await p.setContent(page({
      ...wordmark,
      text: variant.theme.text,
      bg: 'transparent',
      cardBg: variant.card ? variant.theme.surface : null,
      cardBorder: variant.card ? variant.theme.border : null,
      radius: variant.card ? 28 : 0,
      pad: variant.card ? '64px 90px' : '36px 44px',
    }));
    await p.locator('#shot').screenshot({ path: path.join(out, variant.file), omitBackground: true });
    await p.close();
  }

  // Social cards: the wordmark in the 1200x630 frame link previews expect,
  // filling it rather than floating in the middle of it.
  for (const variant of [
    { file: 'logo-social-dark.png', theme: dark },
    { file: 'logo-social-light.png', theme: light },
  ]) {
    const p = await browser.newPage({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: 2 });
    await p.setContent(page({
      text: variant.theme.text, bg: variant.theme.surface,
      markWidth: 215, nameSize: 100, gap: 38, pad: '0',
    }));
    await p.screenshot({ path: path.join(out, variant.file) });
    await p.close();
  }

  await browser.close();
  console.log('wrote banner, wordmark and social variants (light and dark) to docs/assets');
})();
