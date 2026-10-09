# NextFix brand

Source of truth for the product UI and the website. The approved brand sheet is
`docs/brand/brand-sheet.png`; the working logo is `docs/brand/logo.svg`.

**Wordmark:** `Next` in white (ink) + `Fix` in Electric Blue. Mark: a bold gradient "N"
whose diagonal reads as a forward chevron.

**Tagline:** FIND › PRIORITIZE › FIX › PROVE
**Positioning line:** From findings to fixes. / Security remediation, made clear.
**Essence:** Clarity · Prioritization · Remediation · Evidence

## Palette

| Name | Hex | Use |
|---|---|---|
| Midnight | `#0B1220` | page background, depth |
| Navy | `#0F1F3D` | surfaces, navigation |
| Electric Blue | `#3B82F6` | primary actions, "Fix" in the wordmark, set-aside bucket |
| Neon Cyan | `#22D3EE` | highlights, data accents, watch bucket |
| Amber | `#F59E0B` | warnings, fix-next-cycle bucket |
| Vivid Red | `#EF4444` | critical, fix-now bucket |
| Slate | `#94A3B8` | secondary text, borders |

Decision colours in the product (validated for colour-vision deficiency against Navy):

| Decision | Colour |
|---|---|
| Act · Fix now | Vivid Red |
| Attend · Fix next cycle | Amber |
| Track · Set aside with evidence | Electric Blue |
| Track* · Watch | Neon Cyan |

Bars and rings draw them in the order red, amber, blue, cyan so adjacent hues stay distinct.
Every colour is paired with an icon and a label; colour never carries meaning alone.

## Typography

Brand sheet: **Sora** for headings (700 / 600 / 500), **Inter** for body (400 / 500 / 600).

The product UI currently uses the GRCSAC system stacks (`--sans`), which keeps the app
free of font downloads. If Sora and Inter are wanted in the app, they must be bundled
with it, never loaded from a CDN. The website decision (webfonts vs. system stacks) is
the web team's call with Paul; the rest of `*.grcsac.com` is system-only.

## Icon language

Clean line icons, 1.8px stroke, rounded joins: scan, triage, risk, fix, metrics, assets,
evidence, secure. The product ships its own set in `packages/web/src/components/Icons.tsx`.

## Website hand-off

The web team receives: this file, `docs/brand/brand-sheet.png`, `docs/brand/logo.svg`,
and the three marketing mock-ups Paul holds (hero, square social, laptop landing).
Live product screenshots come from `npm run serve` on `samples/express-shop`.
Site lives at **nextfix.grcsac.com** (Cloudflare Pages, same pattern as the other GRCSAC
product sites: a `404.html`, no `immutable` asset caching, no third-party trackers).
