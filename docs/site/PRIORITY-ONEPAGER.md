# "How NextFix decides" one-pager: web hand-off

A page for nextfix.grcsac.com that explains, in one screen, how NextFix turns a scanner's
list into four decisions, and why most findings can wait. The reference build is
`priority-onepager.html` in this folder: a self-contained page in the brand palette, light and
dark, phone to desktop, print-ready. Lift its structure and copy as they are; restyle to the
site's own shell (header, footer, fonts) rather than embedding the file.

Suggested URL: `/how-it-decides/`. Link it from the home page ("How it decides →"), from the
product page's decision section, and from the footer. The same page is the download behind a
"Print the one-pager" button (the reference build has print styles for one tall sheet).

## Structure, top to bottom

1. **Header.** Wordmark (NextFix™ at the first mention), tagline FIND › PRIORITIZE › FIX › PROVE,
   the H1 and the lede. To the right, the four-decision key (colour + icon + label + two-word
   meaning). The key repeats the product's own colours and icons, so a reader who then opens
   the dashboard sees the same language.
2. **Three questions**, side by side with chevrons between them: Reachable? Exposed? Exploited?
   Each card has a one-line question and three or four bullets naming the signals. Reachable is
   blue, Exposed is cyan, Exploited is red (the bullet squares), which is the order of weight.
3. **The reachability ladder.** Seven rungs left to right, from "Not shipped" to "Reachable",
   each with a two-line description and the decision it defaults to. Under them a single
   gradient bar (blue → cyan → amber → red) with three labels: Audit-defensible evidence,
   Worth watching, Action. The bar is the whole argument in one glance.
4. **The four decisions**, one card each in the product colours: when it applies (the rule,
   with the key words in bold) and what it means in a sentence.
5. **Why most findings can wait** (left, five numbered reasons) beside **What moves a finding**
   (right: five lifts, five holds, and the one rule that outranks every hold). Numbers on the
   reasons are deliberate: they are the order a reader should argue them in.
6. **Footer.** The score only orders findings inside a decision; the data sources; the trademark
   line; nextfix.grcsac.com · Apache-2.0 · free.

## Copy (verbatim; keep the wording)

### H1 and lede

**How NextFix decides what to fix next**

Scanners find. NextFix decides. Every vulnerability a scanner reports is asked three questions
about *your* application, then lands in one of four decisions with its evidence attached. Most
findings can wait, and the page says exactly why.

### Four decisions (key)

- ▲ **Fix now** · out of cycle
- ● **Fix next cycle** · tell the owner
- ◐ **Watch** · re-check on new data
- ○ **Set aside with evidence** · VEX for the auditor

### 1 · Reachable?

Can a request from outside actually run the vulnerable code?

- **Is it shipped?** Development-only packages never leave the build.
- **Is it imported?** Installed is not the same as used.
- **Is the vulnerable function called?** One bad function in a library of hundreds.
- **Does an entry point lead there?** The route, its auth guard, and whether request data
  reaches the call.

### 2 · Exposed?

How close is an attacker to that route?

- **Without a login** or behind one.
- **Network-published:** Dockerfile, compose, the listen address.
- **Internet-facing:** infrastructure files, or a declaration.
- **Observed traffic:** the access logs, last 30 days, public versus internal addresses.

### 3 · Exploited?

Is anyone attacking this in the wild?

- **Active:** on CISA's Known Exploited Vulnerabilities list.
- **Likely:** EPSS gives it a 10% or higher chance of exploitation within 30 days.
- **None yet:** severity alone, which is the weakest signal of the three.

### The reachability ladder: seven rungs from "found" to "matters"

Each rung is a fact about your code, checked in order. A finding stops at the first rung it fails.

| Rung | Description | Default |
|---|---|---|
| Not shipped | A development dependency; it is not in the production artifact. | Set aside |
| Never imported | Installed by the lockfile, but no source file loads it. | Set aside |
| Imported, never called | The package is used, the vulnerable function is not. | Set aside |
| No function data yet | Imported, but which function is vulnerable is still unknown, so it cannot be ruled out. | Watch |
| Called, unreached | The function is called, but no HTTP route leads to that code. | Watch |
| In the image only | An OS package or tool in the container; the application never imports it. | Watch · next cycle with a fix |
| Reachable | An entry point leads to the vulnerable call. Now exposure and exploitation decide. | Fix now · next cycle |

Bar labels: Audit-defensible evidence · Worth watching · Action.

### The four decisions

**Fix now** (Act · out of cycle). Reachable **without a login**, and any of: known or likely
exploitation, CVSS 9 or higher, request data reaching a high-severity call, or the internet
already calling that route. Reachable **behind a login** only when exploitation is active.
*An attacker has a path, a door, and a reason. Nothing else on the list is this.*

**Fix next cycle** (Attend · tell the owner). Reachable, but **behind a login**, or without
exploitation evidence. Also: no function data yet with exploitation or high severity, or an
image package with a fix and a reason to move. *Real, but the door is smaller or nobody is
pushing on it. It goes in the next release, not tonight's hotfix.*

**Watch** (Track* · re-check). Called but **no route reaches it**; imported with **no function
data**; or in the container image with no fix to move to. *Re-decided every night with fresh
exploit data, and again when the code changes. It rises the moment the facts do.*

**Set aside with evidence** (Track · VEX). Not shipped, never imported, or the vulnerable
function is **never called**. Or a person accepted it, with a reason, an approver and an
expiry. *Exported as an OpenVEX statement with the standard justification, so the auditor gets
the reason, not a shrug.*

### Why most findings can wait

Severity scores describe the worst case for anyone. NextFix describes the actual case for you.

1. **A critical score in code you never run is noise.** Eighty to ninety-nine percent of
   findings on real applications are in packages that are not shipped, not imported, or whose
   vulnerable function is never called. They are set aside with the proof.
2. **Behind a login is a smaller door.** An attacker needs credentials first. The finding is
   still fixed, in the next cycle, unless it is being exploited in the wild.
3. **Nobody is calling it, yet.** Thirty days of access logs with no request to any route that
   reaches the call holds a severity-only "fix now" at "next cycle". The first request, or new
   exploit data, lifts it back.
4. **Not on the internet.** A service the infrastructure files, or the logs, show as internal
   only has an internal attacker surface. An open route there waits a cycle; the same route on
   the internet does not.
5. **No fix to move to.** A finding with no published fix is watched and mitigated at the entry
   point rather than scheduled, so the queue holds work someone can actually do.

### What moves a finding

The same evidence that lets things wait also pulls things forward.

Lifts it: **Known exploitation** (CISA KEV) or EPSS at 10% or more · **No login** on the route
that reaches the call · **Request data** traced into the vulnerable call's arguments ·
**Public traffic** observed on that route in the last 30 days · **Internet-facing** per
infrastructure files or a declaration.

Holds it: **Behind a login**, or treated as internal in the project config · **Nobody called
it** in a month of logs that cover this service · **Internal only**: the internet cannot reach
the service · **Loopback only**: the service binds to the local host · **A person accepted
it**, with a reason and an expiry.

**One rule outranks every hold:** known or likely exploitation keeps a reachable finding at Fix
now. Quiet routes and internal networks lower the bar for severity, never for evidence of attack.

### Footer

**The score (0 to 100) only orders findings inside a decision; it never changes one.** Every
decision carries its "why" in plain words: the route, the call, the guard, the traffic, the
exploit data, the fix. Data: OSV advisories, FIRST EPSS, CISA KEV, your own logs and
infrastructure files. Nothing leaves your machine but those lookups.

nextfix.grcsac.com · Apache-2.0 · free · NextFix and the NextFix logo are trademarks of GRCSAC LLC.

## Design notes

- Palette and decision colours are the brand's (`docs/BRAND.md`): Fix now Vivid Red, Fix next
  cycle Amber, Watch Neon Cyan, Set aside Electric Blue, on Midnight/Navy in dark and on white
  in light. Colour never carries meaning alone: every decision has its icon (▲ ● ◐ ○) and label.
- The reference build uses Sora for headings and Inter for body (the brand sheet). The site's
  font decision stands; if it stays system-only, the GRCSAC stacks are fine.
- The ladder's gradient bar is the one visual that must survive any restyle: blue to cyan to
  amber to red, left to right, with the three labels under it.
- Keep the five reasons numbered and the lifts/holds as two columns with up and down markers.
- Every number on the page is backed by the repository: the rules are `docs/DECISION-MODEL.md`
  §4 and §5a; "eighty to ninety-nine percent" is the README validation table (80% to 99% set
  aside or watched across the five sample applications).
- Do not say: scanner, guaranteed, zero false positives, or any claim the repository cannot back (see
  `docs/WEB-HANDOFF.md` §7).

## Files

- `priority-onepager.html`: the reference page (self-contained; the two Google Fonts links are
  the only external requests, drop them for a system-font build).
- `docs/brand/logo.svg`, `docs/brand/brand-sheet.png`: the mark and the sheet.
