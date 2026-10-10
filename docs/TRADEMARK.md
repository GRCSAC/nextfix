# NEXTFIX trademark: current plan and a prepared application

## Decision (2026-10-10): use the mark unregistered for now

NextFix is used as an unregistered trademark of GRCSAC LLC. In the United States rights in a
mark come from use in commerce, not from registration; registration adds nationwide
presumption of ownership and the ® symbol, which can be added later. Until then:

- Write **NextFix™** at the first mention on the website, in the README and in release notes
  (never ®, which is reserved for registered marks).
- Keep dated evidence of first public use and of continuous use: the first public GitHub
  release page, the website as it looked on launch day (a PDF print and the Wayback Machine
  capture), the launch post. Store copies under a `trademark/` folder outside the repository.
- Keep the name consistent everywhere: "NextFix" as the product, "NextFix by GRCSAC" where
  the owner matters, the same wordmark and logo.
- Watch for confusing use: a saved search for "nextfix" on the USPTO search system, npm,
  PyPI and GitHub every few months. If anyone files for a confusingly similar mark, that is
  the moment to file (and the prepared package below is the application).

### Filing later

When registration becomes worth the fee, file **use-based** (Section 1(a)) rather than
intent-to-use: the application fee is the same ($350 per class, $700 for both) but the $300
Statement of Use step never arises, and the specimens are the live website and release page.
Class 9 alone ($350) covers the software that ships; class 42 is optional insurance for a
hosted "NextFix" service.

## The prepared application

Everything below is ready to paste into the USPTO filing form. The filing itself must be done
by the applicant: USPTO.gov requires an account verified against a government ID, the
declaration is signed under penalty of perjury by the applicant or an authorised officer, and
the fee is paid at submission. Not legal advice; a trademark attorney can review before filing.

## Where

https://www.uspto.gov/trademarks/apply → "Apply online" → TEAS base application
(the 2025 single form; choose the standard application, not the "expanded" one, to keep the
per-class fee at the base rate).

## Mark

| Field | Value |
|---|---|
| Mark | **NEXTFIX** |
| Mark type | Standard character mark (word only, no stylisation, no colour claim) |
| Translation / transliteration | None |
| Disclaimer | None expected. If the examiner asks to disclaim "FIX", accept it; the mark as a whole remains protectable. |

A standard character filing protects the word in any font or design, which covers the logo
lock-up as well. A separate design-mark filing for the gradient N is optional and can wait.

## Applicant (owner)

| Field | Value |
|---|---|
| Owner name | GRCSAC LLC |
| Entity type | Limited liability company |
| State/country of organisation | New Jersey, United States |
| Mailing address | *(the LLC's address of record)* |
| Email for correspondence | paul@grcsac.com (or nextfix@grcsac.com) |
| Attorney | None required: a US-domiciled applicant may file without one |

## Filing basis

**Section 1(a), use in commerce**, once NextFix is publicly available: give the date of first
use (the first public release) and attach the specimens below with the application. Before
launch the basis would be Section 1(b), intent to use, with a Statement of Use ($150 per
class) after launch.

## Goods and services

Use the USPTO ID Manual wording as closely as possible (the form offers a search; pick the
closest pre-approved entry to keep the base fee).

**Class 9 — downloadable software**

> Downloadable computer software for identifying, analyzing, prioritizing and reporting
> security vulnerabilities in computer software applications; downloadable computer software
> for software composition analysis and for analyzing the reachability and exploitability of
> software vulnerabilities; downloadable computer software for generating vulnerability
> exploitability (VEX) reports.

**Class 42 — software and technology services**

> Providing online non-downloadable software for identifying, analyzing, prioritizing and
> reporting security vulnerabilities in computer software applications; software as a service
> (SaaS) services featuring software for vulnerability management and remediation
> prioritization; providing temporary use of online non-downloadable software for software
> composition analysis; computer security consultancy in the field of software vulnerability
> remediation.

Class 42 is worth keeping even for a free tool: the hosted dashboards and the website are
services, and it blocks a competitor from offering a "NextFix" service.

## Fees (2025 schedule)

| Item | Amount |
|---|---|
| Base application, per class | $350 |
| Two classes | **$700 at filing** |
| Statement of Use, per class (after launch) | $150 each, $300 total |
| Extension of time to file the Statement of Use, if needed, per class | $125 each |

Fees are not refundable if the application is refused.

## Timeline

- Filing receipt: immediate. Serial number arrives by email.
- First examination: roughly 6–8 months after filing.
- Publication for opposition: about a month after approval, 30-day window.
- Notice of Allowance: after publication for a 1(b) application. You then have 6 months
  (extendable up to 36) to file the Statement of Use with a specimen.
- Registration: a few months after the Statement of Use is accepted.

## Specimen (attached to a use-based application; at the Statement of Use stage for intent-to-use)

- Class 9: a screenshot of the download or installation page showing the mark next to the
  software and a way to obtain it (the GitHub releases page or nextfix.grcsac.com download
  section qualifies once live).
- Class 42: a screenshot of the running dashboard or the website page offering the service,
  showing the mark.

Keep dated screenshots from launch day.

## Declaration

The form ends with the standard declaration (that the applicant believes it is entitled to
use the mark, has a bona fide intent to use it, and that the statements are true). It is
signed electronically by Paul Zarou as a member/officer of GRCSAC LLC.

## After filing

1. Add the serial number to this file and to `docs/NAME-CHECK.md`.
2. Keep ™ (not ®) next to the name until registration issues, then switch to ®.
3. For an intent-to-use filing only: calendar the Statement of Use deadline when the Notice
   of Allowance arrives.
