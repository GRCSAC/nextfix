# Changelog

All notable changes to NextFix are recorded here. Version numbers come from the root
`package.json` (single source of truth) and are stamped into every report and VEX document.

## [Unreleased]

## [0.1.0] — 2026-10-09

### Added
- End-to-end spike: npm lockfile inventory → OSV advisories → EPSS/KEV enrichment →
  JavaScript call-graph and Express entry-point analysis → four-tier reachability →
  Docker exposure → SSVC-style decision → terminal table, JSON report, OpenVEX export.
- Curated vulnerable-symbol seed for lodash, express, minimist.
- Demo target `samples/express-shop` that exercises every reachability tier.
