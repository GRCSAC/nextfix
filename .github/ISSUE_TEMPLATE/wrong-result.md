---
name: Wrong result
about: NextFix missed an entry point, misread a guard, or claimed a path that is not there
title: ''
labels: analyzer
---

**What NextFix said**
Paste the finding's "why" lines or the entry point list (`nextfix scan <dir> --json out.json`).

**What is actually true**
The route / guard / call as it exists in the code, with file and line.

**Framework and version**
Express / Fastify / Koa / other, and the NextFix version (`nextfix --version`).

**Minimal reproduction**
A small app that shows the problem is ideal; a snippet of the registration and handler is fine.
