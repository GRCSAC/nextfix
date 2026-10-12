import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discoverLinks, imageTail, isExternalHost, urlsIn } from './links.ts';
import { analyzeInfra, applyInfra, hclResources } from './infra.ts';
import { walkProject } from './files.ts';
import type { Exposure } from '../types.ts';

const FIXTURE = fileURLToPath(new URL('../../test-fixtures/deploy-app/', import.meta.url));

test('walkProject skips dependency folders and dotfolders, honours ignore, caps depth', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nextfix-walk-'));
  mkdirSync(join(dir, 'node_modules', 'x'), { recursive: true });
  mkdirSync(join(dir, '.hidden'), { recursive: true });
  mkdirSync(join(dir, 'skipme'), { recursive: true });
  mkdirSync(join(dir, 'a', 'b', 'c', 'd', 'e', 'f'), { recursive: true });
  writeFileSync(join(dir, 'node_modules', 'x', '.env'), 'X=1');
  writeFileSync(join(dir, '.hidden', 'y.yaml'), 'a: 1');
  writeFileSync(join(dir, 'skipme', 'z.yaml'), 'a: 1');
  writeFileSync(join(dir, 'a', 'b', 'c', 'd', 'e', 'f', 'deep.yaml'), 'a: 1');
  writeFileSync(join(dir, '.env'), 'A=1');
  writeFileSync(join(dir, 'a', 'k.yaml'), 'a: 1');
  const rel = walkProject(dir, { ignore: ['skipme'] }).map((f) => f.rel);
  assert.deepEqual(rel, ['.env', 'a/k.yaml']);
  assert.equal(walkProject(dir).find((f) => f.name === '.env')?.ext, 'env');
});

test('links: compose, Kubernetes, env and config files name the services this application calls, and the names it answers to', () => {
  const links = discoverLinks(FIXTURE, { projectName: 'shop-api', images: ['ghcr.io/acme/shop-api:1.4'] });
  assert.deepEqual(links.identity.names, ['deploy-app', 'shop', 'shop-api']);
  assert.deepEqual(links.identity.hosts, ['shop.acme.com']);
  const byHost = Object.fromEntries(links.outbound.map((l) => [l.host, l]));
  // compose: depends_on, service names in environment values, URLs in environment values
  assert.equal(byHost.billing?.kind, 'compose');
  assert.equal(byHost.billing?.port, 8080, 'the URL form carries the port');
  assert.equal(byHost.db?.evidence, 'docker-compose.yml: services.shop.depends_on db');
  assert.equal(byHost.search?.evidence, 'docker-compose.yml: services.shop.environment: SEARCH_HOST=search');
  assert.equal(byHost['api.stripe.com']?.external, true);
  // Kubernetes: container env
  assert.equal(byHost['inventory.default.svc.cluster.local']?.kind, 'kubernetes');
  assert.equal(byHost['inventory.default.svc.cluster.local']?.external, false, 'cluster-local suffix is ours');
  assert.equal(byHost['smtp.sendgrid.net']?.external, true);
  // .env: URLs and *_HOST keys; PUBLIC_URL names ourselves; localhost and templated values are skipped
  assert.equal(byHost['payments.internal.acme.com']?.kind, 'env');
  assert.equal(byHost['payments.internal.acme.com']?.external, true, 'a dotted public-looking domain counts as external even with "internal" inside it');
  assert.equal(byHost['cache.acme.internal']?.external, false);
  assert.equal(byHost['o1.ingest.sentry.io']?.external, true);
  assert.equal(byHost.localhost, undefined);
  assert.equal(Object.keys(byHost).some((h) => h.includes('$')), false);
  // config: URLs in JSON; example.com is a placeholder
  assert.equal(byHost['plausible.io']?.kind, 'config');
  assert.equal(byHost['warehouse.acme.internal']?.port, 5432);
  assert.equal(byHost['example.com'], undefined);
  // our own names never appear as links
  assert.equal(byHost['shop.acme.com'], undefined);
  assert.equal(byHost['shop-api'], undefined);
  // internal services sort before external ones
  const firstExternal = links.outbound.findIndex((l) => l.external);
  assert.ok(links.outbound.slice(firstExternal).every((l) => l.external));
});

test('link helpers', () => {
  assert.equal(imageTail('ghcr.io/acme/shop-api:1.4'), 'shop-api');
  assert.equal(imageTail('postgres'), 'postgres');
  assert.equal(imageTail('registry:5000/x/y@sha256:abc'), 'y');
  assert.deepEqual(urlsIn('see http://a:3000/x and postgres://u:p@db.internal:5432/db'), [{ host: 'a', port: 3000 }, { host: 'db.internal', port: 5432 }]);
  assert.equal(isExternalHost('billing'), false);
  assert.equal(isExternalHost('billing.svc.cluster.local'), false);
  assert.equal(isExternalHost('api.stripe.com'), true);
  assert.equal(isExternalHost('10.0.0.5'), false);
});

test('infra: Terraform, CloudFormation, Kubernetes and compose bindings decide internet reach with file evidence', () => {
  const r = analyzeInfra(FIXTURE);
  assert.equal(r.reach, 'internet');
  assert.ok(r.internet.includes('infra/main.tf: aws_security_group "web" allows 0.0.0.0/0 on port 443'), r.internet.join('\n'));
  assert.ok(r.internet.includes('infra/main.tf: aws_lb "shop" is internet-facing'));
  assert.ok(r.internal.includes('infra/main.tf: aws_lb "admin" is internal'));
  assert.ok(r.internet.includes('infra/stack.yaml: Sg allows 0.0.0.0/0 on port 80'));
  assert.ok(r.internal.includes('infra/stack.yaml: Alb (AWS::ElasticLoadBalancingV2::LoadBalancer) is internal'));
  assert.ok(r.internet.includes('k8s/deploy.yaml: Ingress shop for shop.acme.com'));
  assert.ok(r.internal.includes('docker-compose.yml: services.shop publishes port 3000 on loopback only'));
  assert.equal(r.evidence.length, 4, 'the first four internet signals are quoted');

  // A declaration outranks the files, both ways.
  assert.equal(analyzeInfra(FIXTURE, { declared: false }).reach, 'internal');
  assert.equal(analyzeInfra(FIXTURE, { declared: false }).evidence[0], 'nextfix.config.json: internetFacing is false');
  assert.equal(analyzeInfra(FIXTURE, { declared: true }).evidence[0], 'nextfix.config.json: internetFacing is true');

  // Internal signals alone say internal; nothing says unknown.
  const dir = mkdtempSync(join(tmpdir(), 'nextfix-infra-'));
  writeFileSync(join(dir, 'compose.yaml'), 'services:\n  api:\n    build: .\n    ports:\n      - "127.0.0.1:8080:8080"\n');
  const only = analyzeInfra(dir);
  assert.equal(only.reach, 'internal');
  assert.deepEqual(only.evidence, ['compose.yaml: services.api publishes port 8080 on loopback only']);
  writeFileSync(join(dir, 'compose.yaml'), 'services:\n  api:\n    build: .\n    ports:\n      - "8080:8080"\n');
  assert.equal(analyzeInfra(dir).reach, 'unknown');
  writeFileSync(join(dir, 'Procfile'), 'web: node server.js\n');
  const paas = analyzeInfra(dir);
  assert.equal(paas.reach, 'internet');
  assert.deepEqual(paas.evidence, ['Procfile: web process for a hosting platform']);

  const x: Exposure = { network: 'published', ports: [3000], evidence: [] };
  applyInfra(x, paas);
  assert.equal(x.reach, 'internet');
  applyInfra(x, { reach: 'unknown', evidence: [], internet: [], internal: [] });
  assert.equal(x.reach, 'internet', 'unknown never overwrites a verdict');
});

test('hclResources: brace counting survives strings and comments', () => {
  const text = `resource "aws_lb" "a" {\n  name = "x}" # } in a comment\n  tags = { team = "web" }\n}\nresource "aws_lb" "b" {\n  internal = true\n}\n`;
  const rs = hclResources(text);
  assert.deepEqual(rs.map((r) => r.name), ['a', 'b']);
  assert.ok(rs[0]!.body.includes('tags = { team = "web" }'));
  assert.ok(!rs[0]!.body.includes('internal = true'));
});
