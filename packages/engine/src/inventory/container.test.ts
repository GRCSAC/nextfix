import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { detectSbomFiles, dockerSyftArgs, findOnPath, findSyft, mapPackage, parsePurl, parseSbom, readContainerInventory, runSyft } from './container.ts';
import { compareDistroVersion } from '../vulns/distro-version.ts';
import { compareVersions, isDistro, osvQueryable, osvVersion } from '../vulns/ecosystems.ts';
import { decide } from '../decide/ssvc.ts';
import { fixCommandFor } from '../report/ticket.ts';
import type { Advisory, Component, Finding } from '../types.ts';

const FIXTURES = fileURLToPath(new URL('../../test-fixtures/sbom/', import.meta.url));
const FAKE_SYFT_DIR = join(FIXTURES, 'fake-syft');
const read = (name: string) => readFileSync(join(FIXTURES, name), 'utf8');

test('purl parsing handles scopes, qualifiers, encoding and subpaths', () => {
  const p = parsePurl('pkg:deb/debian/libc6@2.36-9%2Bdeb12u4?arch=amd64&distro=debian-12&upstream=glibc#sub/path')!;
  assert.equal(p.type, 'deb');
  assert.equal(p.namespace, 'debian');
  assert.equal(p.name, 'libc6');
  assert.equal(p.version, '2.36-9+deb12u4');
  assert.deepEqual(p.qualifiers, { arch: 'amd64', distro: 'debian-12', upstream: 'glibc' });
  const npm = parsePurl('pkg:npm/%40babel/core@7.22.5')!;
  assert.equal(npm.namespace, '@babel');
  assert.equal(npm.name, 'core');
  assert.equal(npm.version, '7.22.5');
  const go = parsePurl('pkg:golang/github.com/foo/bar@v1.2.3')!;
  assert.equal(go.namespace, 'github.com/foo');
  assert.equal(go.name, 'bar');
  assert.equal(parsePurl('not a purl'), undefined);
});

test('packages map to the OSV ecosystem that answers for them', () => {
  const m = (purl: string, type?: string) => mapPackage({ purl, type })!.component;
  const deb = m('pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl');
  assert.equal(deb.ecosystem, 'Debian:12');
  assert.equal(deb.name, 'openssl', 'queried by source package');
  assert.equal(deb.path, 'libssl3', 'binary package kept as the location');
  assert.equal(deb.origin, 'image');
  assert.equal(m('pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.12?distro=ubuntu-22.04').ecosystem, 'Ubuntu:22.04:LTS');
  assert.equal(m('pkg:deb/ubuntu/openssl@3.0.2?distro=ubuntu-23.10').ecosystem, 'Ubuntu:23.10');
  assert.equal(m('pkg:deb/debian/openssl@3.0.2').ecosystem, 'Debian', 'no release known → unversioned');
  assert.equal(m('pkg:apk/alpine/libssl3@3.1.4-r0?distro=alpine-3.18.4&upstream=openssl').ecosystem, 'Alpine:v3.18');
  assert.equal(m('pkg:apk/wolfi/openssl@3.1.4-r0?distro=wolfi-20230201').ecosystem, 'Wolfi');
  const rpm = m('pkg:rpm/almalinux/openssl-libs@3.0.7-16.el9_2?arch=x86_64&epoch=1&distro=almalinux-9.2&upstream=openssl-3.0.7-16.el9_2.src.rpm');
  assert.equal(rpm.ecosystem, 'AlmaLinux:9');
  assert.equal(rpm.name, 'openssl');
  assert.equal(rpm.version, '1:3.0.7-16.el9_2', 'epoch folded into the version');
  assert.equal(m('pkg:rpm/fedora/openssl@3.0.7?distro=fedora-39').ecosystem, 'generic', 'no OSV source → not queried');
  const scoped = m('pkg:npm/%40babel/core@7.22.5');
  assert.equal(scoped.name, '@babel/core');
  assert.equal(scoped.purl, 'pkg:npm/%40babel/core@7.22.5');
  const py = m('pkg:pypi/Requests@2.31.0');
  assert.equal(py.ecosystem, 'PyPI');
  assert.equal(py.name, 'requests');
  assert.equal(py.purl, 'pkg:pypi/requests@2.31.0');
  const go = m('pkg:golang/gopkg.in/yaml.v3@v3.0.0');
  assert.equal(go.ecosystem, 'Go');
  assert.equal(go.name, 'gopkg.in/yaml.v3');
  assert.equal(osvVersion('Go', go.version), '3.0.0');
  assert.equal(m('pkg:golang/stdlib@1.21.0').version, '1.21.0');
  assert.equal(m('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1').name, 'org.apache.logging.log4j:log4j-core');
  assert.equal(m('pkg:generic/node@18.17.1', 'binary').ecosystem, 'generic');
  assert.equal(mapPackage({ name: 'x' }), undefined, 'no version → dropped');
});

test('CycloneDX: OS detected, binary packages of one source merge, locations kept', () => {
  const sbom = parseSbom(read('image.cdx.json'));
  assert.equal(sbom.format, 'cyclonedx');
  assert.equal(sbom.os, 'debian 12');
  const names = sbom.components.map((c) => `${c.ecosystem}:${c.name}@${c.version}`);
  assert.ok(names.includes('Debian:12:openssl@3.0.11-1~deb12u2'));
  assert.ok(names.includes('Debian:12:glibc@2.36-9+deb12u4'));
  assert.ok(names.includes('npm:lodash@4.17.15'));
  assert.ok(names.includes('npm:@babel/core@7.22.5'));
  assert.ok(names.includes('PyPI:requests@2.31.0'));
  assert.ok(names.includes('Go:gopkg.in/yaml.v3@v3.0.0'));
  assert.ok(names.includes('generic:node@18.17.1'));
  assert.ok(!names.some((n) => n.includes('operating-system')));
  const lodash = sbom.components.find((c) => c.name === 'lodash')!;
  assert.equal(lodash.path, '/app/node_modules/lodash/package.json');
  assert.equal(lodash.packageType, 'npm');
});

test('SPDX: purls from externalRefs, OS package skipped, packages without purl or version dropped', () => {
  const sbom = parseSbom(read('image.spdx.json'));
  assert.equal(sbom.format, 'spdx');
  assert.equal(sbom.os, 'alpine 3.18.4');
  const alpine = sbom.components.filter((c) => c.ecosystem === 'Alpine:v3.18');
  assert.deepEqual(alpine.map((c) => c.name).sort(), ['busybox', 'openssl', 'openssl'], 'libssl3 and libcrypto3 both map to openssl before merging');
  assert.equal(sbom.components.find((c) => c.ecosystem === 'AlmaLinux:9')?.version, '1:3.0.7-16.el9_2');
  assert.ok(sbom.components.some((c) => c.name === 'no-purl' && c.ecosystem === 'generic'), 'a package without purl is still listed, unqueried');
});

test('Grype report: artifacts are read once each, distro from the report', () => {
  const sbom = parseSbom(read('grype.json'));
  assert.equal(sbom.format, 'grype');
  assert.equal(sbom.os, 'debian 12');
  assert.deepEqual(sbom.components.map((c) => c.name), ['openssl', 'lodash']);
});

test('unreadable SBOMs are reported, not thrown', () => {
  assert.throws(() => parseSbom('{"hello": 1}'), /not a CycloneDX, SPDX or Grype/);
  assert.throws(() => parseSbom('nope'), /not valid JSON/);
});

test('inventory merges the same source package across binary packages and across files', async () => {
  const inv = await readContainerInventory(FIXTURES, { sboms: ['image.cdx.json', 'grype.json', 'missing.json'] });
  assert.equal(inv.images.length, 3);
  assert.equal(inv.images[0]!.source, 'cyclonedx');
  assert.equal(inv.images[0]!.os, 'debian 12');
  assert.equal(inv.images[0]!.unqueried, 1, 'the node binary');
  assert.equal(inv.images[1]!.components, 0, 'everything in the grype report was already seen');
  assert.match(inv.images[2]!.error ?? '', /ENOENT|no such file/i);
  const openssl = inv.components.find((c) => c.name === 'openssl')!;
  assert.equal(openssl.ecosystem, 'Debian:12');
  assert.deepEqual(openssl.paths, ['libssl3', 'openssl']);
  assert.equal(openssl.image, 'image.cdx.json');
});

test('SBOM files at the project root are picked up by name', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nextfix-sbom-'));
  for (const n of ['app.cdx.json', 'app.spdx.json', 'sbom.json', 'bom.json', 'report.json', 'cdx.json']) writeFileSync(join(dir, n), '{}');
  assert.deepEqual(detectSbomFiles(dir), ['app.cdx.json', 'app.spdx.json', 'bom.json', 'sbom.json']);
  assert.deepEqual(detectSbomFiles(join(dir, 'nope')), []);
});

test('syft is found on the PATH and absent otherwise', () => {
  assert.equal(findSyft({ pathEnv: join(tmpdir(), 'definitely-not-here') }), undefined);
  if (process.platform !== 'win32') chmodSync(join(FAKE_SYFT_DIR, 'syft'), 0o755);
  const found = findSyft({ pathEnv: [join(tmpdir(), 'nope'), FAKE_SYFT_DIR].join(delimiter) });
  assert.ok(found?.startsWith(FAKE_SYFT_DIR), `found ${found}`);
  assert.equal(findSyft({ syftPath: found }), found, 'an explicit path is used as given');
  assert.equal(findOnPath('syft', ''), undefined);
});

test('an image is inventoried through syft, and a syft failure is reported per image', async () => {
  if (process.platform !== 'win32') chmodSync(join(FAKE_SYFT_DIR, 'syft'), 0o755);
  const syft = findSyft({ pathEnv: FAKE_SYFT_DIR })!;
  const text = await runSyft(syft, 'example/shop:1.2');
  assert.equal(JSON.parse(text).bomFormat, 'CycloneDX');
  await assert.rejects(runSyft(syft, 'fail:please'), /syft failed for fail:please: .*not found/);
  await assert.rejects(runSyft(syft, 'evil; rm -rf /'), /will not pass to a shell/);

  // pathEnv keeps Docker out of reach so the failure is reported rather than retried in a container.
  const inv = await readContainerInventory(FIXTURES, { images: ['example/shop:1.2', 'fail:please'], syftPath: syft, pathEnv: FAKE_SYFT_DIR });
  assert.equal(inv.images[0]!.source, 'syft');
  assert.equal(inv.images[0]!.components, 9, 'libssl3 and openssl merge into one source package');
  assert.ok(inv.images[1]!.error?.includes('not found'));
  assert.ok(inv.components.every((c) => c.image === 'example/shop:1.2'));

  const none = await readContainerInventory(FIXTURES, { images: ['example/shop:1.2'], pathEnv: '', syftPath: undefined });
  assert.match(none.images[0]!.error ?? '', /neither syft .* nor Docker/);
  assert.equal(none.components.length, 0);
});

test('without a local syft, the official container is run against the daemon socket', () => {
  assert.deepEqual(dockerSyftArgs('example/shop:1.2', 'anchore/syft:v1.52.0'), ['run', '--rm', '-v', '/var/run/docker.sock:/var/run/docker.sock', 'anchore/syft:v1.52.0', 'example/shop:1.2', '-o', 'cyclonedx-json', '-q']);
  assert.equal(findSyft({ syftPath: 'docker' }), undefined, '"docker" forces the container route');
});

test('distribution versions order like dpkg', () => {
  const lt = (a: string, b: string) => assert.ok(compareDistroVersion(a, b) < 0, `${a} < ${b}`);
  lt('3.0.11-1~deb12u2', '3.0.13-1~deb12u1');
  lt('3.0.11-1~deb12u2', '3.0.11-1');
  lt('2.36-9+deb12u4', '2.36-9+deb12u10');
  lt('1.36.1-r5', '1.36.1-r15');
  lt('3.1.4-r0', '3.1.4-r1');
  lt('1:3.0.7-16.el9_2', '1:3.0.7-24.el9');
  lt('3.0.7', '1:1.0');
  lt('1.0~rc1', '1.0');
  lt('1.0', '1.0a');
  assert.equal(compareDistroVersion('2.36-9+deb12u4', '2.36-9+deb12u4'), 0);
  assert.ok(compareVersions('Debian:12', '3.0.13-1~deb12u1', '3.0.11-1~deb12u2') > 0);
  assert.ok(compareVersions('Go', 'v1.2.3', '1.10.0') < 0);
  assert.ok(isDistro('Alpine:v3.18'));
  assert.ok(!isDistro('npm'));
  assert.ok(!osvQueryable('generic'));
});

function imageFinding(over: Partial<Component> = {}, adv: Partial<Advisory> = {}, extra: Partial<Pick<Finding, 'epss' | 'kev'>> = {}) {
  const component: Component = { ecosystem: 'Debian:12', name: 'openssl', version: '3.0.11-1~deb12u2', purl: 'pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12&upstream=openssl', dev: false, optional: false, direct: false, path: 'libssl3', paths: ['libssl3', 'openssl'], origin: 'image', image: 'example/shop:1.2', packageType: 'deb', ...over };
  const advisory: Advisory = { id: 'DEBIAN-CVE-2024-0727', aliases: ['CVE-2024-0727'], cve: 'CVE-2024-0727', summary: 'PKCS12 NULL pointer', details: '', references: [], cvssScore: 5.5, severityLabel: 'MEDIUM', ...adv };
  return decide({ id: 'x', component, advisory, reach: { tier: 'image-only', confidence: 'package-level', importedIn: [], callSites: [], paths: [] }, exposure: { network: 'published', ports: [3000], evidence: ['Dockerfile: EXPOSE 3000'] }, ...extra });
}

test('image-only findings: watched unless exploited, or fixable and severe', () => {
  const quiet = imageFinding();
  assert.equal(quiet.decision, 'Track*');
  assert.ok(quiet.why.some((w) => w.includes('In the container image only') && w.includes('libssl3, openssl')));
  assert.ok(quiet.why.some((w) => w.startsWith('No fix is available')));

  const fixable = imageFinding({}, { fixedVersion: '3.0.13-1~deb12u1', cvssScore: 7.5, severityLabel: 'HIGH' });
  assert.equal(fixable.decision, 'Attend');
  assert.match(fixable.fix ?? '', /in the image/);

  const severeNoFix = imageFinding({}, { cvssScore: 9.8 });
  assert.equal(severeNoFix.decision, 'Track*', 'nothing to move to');

  const kev = imageFinding({}, {}, { kev: { dateAdded: '2024-01-01', ransomware: false } });
  assert.equal(kev.decision, 'Attend');
  assert.ok(kev.score > quiet.score);

  const likely = imageFinding({}, { fixedVersion: '3.0.13-1~deb12u1' }, { epss: { score: 0.4, percentile: 0.97 } });
  assert.equal(likely.decision, 'Attend');
});

test('fix commands follow the ecosystem', () => {
  const f = (eco: Component['ecosystem'], name = 'openssl', fixedVersion = '2') => fixCommandFor({ component: { ecosystem: eco, name }, advisory: { fixedVersion } } as unknown as Finding);
  assert.equal(f('Debian:12'), 'apt-get update && apt-get install --only-upgrade -y openssl');
  assert.equal(f('Ubuntu:22.04:LTS'), 'apt-get update && apt-get install --only-upgrade -y openssl');
  assert.equal(f('Alpine:v3.18'), 'apk upgrade --no-cache openssl');
  assert.equal(f('AlmaLinux:9'), 'dnf upgrade -y openssl');
  assert.equal(f('Go', 'gopkg.in/yaml.v3', '3.0.1'), 'go get gopkg.in/yaml.v3@v3.0.1');
  assert.equal(f('npm', 'lodash', '4.17.21'), 'npm install lodash@4.17.21');
  assert.equal(f('PyPI', 'requests', '2.32.0'), 'pip install "requests==2.32.0"');
  assert.equal(f('generic'), undefined);
});
