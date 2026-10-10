// Stands in for syft in tests: prints the fixture SBOM for any image reference.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
if (args[0] === 'version') {
  console.log('Application: fake-syft\nVersion: 0.0.0');
  process.exit(0);
}
if (args.includes('fail:please')) {
  console.error('could not fetch image "fail:please": not found');
  process.exit(1);
}
process.stdout.write(readFileSync(fileURLToPath(new URL('../image.cdx.json', import.meta.url)), 'utf8'));
