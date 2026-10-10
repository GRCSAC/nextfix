/**
 * Version ordering for distribution packages: the dpkg algorithm (`epoch:upstream-revision`,
 * digit runs compared numerically, `~` sorts before everything including the end of the
 * string). Alpine's apk and rpm's `rpmvercmp` agree with it on every version seen in
 * practice, so one comparator serves Debian, Ubuntu, Alpine, Wolfi and the rpm family.
 */
export function compareDistroVersion(a: string, b: string): number {
  const [ea, ua, ra] = split(a);
  const [eb, ub, rb] = split(b);
  if (ea !== eb) return ea - eb;
  const u = verrevcmp(ua, ub);
  if (u !== 0) return u;
  return verrevcmp(ra, rb);
}

function split(v: string): [number, string, string] {
  let epoch = 0;
  let rest = v.trim();
  const colon = rest.indexOf(':');
  if (colon > 0 && /^\d+$/.test(rest.slice(0, colon))) {
    epoch = parseInt(rest.slice(0, colon), 10);
    rest = rest.slice(colon + 1);
  }
  const dash = rest.lastIndexOf('-');
  if (dash > 0) return [epoch, rest.slice(0, dash), rest.slice(dash + 1)];
  return [epoch, rest, ''];
}

/** Weight of a non-digit character: `~` lowest, then end-of-string, letters, then everything else. */
function order(ch: string | undefined): number {
  if (ch === undefined || ch === '') return 0;
  if (ch === '~') return -1;
  if (/[A-Za-z]/.test(ch)) return ch.charCodeAt(0);
  return ch.charCodeAt(0) + 256;
}

function verrevcmp(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    let first = 0;
    // Non-digit run.
    while ((i < a.length && !/\d/.test(a[i]!)) || (j < b.length && !/\d/.test(b[j]!))) {
      const ac = order(i < a.length && !/\d/.test(a[i]!) ? a[i] : undefined);
      const bc = order(j < b.length && !/\d/.test(b[j]!) ? b[j] : undefined);
      if (ac !== bc) return ac - bc;
      i++;
      j++;
    }
    // Digit run.
    while (i < a.length && a[i] === '0') i++;
    while (j < b.length && b[j] === '0') j++;
    while (i < a.length && /\d/.test(a[i]!) && j < b.length && /\d/.test(b[j]!)) {
      if (!first) first = a.charCodeAt(i) - b.charCodeAt(j);
      i++;
      j++;
    }
    if (i < a.length && /\d/.test(a[i]!)) return 1;
    if (j < b.length && /\d/.test(b[j]!)) return -1;
    if (first) return first;
  }
  return 0;
}
