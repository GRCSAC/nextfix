export interface Hunk {
  oldStart: number;
  oldLines: number;
  newStart: number;
  newLines: number;
  /** Lines in the new file that were added or sit next to deletions (for mapping to functions). */
  touchedNewLines: number[];
}

export interface DiffFile {
  path: string;
  oldPath?: string;
  deleted: boolean;
  added: boolean;
  hunks: Hunk[];
}

/** Parses a unified diff (git format) into files and hunks with touched line numbers. */
export function parseUnifiedDiff(text: string): DiffFile[] {
  const files: DiffFile[] = [];
  let cur: DiffFile | undefined;
  let hunk: Hunk | undefined;
  let newLine = 0;
  for (const raw of text.split(/\r?\n/)) {
    if (raw.startsWith('diff --git ')) {
      const m = /^diff --git a\/(.+?) b\/(.+)$/.exec(raw);
      cur = { path: m?.[2] ?? raw.slice(11), oldPath: m?.[1], deleted: false, added: false, hunks: [] };
      files.push(cur);
      hunk = undefined;
      continue;
    }
    if (!cur) continue;
    if (raw.startsWith('deleted file mode')) cur.deleted = true;
    else if (raw.startsWith('new file mode')) cur.added = true;
    else if (raw.startsWith('+++ ')) {
      const p = raw.slice(4).trim();
      if (p !== '/dev/null') cur.path = p.replace(/^b\//, '');
    } else if (raw.startsWith('@@')) {
      const m = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(raw);
      if (!m) continue;
      hunk = { oldStart: Number(m[1]), oldLines: m[2] === undefined ? 1 : Number(m[2]), newStart: Number(m[3]), newLines: m[4] === undefined ? 1 : Number(m[4]), touchedNewLines: [] };
      cur.hunks.push(hunk);
      newLine = hunk.newStart;
    } else if (hunk) {
      if (raw.startsWith('+')) {
        hunk.touchedNewLines.push(newLine);
        newLine++;
      } else if (raw.startsWith('-')) {
        // A deletion touches the surrounding position in the new file.
        hunk.touchedNewLines.push(Math.max(hunk.newStart, newLine));
      } else if (raw.startsWith('\\')) {
        /* "\ No newline at end of file" */
      } else {
        newLine++;
      }
    }
  }
  for (const f of files) for (const h of f.hunks) h.touchedNewLines = [...new Set(h.touchedNewLines)];
  return files;
}

const SKIP_PATH = /(^|\/)(test|tests|__tests__|spec|specs|docs?|examples?|benchmark|bench|fixtures|dist|build|coverage|\.github)(\/|$)|\.(test|spec)\.[cm]?[jt]sx?$|\.d\.ts$|\.(md|json|yml|yaml|lock|txt|snap|html|css)$/i;
const SOURCE_EXT = /\.((c|m)?(j|t)sx?|py)$/i;

export function isPython(path: string): boolean {
  return /\.py$/i.test(path);
}

/** Keeps only files that could change the package's runtime behaviour. */
export function sourceFiles(files: DiffFile[]): DiffFile[] {
  return files.filter((f) => !f.deleted && SOURCE_EXT.test(f.path) && !SKIP_PATH.test(f.path) && f.hunks.length > 0);
}
