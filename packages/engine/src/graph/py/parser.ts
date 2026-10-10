import { Parser, Language, type Node, type Tree } from 'web-tree-sitter';
import { readAsset } from '../../assets.ts';

let ready: Promise<Parser> | undefined;

/** One shared Python parser (tree-sitter via WebAssembly, no native build). */
export function pythonParser(): Promise<Parser> {
  if (!ready) {
    ready = (async () => {
      // Both wasm modules come from the asset store, so the same code runs from source and from the executable.
      await Parser.init({ wasmBinary: readAsset('tree-sitter.wasm') });
      const lang = await Language.load(readAsset('tree-sitter-python.wasm'));
      const p = new Parser();
      p.setLanguage(lang);
      return p;
    })();
  }
  return ready;
}

export async function parsePython(text: string): Promise<Tree> {
  const p = await pythonParser();
  const tree = p.parse(text);
  if (!tree) throw new Error('tree-sitter returned no tree');
  return tree;
}

/** Source text of a node. */
export function src(n: Node | null | undefined): string {
  return n ? n.text : '';
}

export function field(n: Node, name: string): Node | null {
  return n.childForFieldName(name);
}

export function children(n: Node, type?: string): Node[] {
  return n.namedChildren.filter((c) => !type || c.type === type);
}

/** Depth-first walk; return false from `visit` to skip a subtree. */
export function walk(n: Node, visit: (node: Node) => boolean | void): void {
  if (visit(n) === false) return;
  for (const c of n.namedChildren) walk(c, visit);
}

/** Unquotes a Python string literal node (simple and f-strings with no interpolation). */
export function stringValue(n: Node | null | undefined): string | undefined {
  if (!n) return undefined;
  if (n.type === 'string') {
    const parts = n.namedChildren.filter((c) => c.type === 'string_content').map((c) => c.text);
    if (n.namedChildren.some((c) => c.type === 'interpolation')) return undefined;
    return parts.join('');
  }
  if (n.type === 'concatenated_string') {
    const vals = n.namedChildren.map((c) => stringValue(c));
    return vals.every((v) => v !== undefined) ? vals.join('') : undefined;
  }
  return undefined;
}

export type { Node, Tree };
