import { Parser, Language, type Node, type Tree } from 'web-tree-sitter';
import { readAsset } from '../../assets.ts';

let ready: Promise<Parser> | undefined;

/** One shared Go parser (tree-sitter via WebAssembly, no native build). */
export function goParser(): Promise<Parser> {
  if (!ready) {
    ready = (async () => {
      // Both wasm modules come from the asset store, so the same code runs from source and from the executable.
      await Parser.init({ wasmBinary: readAsset('tree-sitter.wasm') });
      const lang = await Language.load(readAsset('tree-sitter-go.wasm'));
      const p = new Parser();
      p.setLanguage(lang);
      return p;
    })();
  }
  return ready;
}

export async function parseGo(text: string): Promise<Tree> {
  const p = await goParser();
  const tree = p.parse(text);
  if (!tree) throw new Error('tree-sitter returned no tree');
  return tree;
}

export function field(n: Node, name: string): Node | null {
  return n.childForFieldName(name);
}

/** Depth-first walk; return false from `visit` to skip a subtree. */
export function walk(n: Node, visit: (node: Node) => boolean | void): void {
  if (visit(n) === false) return;
  for (const c of n.namedChildren) walk(c, visit);
}

/** Value of a Go string literal node (interpreted or raw); undefined for anything else. */
export function stringValue(n: Node | null | undefined): string | undefined {
  if (!n) return undefined;
  if (n.type === 'interpreted_string_literal') {
    try {
      return JSON.parse(n.text) as string;
    } catch {
      return n.namedChildren.map((c) => c.text).join('');
    }
  }
  if (n.type === 'raw_string_literal') return n.text.slice(1, -1);
  if (n.type === 'parenthesized_expression') return stringValue(n.namedChildren[0]);
  return undefined;
}

export const line = (n: Node): number => n.startPosition.row + 1;
export const col = (n: Node): number => n.startPosition.column + 1;

export type { Node, Tree };
