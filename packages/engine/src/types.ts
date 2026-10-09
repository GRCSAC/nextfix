export type Ecosystem = 'npm';

export interface Component {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  purl: string;
  /** devDependency (not shipped in the production artifact). */
  dev: boolean;
  optional: boolean;
  /** Declared directly in the root manifest (vs. transitive). */
  direct: boolean;
  /** Lockfile path, e.g. node_modules/a/node_modules/b */
  path: string;
}

export interface Advisory {
  id: string;
  aliases: string[];
  cve?: string;
  summary: string;
  details: string;
  published?: string;
  modified?: string;
  severityLabel?: string;
  cvssVector?: string;
  cvssScore?: number;
  /** Lowest fixed version above the component's version, if any. */
  fixedVersion?: string;
  references: string[];
}

export type SymbolSource = 'curated' | 'derived' | 'advisory';
export type SymbolConfidence = 'confirmed' | 'derived';

export interface SymbolEntry {
  ids: string[];
  ecosystem: Ecosystem;
  package: string;
  /** For framework objects (e.g. Express `res`), the receiver type the symbols live on. */
  receiver?: string;
  symbols: string[];
  source: SymbolSource;
  confidence: SymbolConfidence;
  note?: string;
  references?: string[];
}

export type ReachTier =
  | 'dev-only'
  | 'unused'
  | 'imported-not-called'
  | 'imported-unknown-symbol'
  | 'called-unreached'
  | 'reachable';

export type ReachConfidence = SymbolConfidence | 'package-level';

export interface EntryPoint {
  method: string;
  path: string;
  file: string;
  line: number;
  authenticated: boolean;
  guards: string[];
  /** false when a router file is never mounted on an app (path is relative to nothing). */
  mounted: boolean;
  handlerIds: string[];
}

export interface PathHop {
  functionId: string;
  name: string;
  file: string;
  line: number;
}

export interface CallSiteRef {
  file: string;
  line: number;
  col: number;
  text: string;
  symbol: string;
  userInput: boolean;
}

export interface ReachPath {
  entry: EntryPoint;
  hops: PathHop[];
  callSite: CallSiteRef;
  /** Request data reaches the vulnerable call, either directly or passed down the chain. */
  userInput: boolean;
  /** Where request data first enters the chain, when it is not at the call site itself. */
  inputEntersAt?: { file: string; line: number; name: string };
}

export interface ReachResult {
  tier: ReachTier;
  confidence: ReachConfidence;
  importedIn: string[];
  callSites: CallSiteRef[];
  paths: ReachPath[];
}

export type NetworkExposure = 'published' | 'local-only' | 'unknown';

export interface Exposure {
  network: NetworkExposure;
  ports: number[];
  evidence: string[];
}

export type Decision = 'Act' | 'Attend' | 'Track*' | 'Track';
export type Exploitation = 'active' | 'likely' | 'none';

export interface Finding {
  id: string;
  component: Component;
  advisory: Advisory;
  symbols?: SymbolEntry;
  reach: ReachResult;
  exposure: Exposure;
  epss?: { score: number; percentile: number };
  kev?: { dateAdded: string; ransomware: boolean };
  exploitation: Exploitation;
  decision: Decision;
  score: number;
  why: string[];
  fix?: string;
}

export interface ScanSummary {
  components: number;
  advisories: number;
  findings: number;
  byDecision: Record<Decision, number>;
  byTier: Record<ReachTier, number>;
  /** Findings that are neither Act nor Attend, as a fraction of all findings. */
  noiseRemoved: number;
}

export interface ScanReport {
  tool: { name: 'NextFix'; version: string };
  target: { dir: string; name?: string; version?: string };
  generatedAt: string;
  summary: ScanSummary;
  exposure: Exposure;
  entryPoints: EntryPoint[];
  findings: Finding[];
}
