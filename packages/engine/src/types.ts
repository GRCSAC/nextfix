/**
 * OSV ecosystem string. Code ecosystems come from lockfiles and SBOMs; distribution
 * ecosystems (from container images) carry the release suffix OSV expects, e.g. `Debian:12`,
 * `Alpine:v3.18`, `Ubuntu:22.04:LTS`. `generic` is inventoried but never queried.
 */
export type Ecosystem =
  | 'npm'
  | 'PyPI'
  | 'Go'
  | 'Maven'
  | 'RubyGems'
  | 'crates.io'
  | 'NuGet'
  | 'Packagist'
  | 'Hex'
  | 'Pub'
  | 'generic'
  | `Debian${string}`
  | `Ubuntu${string}`
  | `Alpine${string}`
  | 'Wolfi'
  | 'Chainguard'
  | 'Red Hat'
  | `AlmaLinux${string}`
  | `Rocky Linux${string}`;

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
  /** All lockfile paths when the same name@version is installed more than once. */
  paths?: string[];
  /** Where the component was found: absent for the project lockfile, `image` for a container image or SBOM. */
  origin?: 'image';
  /** Image reference or SBOM file the component was found in (also set on lockfile components the image contains). */
  image?: string;
  /** Package manager type from the SBOM (deb, apk, rpm, npm, python, go-module, binary, …). */
  packageType?: string;
}

/** One container image or SBOM that contributed components to a scan. */
export interface ImageInventory {
  /** Image reference as given, or the SBOM file path. */
  ref: string;
  source: 'syft' | 'cyclonedx' | 'spdx' | 'grype';
  /** Operating system found in the image, e.g. `debian 12`. */
  os?: string;
  components: number;
  /** Components in ecosystems OSV cannot answer for (binaries, unknown types). */
  unqueried: number;
  /** Set when the image could not be read (no syft, syft failed); the scan continues without it. */
  error?: string;
}

export interface Advisory {
  id: string;
  aliases: string[];
  /** The CVE used for display; `cves` lists every CVE the advisory covers. */
  cve?: string;
  cves?: string[];
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
  /** References with their advisory-database type (FIX, WEB, …) when known. */
  typedReferences?: { type?: string; url: string }[];
}

export type SymbolSource = 'curated' | 'derived' | 'advisory';
export type SymbolConfidence = 'confirmed' | 'derived';

export interface SymbolEvidence {
  /** Fix commit / PR / compare URLs the symbols were derived from. */
  commits: string[];
  /** Source files touched by the fix (tests and docs excluded). */
  files: string[];
  /** Functions whose body the fix changed, as named in the source. */
  changedFunctions: string[];
  /** How each public symbol was reached: "direct" (changed function is public) or "caller:<fn>" (public caller of a changed internal). */
  resolvedVia: Record<string, string>;
  /** The fix repository name contains the package name. */
  repoMatch: boolean;
  /** Package entry file the symbols were resolved through, when cross-file resolution succeeded. */
  entry?: string;
  derivedAt: string;
}

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
  evidence?: SymbolEvidence;
  /** A human promoted this derived entry to confirmed. */
  reviewed?: boolean;
}

export type ReachTier =
  | 'dev-only'
  | 'unused'
  | 'imported-not-called'
  | 'imported-unknown-symbol'
  | 'called-unreached'
  | 'image-only'
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
  /** Handlers NextFix could not follow into code (factories like `login()`, methods on unknown objects). */
  unresolvedHandlers?: string[];
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
  /** Request data reaches an argument of the vulnerable call, traced parameter by parameter. */
  userInput: boolean;
  /** Where request data first enters the chain, when it is not at the call site itself. */
  inputEntersAt?: { file: string; line: number; name: string };
  /** The request expression that starts the flow, e.g. `req.body.template`. */
  inputSource?: string;
  /** Which argument of the vulnerable call carries it (0-based) and its text. */
  taintedArgument?: { index: number; text: string };
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

export type ExceptionKind = 'accepted-risk' | 'false-positive' | 'mitigated';
export type ExceptionStatus = 'pending' | 'approved' | 'rejected' | 'revoked' | 'expired';

/**
 * A human decision recorded against a finding (the server's exceptions table). Attached to a
 * finding when a report is served; an approved, unexpired one moves the decision to Track.
 */
export interface FindingException {
  /** The exception's id as the API serves it. */
  id: string;
  kind: ExceptionKind;
  status: ExceptionStatus;
  reason?: string;
  /** ISO timestamp after which the exception no longer applies; null or absent for open-ended ones. */
  expiresAt?: string | null;
  approvedBy?: string;
  /** When it was approved (ISO timestamp). */
  approvedAt?: string;
  /** The decision the engine gave before the exception replaced it. */
  originalDecision?: Decision;
}

export interface Finding {
  id: string;
  component: Component;
  advisory: Advisory;
  symbols?: SymbolEntry;
  reach: ReachResult;
  exposure: Exposure;
  /** Highest EPSS across the advisory's CVEs; `cve` names the one it belongs to. */
  epss?: { score: number; percentile: number; cve?: string };
  /** Set when any of the advisory's CVEs is in CISA KEV; `cve` names it. */
  kev?: { dateAdded: string; ransomware: boolean; cve?: string };
  exploitation: Exploitation;
  decision: Decision;
  score: number;
  why: string[];
  fix?: string;
  /** Set by the server when an exception exists for this finding; never written by the engine. */
  exception?: FindingException;
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
  /** Every installed component (absent in reports written before 0.3). */
  components?: Component[];
  /** Container images and SBOMs read for this scan (absent before 0.8). */
  images?: ImageInventory[];
  /**
   * How Go reachability was decided (absent for projects without go.mod): the project call graph,
   * govulncheck's per-advisory verdicts, or neither (offline, or govulncheck missing or failed).
   */
  goAnalysis?: 'call-graph' | 'govulncheck' | 'none';
  /** Why govulncheck did not contribute, when it was expected to. */
  govulncheckError?: string;
  findings: Finding[];
}
