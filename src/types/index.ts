export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type PublishMethod = 'trusted-publishing' | 'manual-or-token' | 'unknown';

export type IntegrityStatus = 'verified' | 'mismatch' | 'partial' | 'not-checked';

export type SigstoreStatus = 'verified' | 'present-unverified' | 'not-found' | 'unknown';

export type TokenSourceType = 'env' | 'npmrc' | 'workflow' | 'npm-cli';

export type TokenKind = 'traditional-static' | 'granular-access-token' | 'session-token' | 'unknown';

export interface BaseCommandOptions {
  rootDir: string;
  configPath?: string;
  output?: string;
  json?: boolean;
  quiet?: boolean;
}

export interface ScanCommandOptions extends BaseCommandOptions {
  threshold?: number;
  failFast?: boolean;
  updateBaseline?: boolean;
  generateWorkflow?: boolean;
  installPreCommit?: boolean;
  sarif?: string;
}

export interface MonitorCommandOptions extends BaseCommandOptions {
  intervalMs?: number;
  slackWebhook?: string;
  webhook?: string;
  once?: boolean;
}

export interface AuditTokensCommandOptions extends BaseCommandOptions {
  revokeStale?: boolean;
  staleAfterDays?: number;
}

export interface VerifyCommandOptions extends BaseCommandOptions {
  packageSpec: string;
  failFast?: boolean;
}

export interface IncidentCommandOptions extends BaseCommandOptions {
  packageSpec: string;
  from: string;
  to: string;
  githubOwner?: string;
  githubRepo?: string;
  githubToken?: string;
}

export interface EmailConfig {
  host: string;
  port: number;
  secure?: boolean;
  username?: string;
  password?: string;
  from: string;
  to: string[];
}

export interface GitHubIntegrationConfig {
  owner?: string;
  repo?: string;
  token?: string;
  tokenEnvVar?: string;
}

export interface NotificationConfig {
  slackWebhook?: string;
  webhook?: string;
  email?: EmailConfig;
}

export interface ScanPolicyConfig {
  riskThreshold?: number;
  failOnSeverity?: Severity;
  ignoreDirs?: string[];
  trustedPackages?: string[];
  trustedScriptPackages?: string[];
  maxScriptFileBytes?: number;
}

export interface BaselineConfig {
  directory?: string;
  path?: string;
  privateKeyPath?: string;
  publicKeyPath?: string;
}

export interface TokenPolicyConfig {
  staleAfterDays?: number;
  mixedModeAllowed?: boolean;
}

export interface CustomIoc {
  packageName: string;
  reason: string;
  advisory?: string;
  addedBy?: string;
  addedAt?: string;
}

export interface GuardrailConfig {
  baseline?: BaselineConfig;
  scan?: ScanPolicyConfig;
  notifications?: NotificationConfig;
  github?: GitHubIntegrationConfig;
  tokenPolicy?: TokenPolicyConfig;
  customIocs?: CustomIoc[];
  monitor?: {
    packages?: string[];
    pollIntervalMs?: number;
    slackWebhook?: string;
    webhook?: string;
    email?: EmailConfig;
  };
  __comment?: string;
  [key: string]: unknown;
}

export interface RegistryDistInfo {
  tarball?: string;
  integrity?: string;
  shasum?: string;
  signatures?: unknown;
  [key: string]: unknown;
}

export interface RegistryPackageVersionMetadata {
  name: string;
  version: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
  dist?: RegistryDistInfo;
  repository?: string | { type?: string; url?: string };
  gitHead?: string;
  time?: string;
  _npmUser?: {
    name?: string;
    email?: string;
  };
  trustedPublisher?: unknown;
  [key: string]: unknown;
}

export interface PackageNode {
  name: string;
  version: string;
  dependencies: Record<string, string>;
  resolved?: string;
  integrity?: string;
  path?: string;
  dev?: boolean;
  optional?: boolean;
  hasInstallScripts?: boolean;
  scripts?: Record<string, string>;
}

export interface LockfileInfo {
  kind: 'package-lock' | 'pnpm-lock' | 'yarn-lock' | 'bun-lock' | 'bun-lockb' | 'none';
  path?: string;
  packages: PackageNode[];
  directDependencies: Record<string, string>;
  warnings: string[];
}

export interface ScriptFinding {
  packageName: string;
  packageVersion: string;
  scriptName: string;
  command: string;
  score: number;
  severity: Severity;
  reasons: string[];
  evidence: string[];
}

export interface PackageSnapshot {
  name: string;
  version: string;
  packagePath?: string;
  declaredDependencies: string[];
  optionalDependencies: string[];
  peerDependencies: string[];
  importedDependencies: string[];
  unusedDeclaredDependencies: string[];
  lifecycleScripts: Record<string, string>;
  lifecycleScriptHashes: Record<string, string>;
  scriptFindings: ScriptFinding[];
  highestScriptRisk: number;
  sourceFileCount: number;
  manifestHash: string;
  sourceHash: string;
  packageHash: string;
  hasInstallScripts?: boolean;
  registry?: Pick<RegistryPackageVersionMetadata, 'gitHead' | 'repository' | '_npmUser' | 'trustedPublisher'>;
}

export interface BaselineSnapshot {
  generatedAt: string;
  rootManifestHash: string;
  lockfileHash?: string;
  packageManager?: LockfileInfo['kind'];
  packages: Record<string, PackageSnapshot>;
}

export interface BaselineFile {
  formatVersion: number;
  createdAt: string;
  updatedAt: string;
  publicKeyPem: string;
  signatureAlgorithm: 'ed25519';
  snapshot: BaselineSnapshot;
  signature: string;
}

export interface ScanIssue {
  id: string;
  code: string;
  category:
    | 'mutation'
    | 'ghost-dependency'
    | 'lifecycle-script'
    | 'token-exposure'
    | 'provenance'
    | 'integrity'
    | 'incident'
    | 'configuration'
    | 'ioc';
  severity: Severity;
  title: string;
  description: string;
  packageName?: string;
  packageVersion?: string;
  dependencyName?: string;
  location?: string;
  score?: number;
  evidence?: string[];
  recommendation?: string;
  raw?: unknown;
}

export interface ScanExecutionResult {
  rootDir: string;
  generatedAt: string;
  baselinePath: string;
  baselineVerified: boolean;
  baselineCreated: boolean;
  lockfile: LockfileInfo;
  packagesScanned: number;
  lifecycleScriptsDiscovered: number;
  issues: ScanIssue[];
  packages: Record<string, PackageSnapshot>;
}

export interface FeedChange {
  sequence: number;
  packageName: string;
  deleted?: boolean;
  doc?: Record<string, unknown>;
}

export interface MonitorAlert {
  occurredAt: string;
  packageName: string;
  previousVersion?: string;
  version: string;
  publishedBy?: string;
  publisherEmail?: string;
  publishMethod: PublishMethod;
  hasTrustedPublisher: boolean;
  hasProvenance: boolean;
  newDependencies: string[];
  removedDependencies: string[];
  addedLifecycleScripts: string[];
  changedLifecycleScripts: string[];
  ghostDependencies: string[];
  scriptRiskScore: number;
  scriptFindings: ScriptFinding[];
  suspicious: boolean;
  reasons: string[];
}

export interface TokenDiscovery {
  sourceType: TokenSourceType;
  sourcePath?: string;
  envVar?: string;
  registry?: string;
  tokenPreview: string;
  tokenKind: TokenKind;
  canPublish?: boolean;
  bypass2FA?: boolean;
  createdAt?: string;
  lastUsedAt?: string;
  expiresAt?: string;
  id?: string;
  note?: string;
}

export interface TokenAuditResult {
  rootDir: string;
  oidcTrustedPublishingDetected: boolean;
  selfHostedRunnerDetected: boolean;
  staticPublishTokensFound: boolean;
  mixedModeRisk: boolean;
  findings: TokenDiscovery[];
  issues: ScanIssue[];
  suggestedRevocations: string[];
}

export interface IntegrityDiff {
  onlyInPackage: string[];
  modifiedInPackage: string[];
  overlapCount: number;
  matchRatio: number;
}

export interface VerificationResult {
  packageName: string;
  version: string;
  publishMethod: PublishMethod;
  publishedBy?: string;
  publisherEmail?: string;
  hasTrustedPublisher: boolean;
  hasProvenance: boolean;
  hasRegistrySignatures: boolean;
  slsaBuildLevel: 'unknown' | '1' | '2' | '3';
  sigstoreStatus: SigstoreStatus;
  integrityStatus: IntegrityStatus;
  sourceComparison?: IntegrityDiff;
  inconsistentProvenanceSignal: boolean;
  notes: string[];
  issues: ScanIssue[];
  metadata: Record<string, unknown>;
}

export interface WorkflowRunCandidate {
  id: number;
  name: string;
  htmlUrl: string;
  status: string;
  conclusion?: string;
  createdAt: string;
  updatedAt: string;
  possibleMatch: boolean;
  matches: string[];
}

export interface IncidentReport {
  packageName: string;
  version?: string;
  from: string;
  to: string;
  summary: string[];
  checklist: string[];
  possibleLocalMatches: string[];
  workflowRuns: WorkflowRunCandidate[];
  secretsAtRisk: string[];
  rotationCommands: Record<string, string[]>;
  issues: ScanIssue[];
}

export interface RemotePackageAnalysis {
  metadata: RegistryPackageVersionMetadata;
  snapshot: PackageSnapshot;
  tarballSha256: string;
  files: Record<string, Uint8Array>;
}
