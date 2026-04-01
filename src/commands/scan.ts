import * as fs from 'node:fs';
import * as path from 'node:path';

import { generateGuardrailWorkflow } from '../integrations/github-actions';
import { writeSarif } from '../integrations/sarif';
import {
  BaselineSnapshot,
  GuardrailConfig,
  LockfileInfo,
  PackageNode,
  PackageSnapshot,
  ScanCommandOptions,
  ScanExecutionResult,
  ScanIssue,
  Severity,
} from '../types';
import {
  latestSnapshotForPackage,
  loadBaseline,
  mergeSnapshots,
  severityToNumber,
  sha256,
  snapshotKey,
  writeBaseline,
} from '../core/baseline';
import {
  analyzeLifecycleScripts,
  hashLifecycleScripts,
  highestScriptRisk,
  pickLifecycleScripts,
} from '../core/script-analyzer';
import { parseLockfile } from '../utils/lockfile';

const SOURCE_FILE_PATTERN = /\.(?:[cm]?[jt]sx?|json)$/i;
const PACKAGE_SCAN_IGNORE_DIRS = new Set([
  'node_modules',
  '.git',
  '.hg',
  '.svn',
  'coverage',
  '.nyc_output',
  'test',
  'tests',
  '__tests__',
  'docs',
  'examples',
  'example',
]);

export async function runScan(
  options: ScanCommandOptions,
  config: GuardrailConfig,
): Promise<number> {
  const rootDir = path.resolve(options.rootDir);
  const packageJsonPath = path.join(rootDir, 'package.json');
  if (!fs.existsSync(packageJsonPath)) {
    throw new Error(`No package.json found in ${rootDir}`);
  }

  const rootManifestText = fs.readFileSync(packageJsonPath, 'utf8');
  const rootManifest = JSON.parse(rootManifestText) as Record<string, unknown>;
  const lockfile = parseLockfile(rootDir);
  const installedPackages = collectInstalledPackageSnapshots(rootDir, config);
  const packageMap = mergeInstalledAndLockfilePackages(lockfile, installedPackages, rootDir, config);

  // Analyze the root project's own lifecycle scripts
  const rootName = typeof rootManifest.name === 'string' ? rootManifest.name : 'root-project';
  const rootVersion = typeof rootManifest.version === 'string' ? rootManifest.version : '0.0.0';
  const rootLifecycleScripts = pickLifecycleScripts(normalizeScriptRecord(rootManifest.scripts));
  if (Object.keys(rootLifecycleScripts).length > 0) {
    const rootScriptFindings = analyzeLifecycleScripts(rootName, rootVersion, rootLifecycleScripts, (relativePath) =>
      readLocalScriptFile(rootDir, relativePath, config.scan?.maxScriptFileBytes ?? 256000),
    );
    const rootKey = snapshotKey(rootName, rootVersion);
    if (!packageMap[rootKey]) {
      packageMap[rootKey] = {
        name: rootName,
        version: rootVersion,
        packagePath: rootDir,
        declaredDependencies: Object.keys(toRecord(rootManifest.dependencies)).sort(),
        optionalDependencies: [],
        peerDependencies: [],
        importedDependencies: [],
        unusedDeclaredDependencies: [],
        lifecycleScripts: rootLifecycleScripts,
        lifecycleScriptHashes: hashLifecycleScripts(rootLifecycleScripts),
        scriptFindings: rootScriptFindings,
        highestScriptRisk: highestScriptRisk(rootScriptFindings),
        sourceFileCount: 0,
        manifestHash: sha256(rootManifestText),
        sourceHash: sha256('root'),
        packageHash: sha256(rootManifestText),
      };
    }
  }

  const lifecycleScriptsDiscovered = Object.values(packageMap).reduce(
    (count, entry) => count + Object.keys(entry.lifecycleScripts).length,
    0,
  );

  const rootManifestHash = sha256(rootManifestText);
  const lockfileHash = lockfile.path && fs.existsSync(lockfile.path)
    ? sha256(fs.readFileSync(lockfile.path, 'utf8'))
    : undefined;

  const baselineResult = loadBaseline(rootDir, config);
  const currentSnapshot: BaselineSnapshot = {
    generatedAt: new Date().toISOString(),
    rootManifestHash,
    lockfileHash,
    packageManager: lockfile.kind,
    packages: packageMap,
  };

  let baselineCreated = false;
  let baselineVerified = baselineResult.verified;
  let previousSnapshot = baselineResult.baseline?.snapshot;

  if (!baselineResult.baseline) {
    baselineCreated = true;
    baselineVerified = true;
  }

  const trustedPackages = new Set<string>([
    ...Object.keys(toRecord(rootManifest.dependencies)),
    ...(config.scan?.trustedPackages ?? []),
  ]);
  const threshold = options.threshold ?? config.scan?.riskThreshold ?? 70;
  const issues = [
    ...compareSnapshots(previousSnapshot, currentSnapshot, trustedPackages, threshold),
    ...detectProjectGhostDependencies(rootDir, rootManifest, packageMap, lockfile.packages, config),
    ...checkIocs(packageMap, config),
  ];
  issues.sort((left, right) => severityToNumber(right.severity) - severityToNumber(left.severity));

  const mergedSnapshot = mergeSnapshots(
    previousSnapshot,
    currentSnapshot.packages,
    currentSnapshot.rootManifestHash,
    currentSnapshot.lockfileHash,
    currentSnapshot.packageManager,
  );

  if (baselineCreated || options.updateBaseline) {
    writeBaseline(rootDir, config, mergedSnapshot, baselineResult.baseline);
    previousSnapshot = mergedSnapshot;
  }

  if (options.generateWorkflow) {
    writeWorkflow(rootDir);
  }

  if (options.installPreCommit) {
    installPreCommitHook(rootDir);
  }

  if (options.sarif) {
    writeSarif(path.resolve(rootDir, options.sarif), issues);
  }

  const result: ScanExecutionResult = {
    rootDir,
    generatedAt: currentSnapshot.generatedAt,
    baselinePath: baselineResult.path,
    baselineVerified,
    baselineCreated,
    lockfile,
    packagesScanned: Object.keys(packageMap).length,
    lifecycleScriptsDiscovered,
    issues,
    packages: packageMap,
  };

  if (options.output) {
    fs.writeFileSync(path.resolve(rootDir, options.output), `${JSON.stringify(result, null, 2)}\n`);
  }

  if (!options.quiet) {
    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      printScanResult(result, threshold, options.updateBaseline === true);
    }
  }

  const failSeverity = severityToNumber(config.scan?.failOnSeverity ?? 'high');
  const shouldFail = Boolean(options.failFast) && issues.some((issue) => severityToNumber(issue.severity) >= failSeverity);
  return shouldFail ? 1 : 0;
}

function compareSnapshots(
  previous: BaselineSnapshot | undefined,
  current: BaselineSnapshot,
  trustedPackages: Set<string>,
  threshold: number,
): ScanIssue[] {
  const issues: ScanIssue[] = [];

  for (const currentPackage of Object.values(current.packages)) {
    const key = snapshotKey(currentPackage.name, currentPackage.version);
    const previousExact = previous?.packages[key];
    const previousByName = previous ? latestSnapshotForPackage(previous, currentPackage.name) : undefined;

    if (previousExact && previousExact.packageHash !== currentPackage.packageHash) {
      issues.push({
        id: `${key}:hash-changed`,
        code: 'GR_TAMPERED_VERSION',
        category: 'integrity',
        severity: 'critical',
        title: 'Package contents changed for a version already in the baseline',
        description:
          'The same package version now resolves to different manifest or source content than the signed baseline recorded earlier.',
        packageName: currentPackage.name,
        packageVersion: currentPackage.version,
        recommendation:
          'Treat this as a registry or cache integrity incident. Re-fetch from a clean environment and verify the upstream package tarball.',
      });
    }

    if (previousByName && previousByName.version !== currentPackage.version) {
      const newDependencies = currentPackage.declaredDependencies.filter(
        (dependency) => !previousByName.declaredDependencies.includes(dependency),
      );
      const addedScripts = Object.keys(currentPackage.lifecycleScripts).filter(
        (scriptName) => !(scriptName in previousByName.lifecycleScripts),
      );
      const changedScripts = Object.keys(currentPackage.lifecycleScripts).filter(
        (scriptName) => previousByName.lifecycleScripts[scriptName] !== undefined && previousByName.lifecycleScripts[scriptName] !== currentPackage.lifecycleScripts[scriptName],
      );

      if (newDependencies.length > 0) {
        const severity = trustedPackages.has(currentPackage.name) ? 'high' : 'medium';
        issues.push({
          id: `${key}:new-dependencies`,
          code: 'GR_DEPENDENCY_MUTATION',
          category: 'mutation',
          severity,
          title: 'Previously known package introduced new dependencies',
          description:
            `${currentPackage.name}@${currentPackage.version} added dependencies that were not present in the baseline for ${previousByName.version}.`,
          packageName: currentPackage.name,
          packageVersion: currentPackage.version,
          evidence: [
            `previous version: ${previousByName.version}`,
            `new dependencies: ${newDependencies.join(', ')}`,
          ],
          recommendation:
            'Review the package diff before allowing installation. Sudden dependency expansion on mature packages is a high-value supply chain signal.',
        });
      }

      if (currentPackage.sourceFileCount > 0) {
        const ghostDependencies = newDependencies.filter((dependency) =>
          currentPackage.unusedDeclaredDependencies.includes(dependency),
        );
        if (ghostDependencies.length > 0) {
          issues.push({
            id: `${key}:ghost-dependencies`,
            code: 'GR_GHOST_DEPENDENCY',
            category: 'ghost-dependency',
            severity: trustedPackages.has(currentPackage.name) ? 'critical' : 'high',
            title: 'New dependencies are declared but not imported by package source',
            description:
              `${currentPackage.name}@${currentPackage.version} introduced dependencies that do not appear in the package source import graph. This matches the ghost dependency pattern used to hide postinstall droppers.`,
            packageName: currentPackage.name,
            packageVersion: currentPackage.version,
            evidence: [
              `ghost dependencies: ${ghostDependencies.join(', ')}`,
              `baseline version: ${previousByName.version}`,
            ],
            recommendation:
              'Block installation until the maintainer explains the dependency and the package tarball is manually reviewed.',
          });
        }
      }

      if (addedScripts.length > 0 || changedScripts.length > 0) {
        issues.push({
          id: `${key}:lifecycle-changed`,
          code: 'GR_LIFECYCLE_SCRIPT_DELTA',
          category: 'lifecycle-script',
          severity: 'high',
          title: 'Lifecycle scripts were added or changed',
          description:
            `${currentPackage.name}@${currentPackage.version} changed install-time lifecycle scripts compared with the signed baseline.`,
          packageName: currentPackage.name,
          packageVersion: currentPackage.version,
          evidence: [
            `added scripts: ${addedScripts.join(', ') || 'none'}`,
            `changed scripts: ${changedScripts.join(', ') || 'none'}`,
          ],
          recommendation:
            'Treat new or changed install scripts as code execution events. Review the script body and any referenced files before continuing.',
        });
      }
    }

    for (const finding of currentPackage.scriptFindings) {
      if (finding.score < threshold) {
        continue;
      }
      issues.push({
        id: `${key}:${finding.scriptName}`,
        code: 'GR_RISKY_LIFECYCLE_SCRIPT',
        category: 'lifecycle-script',
        severity: finding.severity,
        title: 'Lifecycle script exceeded the GuardRail risk threshold',
        description:
          `${currentPackage.name}@${currentPackage.version} has a ${finding.scriptName} script with risk score ${String(finding.score)}.`,
        packageName: currentPackage.name,
        packageVersion: currentPackage.version,
        score: finding.score,
        evidence: [...finding.reasons, ...finding.evidence].slice(0, 12),
        recommendation:
          'Run installs with --ignore-scripts until the package is reviewed. Investigate network access, file writes, obfuscation, and script-spawn behavior in the lifecycle hook.',
      });
    }
  }

  return issues.sort((left, right) => severityToNumber(right.severity) - severityToNumber(left.severity));
}

function mergeInstalledAndLockfilePackages(
  lockfile: LockfileInfo,
  installedPackages: Record<string, PackageSnapshot>,
  rootDir: string,
  config: GuardrailConfig,
): Record<string, PackageSnapshot> {
  const merged: Record<string, PackageSnapshot> = { ...installedPackages };

  for (const node of lockfile.packages) {
    const key = snapshotKey(node.name, node.version);
    if (merged[key]) {
      // Backfill hasInstallScripts from lockfile onto existing snapshots
      if (node.hasInstallScripts && !merged[key]?.hasInstallScripts) {
        (merged[key] as PackageSnapshot).hasInstallScripts = true;
      }
      continue;
    }
    merged[key] = buildMinimalSnapshotFromLockfile(node, rootDir, config);
  }

  return merged;
}

function buildMinimalSnapshotFromLockfile(node: PackageNode, rootDir: string, config: GuardrailConfig): PackageSnapshot {
  const declaredDependencies = Object.keys(node.dependencies).sort();

  // Try to read lifecycle scripts from the installed package in node_modules
  let lifecycleScripts: Record<string, string> = {};
  const possibleDir = node.path
    ? path.join(rootDir, node.path)
    : path.join(rootDir, 'node_modules', node.name);
  const manifestPath = path.join(possibleDir, 'package.json');
  try {
    if (fs.existsSync(manifestPath)) {
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as Record<string, unknown>;
      lifecycleScripts = pickLifecycleScripts(normalizeScriptRecord(manifest.scripts));
    }
  } catch { /* ignore read errors */ }

  const scriptFindings = Object.keys(lifecycleScripts).length > 0
    ? analyzeLifecycleScripts(node.name, node.version, lifecycleScripts, (relativePath) =>
        readLocalScriptFile(possibleDir, relativePath, config.scan?.maxScriptFileBytes ?? 256000),
      )
    : [];

  return {
    name: node.name,
    version: node.version,
    packagePath: node.path,
    declaredDependencies,
    optionalDependencies: [],
    peerDependencies: [],
    importedDependencies: [],
    unusedDeclaredDependencies: [],
    lifecycleScripts,
    lifecycleScriptHashes: hashLifecycleScripts(lifecycleScripts),
    scriptFindings,
    highestScriptRisk: highestScriptRisk(scriptFindings),
    sourceFileCount: 0,
    manifestHash: sha256(JSON.stringify(node.dependencies)),
    sourceHash: sha256(`${node.name}@${node.version}`),
    packageHash: sha256(JSON.stringify(node)),
    hasInstallScripts: node.hasInstallScripts,
  };
}

function collectInstalledPackageSnapshots(
  rootDir: string,
  config: GuardrailConfig,
): Record<string, PackageSnapshot> {
  const snapshots: Record<string, PackageSnapshot> = {};
  const rootNodeModules = path.join(rootDir, 'node_modules');
  if (!fs.existsSync(rootNodeModules)) {
    return snapshots;
  }

  const visitedPackageDirs = new Set<string>();
  const visitedContainers = new Set<string>();

  const visitContainer = (containerPath: string): void => {
    const realContainer = safeRealpath(containerPath);
    if (!realContainer || visitedContainers.has(realContainer) || !fs.existsSync(containerPath)) {
      return;
    }
    visitedContainers.add(realContainer);

    for (const entry of fs.readdirSync(containerPath)) {
      if (entry === '.bin') {
        continue;
      }
      const entryPath = path.join(containerPath, entry);
      if (!isDirectory(entryPath)) {
        continue;
      }

      if (entry === '.pnpm') {
        for (const nested of fs.readdirSync(entryPath)) {
          const nestedNodeModules = path.join(entryPath, nested, 'node_modules');
          if (fs.existsSync(nestedNodeModules)) {
            visitContainer(nestedNodeModules);
          }
        }
        continue;
      }

      if (entry.startsWith('@')) {
        for (const scopedEntry of fs.readdirSync(entryPath)) {
          const packageDir = path.join(entryPath, scopedEntry);
          if (fs.existsSync(path.join(packageDir, 'package.json'))) {
            processPackageDir(packageDir);
          }
        }
        continue;
      }

      if (fs.existsSync(path.join(entryPath, 'package.json'))) {
        processPackageDir(entryPath);
      }
    }
  };

  const processPackageDir = (packageDir: string): void => {
    const realPackageDir = safeRealpath(packageDir);
    if (!realPackageDir || visitedPackageDirs.has(realPackageDir)) {
      return;
    }
    visitedPackageDirs.add(realPackageDir);

    const snapshot = analyzeInstalledPackage(packageDir, config);
    if (snapshot) {
      snapshots[snapshotKey(snapshot.name, snapshot.version)] = snapshot;
    }

    const nestedNodeModules = path.join(packageDir, 'node_modules');
    if (fs.existsSync(nestedNodeModules)) {
      visitContainer(nestedNodeModules);
    }
  };

  visitContainer(rootNodeModules);
  return snapshots;
}

function analyzeInstalledPackage(
  packageDir: string,
  config: GuardrailConfig,
): PackageSnapshot | null {
  const manifestPath = path.join(packageDir, 'package.json');
  if (!fs.existsSync(manifestPath)) {
    return null;
  }

  try {
    const manifestText = fs.readFileSync(manifestPath, 'utf8');
    const manifest = JSON.parse(manifestText) as Record<string, unknown>;
    const name = typeof manifest.name === 'string' ? manifest.name : undefined;
    const version = typeof manifest.version === 'string' ? manifest.version : undefined;
    if (!name || !version) {
      return null;
    }

    const declaredDependencies = Object.keys(toRecord(manifest.dependencies)).sort();
    const optionalDependencies = Object.keys(toRecord(manifest.optionalDependencies)).sort();
    const peerDependencies = Object.keys(toRecord(manifest.peerDependencies)).sort();
    const lifecycleScripts = pickLifecycleScripts(normalizeScriptRecord(manifest.scripts));
    const importedDependencies = Array.from(scanImportsInDirectory(packageDir, config)).sort();
    const unusedDeclaredDependencies = declaredDependencies.filter(
      (dependency) => !importedDependencies.includes(dependency),
    );
    const scriptFindings = analyzeLifecycleScripts(name, version, lifecycleScripts, (relativePath) =>
      readLocalScriptFile(packageDir, relativePath, config.scan?.maxScriptFileBytes ?? 256000),
    );

    const sourceHashes = collectSourceHashes(packageDir, config);
    const sourceHash = sha256(sourceHashes.join('\n'));
    const manifestHash = sha256(manifestText);

    return {
      name,
      version,
      packagePath: packageDir,
      declaredDependencies,
      optionalDependencies,
      peerDependencies,
      importedDependencies,
      unusedDeclaredDependencies,
      lifecycleScripts,
      lifecycleScriptHashes: hashLifecycleScripts(lifecycleScripts),
      scriptFindings,
      highestScriptRisk: highestScriptRisk(scriptFindings),
      sourceFileCount: sourceHashes.length,
      manifestHash,
      sourceHash,
      packageHash: sha256([manifestHash, sourceHash, JSON.stringify(lifecycleScripts)].join(':')),
    };
  } catch {
    return null;
  }
}

function scanImportsInDirectory(packageDir: string, config: GuardrailConfig): Set<string> {
  const imports = new Set<string>();
  for (const filePath of listSourceFiles(packageDir, config)) {
    const text = fs.readFileSync(filePath, 'utf8');
    for (const specifier of extractModuleSpecifiers(text)) {
      const packageName = normalizeModuleSpecifier(specifier);
      if (packageName) {
        imports.add(packageName);
      }
    }
  }
  return imports;
}

function listSourceFiles(packageDir: string, config: GuardrailConfig): string[] {
  const files: string[] = [];
  const ignored = new Set([...(config.scan?.ignoreDirs ?? []), ...PACKAGE_SCAN_IGNORE_DIRS]);
  const stack = [packageDir];
  const maxFiles = 800;

  while (stack.length > 0 && files.length < maxFiles) {
    const currentDir = stack.pop() as string;
    for (const entry of fs.readdirSync(currentDir, { withFileTypes: true })) {
      const entryPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (ignored.has(entry.name)) {
          continue;
        }
        stack.push(entryPath);
        continue;
      }
      if (!entry.isFile() || !SOURCE_FILE_PATTERN.test(entry.name)) {
        continue;
      }
      const stats = fs.statSync(entryPath);
      if (stats.size > 512000) {
        continue;
      }
      files.push(entryPath);
      if (files.length >= maxFiles) {
        break;
      }
    }
  }

  return files;
}

function collectSourceHashes(packageDir: string, config: GuardrailConfig): string[] {
  return listSourceFiles(packageDir, config)
    .map((filePath) => `${path.relative(packageDir, filePath)}:${sha256(fs.readFileSync(filePath))}`)
    .sort();
}

function readLocalScriptFile(packageDir: string, relativePath: string, maxBytes: number): string | undefined {
  const candidate = path.join(packageDir, relativePath.replace(/^\.\//, ''));
  if (!fs.existsSync(candidate) || !fs.statSync(candidate).isFile()) {
    return undefined;
  }
  const stats = fs.statSync(candidate);
  if (stats.size > maxBytes) {
    return undefined;
  }
  return fs.readFileSync(candidate, 'utf8');
}

function extractModuleSpecifiers(source: string): string[] {
  const patterns = [
    /import\s+[^'"`]+?from\s+['"`]([^'"`]+)['"`]/g,
    /import\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g,
    /require\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g,
    /export\s+[^'"`]+?from\s+['"`]([^'"`]+)['"`]/g,
  ];

  const result: string[] = [];
  for (const pattern of patterns) {
    let match: RegExpExecArray | null = pattern.exec(source);
    while (match) {
      if (match[1]) {
        result.push(match[1]);
      }
      match = pattern.exec(source);
    }
  }
  return result;
}

function normalizeModuleSpecifier(specifier: string): string | undefined {
  if (!specifier || specifier.startsWith('.') || specifier.startsWith('/') || specifier.startsWith('node:')) {
    return undefined;
  }
  const segments = specifier.split('/').filter(Boolean);
  if (segments.length === 0) {
    return undefined;
  }
  if (segments[0]?.startsWith('@') && segments[1]) {
    return `${segments[0]}/${segments[1]}`;
  }
  return segments[0];
}

function normalizeScriptRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') {
    return {};
  }
  const result: Record<string, string> = {};
  for (const [name, rawCommand] of Object.entries(value as Record<string, unknown>)) {
    if (typeof rawCommand === 'string') {
      result[name] = rawCommand;
    }
  }
  return result;
}

function toRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') {
    return {};
  }
  const result: Record<string, string> = {};
  for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
    if (typeof raw === 'string') {
      result[key] = raw;
    }
  }
  return result;
}

function safeRealpath(candidate: string): string | null {
  try {
    return fs.realpathSync(candidate);
  } catch {
    return null;
  }
}

function isDirectory(candidate: string): boolean {
  try {
    return fs.statSync(candidate).isDirectory();
  } catch {
    return false;
  }
}

function installPreCommitHook(rootDir: string): void {
  const hookPath = path.join(rootDir, '.git', 'hooks', 'pre-commit');
  fs.mkdirSync(path.dirname(hookPath), { recursive: true });
  fs.writeFileSync(
    hookPath,
    '#!/usr/bin/env sh\nset -eu\nif command -v guardrail >/dev/null 2>&1; then\n  guardrail scan --fail-fast --quiet\nelse\n  npx guardrail-security scan --fail-fast --quiet\nfi\n',
    { mode: 0o755 },
  );
}

function writeWorkflow(rootDir: string): void {
  const workflowPath = path.join(rootDir, '.github', 'workflows', 'guardrail.yml');
  fs.mkdirSync(path.dirname(workflowPath), { recursive: true });
  fs.writeFileSync(workflowPath, generateGuardrailWorkflow());
}

function detectProjectGhostDependencies(
  rootDir: string,
  rootManifest: Record<string, unknown>,
  packageMap: Record<string, PackageSnapshot>,
  lockfilePackages: PackageNode[],
  config: GuardrailConfig,
): ScanIssue[] {
  const issues: ScanIssue[] = [];
  const projectImports = scanProjectImports(rootDir, config);

  const trustedScriptPackages = new Set<string>([
    'fsevents', 'cpu-features', 'node-gyp', 'node-pre-gyp',
    '@mapbox/node-pre-gyp', 'prebuild-install', 'node-addon-api',
    'bindings', 'nan', 'node-gyp-build', 'esbuild', 'turbo',
    ...(config.scan?.trustedScriptPackages ?? []),
  ]);

  // Get all direct dependencies declared in the project's package.json
  const declaredDeps = new Set<string>([
    ...Object.keys(toRecord(rootManifest.dependencies)),
    ...Object.keys(toRecord(rootManifest.devDependencies)),
  ]);

  // Build a set of packages that have install scripts (from lockfile flag, snapshot, or lockfile node)
  const packagesWithScripts = new Set<string>();
  for (const node of lockfilePackages) {
    if (node.hasInstallScripts) {
      packagesWithScripts.add(node.name);
    }
  }
  for (const snap of Object.values(packageMap)) {
    if (Object.keys(snap.lifecycleScripts).length > 0 || snap.hasInstallScripts) {
      packagesWithScripts.add(snap.name);
    }
  }

  // Check every declared dependency — flag if never imported
  for (const packageName of declaredDeps) {
    if (trustedScriptPackages.has(packageName)) continue;
    if (projectImports.has(packageName)) continue;

    const snap = Object.values(packageMap).find(s => s.name === packageName);
    const hasScripts = packagesWithScripts.has(packageName);
    const scriptNames = snap && Object.keys(snap.lifecycleScripts).length > 0
      ? Object.keys(snap.lifecycleScripts).join(', ')
      : hasScripts ? 'install script (from lockfile)' : 'none';
    const scriptScore = snap?.highestScriptRisk ?? 0;

    if (hasScripts) {
      // Has install scripts + never imported = HIGH or CRITICAL
      const severity: Severity = scriptScore >= 70 ? 'critical' : 'high';
      issues.push({
        id: `project:${packageName}:ghost-unimported`,
        code: 'GR_GHOST_DEPENDENCY_UNIMPORTED',
        category: 'ghost-dependency',
        severity,
        title: 'Package has install scripts but is never imported by project source',
        description:
          `${packageName} has lifecycle scripts (${scriptNames}) but no import, require, or re-export of this package was found anywhere in the project source tree. ` +
          `This matches the ghost dependency pattern used in supply chain attacks like the axios/plain-crypto-js incident.`,
        packageName,
        packageVersion: snap?.version,
        evidence: [
          `lifecycle scripts: ${scriptNames}`,
          `behavior score: ${String(scriptScore)}`,
          `imported in project source: no`,
          `in package.json: yes (direct dependency)`,
        ],
        recommendation:
          'If this package was not intentionally added, treat the environment as compromised. ' +
          'Add to scan.trustedScriptPackages in guardrail.config.json if this is a known-safe native module.',
      });
    } else {
      // No install scripts but still never imported = MEDIUM (unused dep)
      issues.push({
        id: `project:${packageName}:unused-dependency`,
        code: 'GR_UNUSED_DEPENDENCY',
        category: 'ghost-dependency',
        severity: 'medium',
        title: 'Declared dependency is never imported by project source',
        description:
          `${packageName} is listed in package.json but no import, require, or re-export was found in the project source tree. ` +
          `While this package has no install scripts, unused dependencies increase attack surface.`,
        packageName,
        packageVersion: snap?.version,
        evidence: [
          `imported in project source: no`,
          `in package.json: yes (direct dependency)`,
          `has install scripts: no`,
        ],
        recommendation:
          'Remove this dependency if it is not needed, or verify it is used via a mechanism GuardRail cannot detect (e.g., CLI tool, config reference).',
      });
    }
  }

  return issues;
}

function scanProjectImports(rootDir: string, config: GuardrailConfig): Set<string> {
  const imports = new Set<string>();
  const ignored = new Set([
    'node_modules', '.git', '.hg', 'dist', 'build', 'coverage',
    '.nyc_output', '.next', '.nuxt',
    ...(config.scan?.ignoreDirs ?? []),
  ]);
  const sourcePattern = /\.(?:[cm]?[jt]sx?|vue|svelte)$/i;
  const stack = [rootDir];
  const maxFiles = 2000;
  let fileCount = 0;

  while (stack.length > 0 && fileCount < maxFiles) {
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const entryPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!ignored.has(entry.name)) stack.push(entryPath);
        continue;
      }
      if (!entry.isFile() || !sourcePattern.test(entry.name)) continue;
      try {
        const stats = fs.statSync(entryPath);
        if (stats.size > 512000) continue;
      } catch { continue; }
      fileCount++;
      try {
        const text = fs.readFileSync(entryPath, 'utf8');
        for (const specifier of extractModuleSpecifiers(text)) {
          const pkgName = normalizeModuleSpecifier(specifier);
          if (pkgName) imports.add(pkgName);
        }
      } catch { /* skip unreadable files */ }
    }
  }

  return imports;
}

function checkIocs(
  packageMap: Record<string, PackageSnapshot>,
  config: GuardrailConfig,
): ScanIssue[] {
  const issues: ScanIssue[] = [];

  const builtinIocs: Record<string, { reason: string; advisory?: string }> = {
    'plain-crypto-js': {
      reason: 'Package used in the March 2026 axios supply chain attack as a RAT dropper (SILKBELL)',
      advisory: 'GHSA-fw8c-xr5c-95f9',
    },
  };

  const customIocs = config.customIocs ?? [];
  const allIocs = new Map<string, { reason: string; advisory?: string; source: 'built-in' | 'custom' }>();

  for (const [name, info] of Object.entries(builtinIocs)) {
    allIocs.set(name, { ...info, source: 'built-in' });
  }
  for (const ioc of customIocs) {
    allIocs.set(ioc.packageName, { reason: ioc.reason, advisory: ioc.advisory, source: 'custom' });
  }

  for (const snap of Object.values(packageMap)) {
    const match = allIocs.get(snap.name);
    if (!match) continue;

    issues.push({
      id: `ioc:${snap.name}@${snap.version}`,
      code: 'GR_KNOWN_MALICIOUS_PACKAGE',
      category: 'ioc',
      severity: 'critical',
      title: `Known malicious package detected: ${snap.name}`,
      description: match.reason,
      packageName: snap.name,
      packageVersion: snap.version,
      evidence: [
        `source: ${match.source}`,
        ...(match.advisory ? [`advisory: ${match.advisory}`] : []),
      ],
      recommendation: 'Remove this package immediately. If it was installed, treat the environment as compromised and rotate all credentials.',
    });
  }

  return issues;
}

function printScanResult(result: ScanExecutionResult, threshold: number, baselineWasUpdated: boolean): void {
  console.log(`GuardRail scan`);
  console.log(`root: ${result.rootDir}`);
  console.log(`baseline: ${result.baselinePath} (${result.baselineCreated ? 'created' : result.baselineVerified ? 'verified' : 'unverified'})`);
  console.log(`lockfile: ${result.lockfile.kind}${result.lockfile.path ? ` (${result.lockfile.path})` : ''}`);
  console.log(`packages scanned: ${String(result.packagesScanned)}`);
  console.log(`lifecycle scripts discovered: ${String(result.lifecycleScriptsDiscovered)}`);
  console.log(`risk threshold: ${String(threshold)}`);
  if (baselineWasUpdated || result.baselineCreated) {
    console.log(`baseline updated: yes`);
  }

  for (const warning of result.lockfile.warnings) {
    console.log(`warning: ${warning}`);
  }

  console.log('');
  console.log('Lifecycle script inventory:');
  const scriptLines = Object.values(result.packages)
    .flatMap((pkg) =>
      Object.entries(pkg.lifecycleScripts).map(([name, command]) => {
        const score = pkg.scriptFindings.find((finding) => finding.scriptName === name)?.score ?? 0;
        return `- ${pkg.name}@${pkg.version} ${name} [score=${String(score)}] ${command}`;
      }),
    )
    .sort();

  if (scriptLines.length === 0) {
    console.log('- none');
  } else {
    for (const line of scriptLines) {
      console.log(line);
    }
  }

  console.log('');
  console.log(`Findings: ${String(result.issues.length)}`);
  if (result.issues.length === 0) {
    console.log('- no findings above current policy');
    return;
  }

  for (const issue of result.issues) {
    const pkg = issue.packageName && issue.packageVersion ? ` ${issue.packageName}@${issue.packageVersion}` : '';
    console.log(`- [${issue.severity}] ${issue.code}${pkg}: ${issue.title}`);
    console.log(`  ${issue.description}`);
    if (issue.evidence && issue.evidence.length > 0) {
      console.log(`  evidence: ${issue.evidence.join(' | ')}`);
    }
    if (issue.recommendation) {
      console.log(`  action: ${issue.recommendation}`);
    }
  }
}
