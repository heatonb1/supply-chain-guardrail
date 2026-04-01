import * as fs from 'node:fs';
import * as path from 'node:path';
import * as childProcess from 'node:child_process';

import { LockfileInfo, PackageNode } from '../types';
import { parseJsonc } from '../core/baseline';

export function parseLockfile(rootDir: string): LockfileInfo {
  const candidates = [
    { kind: 'package-lock', path: path.join(rootDir, 'package-lock.json') },
    { kind: 'pnpm-lock', path: path.join(rootDir, 'pnpm-lock.yaml') },
    { kind: 'yarn-lock', path: path.join(rootDir, 'yarn.lock') },
    { kind: 'bun-lock', path: path.join(rootDir, 'bun.lock') },
    { kind: 'bun-lockb', path: path.join(rootDir, 'bun.lockb') },
  ] as const;

  for (const candidate of candidates) {
    if (!fs.existsSync(candidate.path)) {
      continue;
    }

    switch (candidate.kind) {
      case 'package-lock':
        return parsePackageLock(candidate.path);
      case 'pnpm-lock':
        return parsePnpmLock(candidate.path);
      case 'yarn-lock':
        return parseYarnLock(candidate.path);
      case 'bun-lock':
        return parseBunLock(candidate.path);
      case 'bun-lockb':
        return parseBinaryBunLock(rootDir, candidate.path);
      default:
        break;
    }
  }

  return {
    kind: 'none',
    packages: [],
    directDependencies: {},
    warnings: ['No supported lockfile found. Scan will fall back to installed packages only.'],
  };
}

function parsePackageLock(filePath: string): LockfileInfo {
  const data = parseJsonc<Record<string, unknown>>(fs.readFileSync(filePath, 'utf8'));
  const packages: PackageNode[] = [];
  const warnings: string[] = [];
  let directDependencies: Record<string, string> = {};

  const packageEntries = (data.packages ?? {}) as Record<string, unknown>;
  if (Object.keys(packageEntries).length > 0) {
    const rootPackage = packageEntries[''] as Record<string, unknown> | undefined;
    directDependencies = normalizeDependencyRecord(rootPackage?.dependencies);

    for (const [packagePath, rawMeta] of Object.entries(packageEntries)) {
      if (packagePath === '' || !rawMeta || typeof rawMeta !== 'object') {
        continue;
      }
      const metadata = rawMeta as Record<string, unknown>;
      const name = String(metadata.name ?? inferNameFromNodeModulesPath(packagePath) ?? '');
      const version = String(metadata.version ?? '');
      if (!name || !version) {
        continue;
      }
      packages.push({
        name,
        version,
        dependencies: normalizeDependencyRecord(metadata.dependencies),
        resolved: typeof metadata.resolved === 'string' ? metadata.resolved : undefined,
        integrity: typeof metadata.integrity === 'string' ? metadata.integrity : undefined,
        path: packagePath,
        dev: Boolean(metadata.dev),
        optional: Boolean(metadata.optional),
        hasInstallScripts: Boolean(metadata.hasInstallScripts),
      });
    }
  } else if (data.dependencies && typeof data.dependencies === 'object') {
    directDependencies = extractLegacyRootDependencies(data.dependencies as Record<string, unknown>);
    walkLegacyPackageLock('', data.dependencies as Record<string, unknown>, packages);
  } else {
    warnings.push('package-lock.json was present but no package entries were readable.');
  }

  return {
    kind: 'package-lock',
    path: filePath,
    packages: dedupePackages(packages),
    directDependencies,
    warnings,
  };
}

function walkLegacyPackageLock(
  prefix: string,
  dependencies: Record<string, unknown>,
  packages: PackageNode[],
): void {
  for (const [name, rawMeta] of Object.entries(dependencies)) {
    if (!rawMeta || typeof rawMeta !== 'object') {
      continue;
    }
    const metadata = rawMeta as Record<string, unknown>;
    const version = String(metadata.version ?? '');
    if (!version) {
      continue;
    }
    packages.push({
      name,
      version,
      dependencies: normalizeDependencyRecord(metadata.requires),
      resolved: typeof metadata.resolved === 'string' ? metadata.resolved : undefined,
      integrity: typeof metadata.integrity === 'string' ? metadata.integrity : undefined,
      path: prefix ? `${prefix}/node_modules/${name}` : `node_modules/${name}`,
      dev: Boolean(metadata.dev),
      optional: Boolean(metadata.optional),
    });

    const nested = metadata.dependencies;
    if (nested && typeof nested === 'object') {
      walkLegacyPackageLock(prefix ? `${prefix}/node_modules/${name}` : `node_modules/${name}`, nested as Record<string, unknown>, packages);
    }
  }
}

function extractLegacyRootDependencies(dependencies: Record<string, unknown>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, rawMeta] of Object.entries(dependencies)) {
    if (!rawMeta || typeof rawMeta !== 'object') {
      continue;
    }
    const version = (rawMeta as Record<string, unknown>).version;
    if (typeof version === 'string') {
      result[name] = version;
    }
  }
  return result;
}

function inferNameFromNodeModulesPath(packagePath: string): string | undefined {
  const normalized = packagePath.replace(/\\/g, '/');
  const marker = 'node_modules/';
  const index = normalized.lastIndexOf(marker);
  if (index === -1) {
    return undefined;
  }
  const tail = normalized.slice(index + marker.length);
  const parts = tail.split('/').filter(Boolean);
  const first = parts[0];
  const second = parts[1];
  if (first?.startsWith('@') && second) {
    return `${first}/${second}`;
  }
  return first;
}

function parsePnpmLock(filePath: string): LockfileInfo {
  const text = fs.readFileSync(filePath, 'utf8');
  const packages: PackageNode[] = [];
  const directDependencies: Record<string, string> = {};
  const warnings: string[] = [];

  let section: 'none' | 'importers' | 'packages' = 'none';
  let importerSubsection = '';
  let currentDependencyName = '';
  let currentPackage: PackageNode | null = null;
  let packageSubsection = '';

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\t/g, '    ');
    const trimmed = line.trim();
    const indent = line.search(/\S|$/);

    if (trimmed.length === 0 || trimmed.startsWith('#')) {
      continue;
    }

    if (trimmed === 'importers:') {
      section = 'importers';
      importerSubsection = '';
      currentDependencyName = '';
      currentPackage = null;
      continue;
    }

    if (trimmed === 'packages:') {
      section = 'packages';
      importerSubsection = '';
      currentDependencyName = '';
      currentPackage = null;
      continue;
    }

    if (section === 'importers') {
      if (indent === 2 && trimmed.endsWith(':')) {
        importerSubsection = '';
        currentDependencyName = '';
        continue;
      }

      if (indent === 4 && trimmed.endsWith(':')) {
        importerSubsection = trimmed.slice(0, -1);
        currentDependencyName = '';
        continue;
      }

      if ((importerSubsection === 'dependencies' || importerSubsection === 'optionalDependencies') && indent === 6 && trimmed.endsWith(':')) {
        currentDependencyName = unquoteYaml(trimmed.slice(0, -1));
        continue;
      }

      if ((importerSubsection === 'dependencies' || importerSubsection === 'optionalDependencies') && indent === 8 && trimmed.startsWith('version:')) {
        if (currentDependencyName) {
          directDependencies[currentDependencyName] = normalizePnpmVersionValue(trimmed.slice('version:'.length).trim());
        }
        continue;
      }

      if ((importerSubsection === 'dependencies' || importerSubsection === 'optionalDependencies') && indent === 6 && trimmed.includes(':') && !trimmed.endsWith(':')) {
        const separator = trimmed.indexOf(':');
        const name = unquoteYaml(trimmed.slice(0, separator));
        const version = normalizePnpmVersionValue(trimmed.slice(separator + 1).trim());
        if (name && version) {
          directDependencies[name] = version;
        }
      }

      continue;
    }

    if (section === 'packages') {
      if (indent === 2 && trimmed.endsWith(':')) {
        const key = unquoteYaml(trimmed.slice(0, -1));
        const parsed = parsePnpmPackageKey(key);
        if (!parsed) {
          currentPackage = null;
          continue;
        }
        currentPackage = {
          name: parsed.name,
          version: parsed.version,
          dependencies: {},
          path: `pnpm:${key}`,
        };
        packages.push(currentPackage);
        packageSubsection = '';
        continue;
      }

      if (!currentPackage) {
        continue;
      }

      if (indent === 4 && trimmed.endsWith(':')) {
        packageSubsection = trimmed.slice(0, -1);
        continue;
      }

      if (indent === 4 && trimmed.startsWith('resolution:')) {
        const integrityMatch = trimmed.match(/integrity:\s*([^,}]+)/i);
        if (integrityMatch?.[1]) {
          currentPackage.integrity = normalizePnpmVersionValue(integrityMatch[1]);
        }
        continue;
      }

      if (packageSubsection === 'dependencies' && indent === 6 && trimmed.includes(':')) {
        const separator = trimmed.indexOf(':');
        const name = unquoteYaml(trimmed.slice(0, separator));
        const version = normalizePnpmVersionValue(trimmed.slice(separator + 1).trim());
        if (name && version) {
          currentPackage.dependencies[name] = version;
        }
      }
    }
  }

  if (packages.length === 0) {
    warnings.push('pnpm-lock.yaml could not be fully parsed. Falling back to installed packages is recommended.');
  }

  return {
    kind: 'pnpm-lock',
    path: filePath,
    packages: dedupePackages(packages),
    directDependencies,
    warnings,
  };
}

function normalizePnpmVersionValue(input: string): string {
  const cleaned = unquoteYaml(input).replace(/^link:/, '').replace(/^workspace:/, '').trim();
  const separator = cleaned.indexOf('(');
  return separator >= 0 ? cleaned.slice(0, separator).trim() : cleaned;
}

function parsePnpmPackageKey(key: string): { name: string; version: string } | null {
  const normalized = key.startsWith('/') ? key.slice(1) : key;
  const separator = normalized.lastIndexOf('@');
  if (separator <= 0) {
    return null;
  }
  const name = normalized.slice(0, separator);
  const version = normalizePnpmVersionValue(normalized.slice(separator + 1));
  if (!name || !version) {
    return null;
  }
  return { name, version };
}

function parseYarnLock(filePath: string): LockfileInfo {
  const text = fs.readFileSync(filePath, 'utf8');
  const blocks = text.split(/\n{2,}/);
  const packages: PackageNode[] = [];
  const directDependencies: Record<string, string> = {};

  for (const block of blocks) {
    const lines = block
      .split(/\r?\n/)
      .map((line: string) => line.replace(/\r/g, ''))
      .filter((line: string) => line.trim().length > 0);

    if (lines.length === 0 || lines[0].startsWith('#')) {
      continue;
    }

    const keyLine = lines[0];
    const firstSpecifier = keyLine.split(',')[0]?.replace(/:$/, '').trim().replace(/^"|"$/g, '');
    if (!firstSpecifier) {
      continue;
    }

    const packageName = inferNameFromSpecifier(firstSpecifier);
    if (!packageName) {
      continue;
    }

    const node: PackageNode = {
      name: packageName,
      version: '',
      dependencies: {},
      path: `yarn:${packageName}`,
    };

    let subsection = '';
    for (const line of lines.slice(1)) {
      const trimmed = line.trim();
      if (trimmed.startsWith('version ')) {
        node.version = trimmed.replace(/^version\s+/, '').replace(/^"|"$/g, '');
        continue;
      }
      if (trimmed.startsWith('resolved ')) {
        node.resolved = trimmed.replace(/^resolved\s+/, '').replace(/^"|"$/g, '');
        continue;
      }
      if (trimmed.startsWith('integrity ')) {
        node.integrity = trimmed.replace(/^integrity\s+/, '').replace(/^"|"$/g, '');
        continue;
      }
      if (trimmed === 'dependencies:' || trimmed === 'optionalDependencies:') {
        subsection = trimmed.replace(/:$/, '');
        continue;
      }
      if ((subsection === 'dependencies' || subsection === 'optionalDependencies') && line.startsWith('    ')) {
        const match = trimmed.match(/^([^\s]+)\s+(.+)$/);
        if (match?.[1] && match[2]) {
          node.dependencies[match[1].replace(/^"|"$/g, '')] = match[2].replace(/^"|"$/g, '');
        }
      }
    }

    if (node.version) {
      packages.push(node);
      if (!(node.name in directDependencies)) {
        directDependencies[node.name] = node.version;
      }
    }
  }

  return {
    kind: 'yarn-lock',
    path: filePath,
    packages: dedupePackages(packages),
    directDependencies,
    warnings: packages.length === 0 ? ['yarn.lock could not be parsed cleanly.'] : [],
  };
}

function parseBunLock(filePath: string): LockfileInfo {
  const text = fs.readFileSync(filePath, 'utf8');
  const warnings: string[] = [];
  const packages: PackageNode[] = [];
  const directDependencies: Record<string, string> = {};

  if (/^\s*"[^"]+":\s*\[/m.test(text)) {
    const lines = text.split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      const match = trimmed.match(/^"([^"]+)":\s*\[\s*"([^"]+)@([^"]+)"/);
      if (!match?.[1] || !match[2] || !match[3]) {
        continue;
      }
      const name = match[2];
      const version = match[3];
      packages.push({
        name,
        version,
        dependencies: {},
        path: `bun:${match[1]}`,
      });
      if (!(name in directDependencies)) {
        directDependencies[name] = version;
      }
    }
  } else {
    warnings.push('bun.lock format was not recognized. Falling back to installed packages is recommended.');
  }

  return {
    kind: 'bun-lock',
    path: filePath,
    packages: dedupePackages(packages),
    directDependencies,
    warnings,
  };
}

function parseBinaryBunLock(rootDir: string, filePath: string): LockfileInfo {
  const warnings: string[] = [];
  try {
    const result = childProcess.spawnSync('bun', ['pm', 'ls', '--all', '--json'], {
      cwd: rootDir,
      encoding: 'utf8',
      maxBuffer: 10 * 1024 * 1024,
    });

    if (result.status !== 0 || !result.stdout) {
      warnings.push(result.stderr?.trim() || 'bun pm ls --all --json failed');
      return {
        kind: 'bun-lockb',
        path: filePath,
        packages: [],
        directDependencies: {},
        warnings,
      };
    }

    const parsed = JSON.parse(result.stdout) as Array<Record<string, unknown>>;
    const packages: PackageNode[] = [];
    for (const entry of parsed) {
      const name = typeof entry.name === 'string' ? entry.name : '';
      const version = typeof entry.version === 'string' ? entry.version : '';
      if (!name || !version) {
        continue;
      }
      packages.push({
        name,
        version,
        dependencies: {},
        path: `bun:${name}`,
      });
    }

    return {
      kind: 'bun-lockb',
      path: filePath,
      packages: dedupePackages(packages),
      directDependencies: Object.fromEntries(packages.map((pkg) => [pkg.name, pkg.version])),
      warnings,
    };
  } catch (error) {
    return {
      kind: 'bun-lockb',
      path: filePath,
      packages: [],
      directDependencies: {},
      warnings: [`bun.lockb found but Bun was unavailable: ${formatError(error)}`],
    };
  }
}

function formatError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function inferNameFromSpecifier(specifier: string): string {
  const cleaned = specifier.replace(/^npm:/, '');
  if (cleaned.startsWith('@')) {
    const segments = cleaned.split('@');
    return segments.length >= 3 ? `@${segments[1]}` : cleaned;
  }
  return cleaned.split('@')[0] ?? cleaned;
}

function normalizeDependencyRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') {
    return {};
  }
  const result: Record<string, string> = {};
  for (const [name, rawVersion] of Object.entries(value as Record<string, unknown>)) {
    if (typeof rawVersion === 'string') {
      result[name] = rawVersion;
    }
  }
  return result;
}

function dedupePackages(packages: PackageNode[]): PackageNode[] {
  const seen = new Map<string, PackageNode>();
  for (const pkg of packages) {
    const key = `${pkg.path ?? pkg.name}:${pkg.name}@${pkg.version}`;
    if (!seen.has(key)) {
      seen.set(key, pkg);
    }
  }
  return Array.from(seen.values());
}

function unquoteYaml(input: string): string {
  return input.trim().replace(/^['"]|['"]$/g, '');
}
