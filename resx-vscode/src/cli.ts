/**
 * RESX command catalog. Mirrors the option groups in `resx/src/cli/args.rs` so the
 * extension only passes options a command accepts; RESX rejects unused options.
 */

export type OptionGroup = 'lookup' | 'symbols' | 'analysis';

export interface CommandSpec {
    groups: readonly OptionGroup[];
    /** JSON envelope key (`kind`) the command emits. */
    kind?: string;
}

const IMAGE: readonly OptionGroup[] = ['lookup', 'symbols'];
const ANALYZED: readonly OptionGroup[] = ['lookup', 'symbols', 'analysis'];

export const COMMANDS = {
    peinfo: { groups: IMAGE, kind: 'peinfo' },
    sections: { groups: IMAGE, kind: 'sections' },
    pechk: { groups: IMAGE, kind: 'pechk' },
    eat: { groups: IMAGE, kind: 'eat' },
    iat: { groups: IMAGE, kind: 'iat' },
    syms: { groups: IMAGE, kind: 'syms' },
    types: { groups: IMAGE, kind: 'types' },
    dump: { groups: ANALYZED, kind: 'dump' },
    calls: { groups: ANALYZED, kind: 'dump' },
    xrefs: { groups: ANALYZED, kind: 'dump' },
    cfg: { groups: ANALYZED, kind: 'dump' },
    'reconstruct-cfg': { groups: ANALYZED, kind: 'reconstruct_cfg' },
    callers: { groups: ANALYZED, kind: 'callers' },
    intelli: { groups: ANALYZED, kind: 'dump' },
    behavior: { groups: ANALYZED, kind: 'behavior' },
    api: { groups: [], kind: 'api' },
    contracts: { groups: IMAGE, kind: 'contracts' },
    ipc: { groups: IMAGE, kind: 'ipc' },
    network: { groups: IMAGE, kind: 'network' },
    crypto: { groups: IMAGE, kind: 'crypto' },
    strings: { groups: IMAGE, kind: 'strings' },
    driver: { groups: IMAGE, kind: 'driver' },
    ioctl: { groups: IMAGE, kind: 'ioctl' },
    entropy: { groups: IMAGE, kind: 'entropy' },
    yara: { groups: IMAGE, kind: 'yara' },
    find: { groups: IMAGE, kind: 'find' },
    scan: { groups: ['symbols'], kind: 'scan' },
    diff: { groups: ANALYZED, kind: 'diff' },
    index: { groups: ANALYZED, kind: 'index' },
    hunt: { groups: ANALYZED, kind: 'hunt' },
    locate: { groups: IMAGE, kind: 'locate' },
    'locate-sym': { groups: IMAGE, kind: 'locate' },
    payload: { groups: [], kind: 'payload' },
    patch: { groups: IMAGE, kind: 'patch' },
    config: { groups: [], kind: 'config' },
} as const satisfies Record<string, CommandSpec>;

export type ResxCommand = keyof typeof COMMANDS;

/** Options shared across commands; each is emitted only where its group applies. */
export interface SharedOptions {
    /** Image lookup directories (`--path`, repeatable). */
    lookupPaths?: string[];
    /** Symbol search path entries, joined into one `--sym-path`. */
    symPaths?: string[];
    pdbFile?: string;
    symServer?: string;
    reloadSymbols?: boolean;
    noPdb?: boolean;
    /** Recovered API call arguments (`--args`). */
    apiArgs?: boolean;
    /** Skip SDK header enrichment for this run. */
    noHeaders?: boolean;
    hostile?: boolean;
    /** Per-function instruction budget; 0 means unlimited. */
    maxInsns?: number;
    /** Recursive traversal budget; 0 means unlimited. */
    maxTotal?: number;
}

export function commandAccepts(command: ResxCommand, group: OptionGroup): boolean {
    return (COMMANDS[command].groups as readonly OptionGroup[]).includes(group);
}

function budget(value: number): string {
    return value === 0 ? 'unlimited' : String(Math.floor(value));
}

/** Expands shared options into argv for `command`, dropping options it does not take. */
export function sharedArgs(command: ResxCommand, opts: SharedOptions = {}): string[] {
    const out: string[] = [];
    if (commandAccepts(command, 'lookup')) {
        for (const dir of opts.lookupPaths ?? []) {
            if (dir.trim()) out.push('--path', dir.trim());
        }
    }
    if (commandAccepts(command, 'symbols')) {
        const symPath = (opts.symPaths ?? []).map(p => p.trim()).filter(Boolean).join(';');
        if (symPath) out.push('--sym-path', symPath);
        if (opts.pdbFile?.trim()) out.push('--pdb', opts.pdbFile.trim());
        if (opts.symServer?.trim()) out.push('--sym-server', opts.symServer.trim());
        if (opts.reloadSymbols) out.push('--reload');
        if (opts.noPdb) out.push('--no-pdb');
        if (opts.apiArgs) out.push('--args');
        if (opts.noHeaders) out.push('--no-headers');
    }
    if (commandAccepts(command, 'analysis')) {
        if (opts.hostile) out.push('--hostile');
        if (opts.maxInsns !== undefined && opts.maxInsns >= 0) out.push('--max-insns', budget(opts.maxInsns));
        if (opts.maxTotal !== undefined && opts.maxTotal >= 0) out.push('--max-total', budget(opts.maxTotal));
    }
    return out;
}

/**
 * Full argv: command, command-specific flags, shared options, JSON output, then the
 * positional operands after `--` so a query or path starting with `-` stays an operand.
 */
export function buildArgs(
    command: ResxCommand,
    operands: string[],
    flags: string[] = [],
    opts: SharedOptions = {},
): string[] {
    const tail = operands.length ? ['--', ...operands] : [];
    return [command, ...flags, ...sharedArgs(command, opts), '--json', '--no-color', '--quiet', ...tail];
}

/**
 * Returns the command payload from a versioned `{schema_version, <key>: {...}}` envelope.
 * Documents without an envelope (`find`) or with several top-level keys are returned whole.
 */
export function unwrapEnvelope(data: unknown, key?: string): unknown {
    if (!data || typeof data !== 'object' || Array.isArray(data)) return data;
    const record = data as Record<string, unknown>;
    if (!('schema_version' in record)) return data;
    if (key && record[key] !== undefined) return record[key];
    const keys = Object.keys(record).filter(k => k !== 'schema_version' && k !== 'kind');
    if (keys.length === 1) {
        const value = record[keys[0]];
        if (value && typeof value === 'object' && !Array.isArray(value)) return value;
    }
    return data;
}

/** The single payload key of a versioned envelope, when there is one. */
export function envelopeKey(data: unknown): string | undefined {
    if (!data || typeof data !== 'object' || Array.isArray(data)) return undefined;
    const record = data as Record<string, unknown>;
    if (typeof record.kind === 'string') return record.kind;
    if (!('schema_version' in record)) return undefined;
    const keys = Object.keys(record).filter(k => k !== 'schema_version');
    return keys.length === 1 ? keys[0] : undefined;
}

export interface DumpRequest {
    image: string;
    target?: string;
    at?: string;
    callDepth?: number;
    callsOnly?: string[];
    callsExclude?: string[];
    ssa?: boolean;
    edrchk?: boolean;
    hookchk?: boolean;
}

/** Flags for the viewer's full dump: listing with bytes, call map, CFG, strings, xrefs and C. */
export function dumpFlags(req: DumpRequest): string[] {
    const flags: string[] = [];
    if (req.at) flags.push('--at', req.at);
    flags.push('--bytes', '--cfg', 'text', '--strings', '--xrefs', '--recomp');
    flags.push('--calls', String(clampInt(req.callDepth ?? 1, 1, 8)));
    if (req.callsOnly?.length) flags.push('--calls-only', req.callsOnly.join(','));
    if (req.callsExclude?.length) flags.push('--calls-exclude', req.callsExclude.join(','));
    if (req.ssa) flags.push('--ssa');
    if (req.hookchk) flags.push('--hookchk');
    if (req.edrchk) flags.push('--edrchk');
    return flags;
}

export function clampInt(value: unknown, min: number, max: number): number {
    const n = Math.floor(Number(value));
    if (!Number.isFinite(n)) return min;
    return Math.max(min, Math.min(max, n));
}
