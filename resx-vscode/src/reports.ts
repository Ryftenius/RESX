import { clampInt, ResxCommand } from './cli';

/**
 * On-demand reports the viewer can request. The webview sends an id and loose params;
 * everything here validates them, so argv never contains webview-authored options.
 */
export const REPORT_IDS = [
    'behavior',
    'contracts',
    'ipc',
    'network',
    'crypto',
    'strings',
    'entropy',
    'driver',
    'ioctl',
    'pechk',
    'find',
    'calls',
    'callers',
    'reconstruct',
] as const;

export type ReportId = (typeof REPORT_IDS)[number];

export interface ReportPlan {
    command: ResxCommand;
    operands: string[];
    flags: string[];
    /** Progress title; long-running reports show a notification. */
    title: string;
    /** Whether `--args` / `--no-headers` / hostile options apply. */
    usesApiArgs: boolean;
}

export function isReportId(value: unknown): value is ReportId {
    return typeof value === 'string' && (REPORT_IDS as readonly string[]).includes(value);
}

type Params = Record<string, unknown>;

function text(params: Params, key: string, max = 512): string {
    const value = params[key];
    if (typeof value !== 'string') return '';
    return value.replace(/[\0\r\n]/g, ' ').trim().slice(0, max);
}

function flag(params: Params, key: string): boolean {
    return params[key] === true;
}

/** RVA / VA / file-offset target forms RESX accepts. */
const ADDRESS = /^(?:(?:rva|va|file):)?(?:0x)?[0-9a-f]{1,16}$/i;
const FILTER_TERM = /^!?[A-Za-z0-9_][A-Za-z0-9_.*-]{0,63}$/;

export function normalizeAddress(value: unknown): string | null {
    if (typeof value !== 'string') return null;
    const raw = value.trim();
    if (!ADDRESS.test(raw)) return null;
    if (/^(?:rva|va|file):/i.test(raw)) return raw.toLowerCase();
    return raw.toLowerCase().startsWith('0x') ? raw.toLowerCase() : `0x${raw.toLowerCase()}`;
}

/** Comma-separated call-tree filter terms (`winapi`, `iat`, `crt`, `kernel32.dll`, ...). */
export function filterTerms(value: unknown): string[] {
    const raw = Array.isArray(value) ? value.join(',') : typeof value === 'string' ? value : '';
    // `-term` and `!term` both exclude; `!` keeps a leading dash out of argv.
    return raw.split(',')
        .map(t => t.trim().replace(/^-(?=[A-Za-z0-9_])/, '!'))
        .filter(t => FILTER_TERM.test(t))
        .slice(0, 16);
}

/** Synthetic or address targets that `callers` cannot resolve (it needs a named function). */
export function isNamedFunction(target: string): boolean {
    return !/^(?:entry|rentry|sub_[0-9a-f]+|loc_[0-9a-f]+|(?:rva|va|file):.*|0x[0-9a-f]+|[0-9a-f]+h?)$/i.test(target.trim());
}

/** Function target: name, IMAGE!NAME, entry/rentry, or an address form. */
export function normalizeTarget(value: unknown): string | null {
    if (typeof value !== 'string') return null;
    const raw = value.trim();
    if (!raw || raw.length > 512 || /[\0\r\n]/.test(raw)) return null;
    return raw;
}

export function planReport(id: ReportId, image: string, params: Params): ReportPlan | { error: string } {
    const base = (command: ResxCommand, title: string, flags: string[] = [], operands = [image], usesApiArgs = false): ReportPlan =>
        ({ command, operands, flags, title, usesApiArgs });
    switch (id) {
        case 'behavior':
            return base('behavior', 'behavior triage', [], [image], true);
        case 'contracts':
        case 'ipc':
        case 'network':
        case 'crypto':
            return base(id, `${id} evidence`, [], [image], true);
        case 'driver':
        case 'ioctl':
            return base(id, `${id} analysis`, [], [image], true);
        case 'pechk':
            return base('pechk', 'PE validation');
        case 'strings': {
            const flags = [
                '--min-len', String(clampInt(params.minLen ?? 5, 1, 4096)),
                '--limit', String(clampInt(params.limit ?? 2000, 1, 8192)),
            ];
            const encoding = text(params, 'encoding');
            if (['ascii', 'utf16le', 'both'].includes(encoding)) flags.push('--encoding', encoding);
            if (flag(params, 'interesting')) flags.push('--interesting');
            if (flag(params, 'rawWide')) flags.push('--raw-wide');
            const match = text(params, 'match', 256);
            if (match) flags.push('--match', match);
            const tag = text(params, 'tag', 64);
            if (tag) flags.push('--tag', tag);
            return base('strings', 'string extraction', flags);
        }
        case 'entropy': {
            const window = clampInt(params.window ?? 1024, 64, 1 << 20);
            const stride = clampInt(params.stride ?? Math.max(1, window >> 1), 16, 1 << 20);
            const flags = ['--window', String(window), '--stride', String(stride)];
            if (flag(params, 'all')) flags.push('--all');
            return base('entropy', 'entropy', flags);
        }
        case 'find': {
            const query = text(params, 'query', 1024);
            if (!query) return { error: 'Enter bytes, text, a constant or an instruction pattern to find.' };
            const mode = text(params, 'mode');
            const flags: string[] = [];
            if (['auto', 'raw', 'decoded', 'semantic'].includes(mode)) flags.push('--mode', mode);
            if (flag(params, 'encoded')) flags.push('--encoded');
            return base('find', 'find', flags, [image, query]);
        }
        case 'calls': {
            const target = normalizeTarget(params.target);
            if (!target) return { error: 'calls needs a function target.' };
            const flags = ['--depth', String(clampInt(params.depth ?? 3, 1, 8)), '--rva'];
            const only = filterTerms(params.only);
            if (only.length) flags.push('--only', only.join(','));
            const exclude = filterTerms(params.exclude);
            if (exclude.length) flags.push('--exclude', exclude.join(','));
            return base('calls', 'call tree', flags, [image, target], true);
        }
        case 'callers': {
            const target = normalizeTarget(params.target);
            if (!target) return { error: 'callers needs a function name.' };
            if (!isNamedFunction(target)) {
                return { error: `Callers are traced by name (export, PDB symbol or import); "${target}" has no name RESX can resolve. Load PDB symbols to name internal functions.` };
            }
            const flags = [
                '--depth', String(clampInt(params.depth ?? 3, 1, 8)),
                '--max-callers', String(clampInt(params.maxCallers ?? 30, 1, 500)),
                '--show-site',
                '--rva',
            ];
            return base('callers', 'caller tree', flags, [image, target]);
        }
        case 'reconstruct': {
            const flags: string[] = ['--depth', String(clampInt(params.depth ?? 3, 1, 8))];
            const thread = text(params, 'threadFilter', 128);
            if (thread) flags.push('--thread-filter', thread);
            const api = text(params, 'apiFilter', 128);
            if (api) flags.push('--api-filter', api);
            if (flag(params, 'driverFlow')) flags.push('--driver-flow');
            return base('reconstruct-cfg', 'startup flow', flags, [image], true);
        }
    }
}
