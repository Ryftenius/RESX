import * as fs from 'fs/promises';
import * as path from 'path';
import * as vscode from 'vscode';
import { ResxEditorProvider } from './editor';
import { unwrapListPayload } from './payloads';
import { runJson, RunOptions } from './runner';

interface LocateHit {
    dll?: string;
    dll_path?: string;
    name?: string;
    rva?: string;
    source?: string;
    from_pdb?: boolean;
}

interface ExportHit {
    name?: string;
    ordinal?: number;
    rva?: string;
    forward_to?: string;
}

interface SymbolHit {
    name?: string;
    kind?: string;
    rva?: string;
    va?: string;
    type_name?: string;
    size?: number;
}

interface DumpTargetPick {
    name?: string;
    rva?: string;
    source: 'export' | 'symbol';
    kind?: string;
    detail?: string;
}

interface ModulePick {
    label: string;
    description: string;
    detail: string;
    moduleArg: string;
    modulePath: string;
}

interface LocateSuggestion {
    label: string;
    description: string;
    detail: string;
    query: string;
}

let moduleCache: ModulePick[] | null = null;
const symbolCache = new Map<string, string[]>();
const locateIndexStateKey = 'resx.locateIndex.v1';
const locateIndexSeedModules = [
    'ntdll.dll',
    'kernel32.dll',
    'kernelbase.dll',
    'advapi32.dll',
    'user32.dll',
    'gdi32.dll',
    'ws2_32.dll',
    'ole32.dll',
    'combase.dll',
    'rpcrt4.dll',
    'crypt32.dll',
    'bcrypt.dll',
    'secur32.dll',
    'shell32.dll',
    'shlwapi.dll',
    'wininet.dll',
    'winhttp.dll',
    'netapi32.dll',
    'iphlpapi.dll',
];

export function registerResxCommands(context: vscode.ExtensionContext): vscode.Disposable[] {
    return [
        vscode.commands.registerCommand('resx.locate', async () => {
            await openLocate(context, 'locate');
        }),
        vscode.commands.registerCommand('resx.locateSymbol', async () => {
            await openLocate(context, 'locate-sym');
        }),
        vscode.commands.registerCommand('resx.dump', async () => {
            await openDump(context);
        }),
    ];
}

async function openLocate(context: vscode.ExtensionContext, kind: 'locate' | 'locate-sym'): Promise<void> {
    const query = await pickLocateQuery(context, kind);
    if (!query) return;

    const result = await runJson(context, [kind, query]);
    if (result.error) {
        void vscode.window.showErrorMessage(result.error);
        return;
    }

    const hits = unwrapListPayload<LocateHit>(result.data, 'matches');
    if (!hits.length) {
        void vscode.window.showWarningMessage(`No matches found for ${query}.`);
        return;
    }

    const hit = await pickLocateHit(hits, kind === 'locate' ? 'RESX Locate' : 'RESX Locate Symbol');
    if (!hit?.dll_path) return;

    await openResolvedTarget(hit, query);
}

async function openDump(context: vscode.ExtensionContext): Promise<void> {
    const module = await pickModule();
    if (!module) return;

    const func = await pickDumpTarget(context, module);
    if (!func) return;

    const uri = vscode.Uri.file(module.modulePath);
    await vscode.commands.executeCommand('vscode.openWith', uri, ResxEditorProvider.viewType);
    await ResxEditorProvider.navigateTo(uri, {
        func: func.name || '',
        rva: func.rva || undefined,
        dll: module.label,
        dllPath: module.modulePath,
        sourceLabel: func.name || '',
        loadSymbols: true,
    });
}

function resxRunOpts(): RunOptions {
    const cfg = vscode.workspace.getConfiguration('resx');
    return {
        symPaths: cfg.get<string[]>('symbolPaths', []),
        pdbFile: cfg.get<string>('pdbFile', '') || undefined,
    };
}

async function openResolvedTarget(hit: LocateHit, fallbackQuery: string): Promise<void> {
    const uri = vscode.Uri.file(hit.dll_path || '');
    await vscode.commands.executeCommand('vscode.openWith', uri, ResxEditorProvider.viewType);
    await ResxEditorProvider.navigateTo(uri, {
        func: hit.name || fallbackQuery,
        rva: hit.rva || undefined,
        dll: hit.dll || undefined,
        dllPath: hit.dll_path || undefined,
        sourceLabel: hit.name || fallbackQuery,
    });
}

async function pickLocateHit(hits: LocateHit[], title: string): Promise<LocateHit | undefined> {
    if (hits.length === 1) return hits[0];

    const items = hits.map(hit => ({
        label: `${hit.dll || 'unknown'}!${hit.name || '?'}`,
        description: hit.rva || '',
        detail: hit.dll_path || '',
        hit,
    }));

    const picked = await vscode.window.showQuickPick(items, {
        title,
        placeHolder: 'Select a resolved location',
        matchOnDescription: true,
        matchOnDetail: true,
    });

    return picked?.hit;
}

async function pickLocateQuery(
    context: vscode.ExtensionContext,
    kind: 'locate' | 'locate-sym',
): Promise<string | undefined> {
    const title = kind === 'locate' ? 'RESX Locate' : 'RESX Locate Symbol';
    const placeHolder = kind === 'locate'
        ? 'Search for an API or export name'
        : 'Search for an API, export, or symbol name';
    const fallback = kind === 'locate' ? 'NtOpenProcess' : 'RtlpHeapHandleError';

    return new Promise(resolve => {
        const quickPick = vscode.window.createQuickPick<LocateSuggestion>();
        let settled = false;
        let suggestions: LocateSuggestion[] = [];

        quickPick.title = title;
        quickPick.placeholder = placeHolder;
        quickPick.matchOnDescription = true;
        quickPick.matchOnDetail = true;
        quickPick.ignoreFocusOut = true;

        const refreshItems = () => {
            const items = buildLocateItems(suggestions, quickPick.value, fallback);
            if (!suggestions.length) {
                items.push({
                    label: '$(sync) Loading cached RESX suggestions...',
                    description: 'The export index is being built in the background',
                    detail: 'You can still press Enter to run the typed query directly',
                    query: quickPick.value.trim() || fallback,
                });
            }
            quickPick.items = items;
        };

        refreshItems();

        const finalize = (value?: string) => {
            if (settled) return;
            settled = true;
            quickPick.hide();
            quickPick.dispose();
            resolve(value);
        };

        quickPick.onDidChangeValue(value => {
            refreshItems();
        });

        quickPick.onDidAccept(() => {
            const selected = quickPick.selectedItems[0];
            const raw = selected?.query || quickPick.value.trim();
            finalize(raw || undefined);
        });

        quickPick.onDidHide(() => finalize(undefined));
        quickPick.show();

        void getLocateSuggestions(context, kind).then(items => {
            if (settled) return;
            suggestions = items;
            refreshItems();
        });
    });
}

function buildLocateItems(
    suggestions: LocateSuggestion[],
    rawValue: string,
    fallback: string,
): LocateSuggestion[] {
    const value = rawValue.trim();
    const normalized = value.toLowerCase();

    const matches = normalized
        ? suggestions.filter(item => item.query.toLowerCase().includes(normalized)).slice(0, 50)
        : suggestions.slice(0, 20);

    const items: LocateSuggestion[] = [];
    if (value) {
        items.push({
            label: `$(search) Locate "${value}"`,
            description: 'Run RESX with the typed query',
            detail: 'Press Enter to search directly',
            query: value,
        });
    } else {
        items.push({
            label: `$(search) Try "${fallback}"`,
            description: 'Run RESX with a direct query',
            detail: 'Type to narrow the suggestion list',
            query: fallback,
        });
    }

    for (const match of matches) {
        if (match.query.toLowerCase() === normalized) continue;
        items.push(match);
    }

    return items;
}

async function getLocateSuggestions(
    context: vscode.ExtensionContext,
    kind: 'locate' | 'locate-sym',
): Promise<LocateSuggestion[]> {
    const exports = await getLocateIndex(context);
    const items = exports.map(name => ({
        label: name,
        description: '',
        detail: '',
        query: name,
    }));

    if (kind === 'locate-sym') {
        const seeded = [
            'RtlpHeapHandleError',
            'KiSystemCall64',
            'LdrLoadDll',
            'RtlAllocateHeap',
        ];
        for (const name of seeded) {
            if (exports.includes(name)) continue;
            items.unshift({
                label: name,
                description: '',
                detail: '',
                query: name,
            });
        }
    }

    return items;
}

async function getLocateIndex(context: vscode.ExtensionContext): Promise<string[]> {
    const cached = symbolCache.get(locateIndexStateKey);
    if (cached) return cached;

    const stored = context.globalState.get<string[]>(locateIndexStateKey);
    if (stored?.length) {
        symbolCache.set(locateIndexStateKey, stored);
        void refreshLocateIndex(context);
        return stored;
    }

    return refreshLocateIndex(context);
}

async function refreshLocateIndex(context: vscode.ExtensionContext): Promise<string[]> {
    const modules = await getModulePicks();
    const preferred = locateIndexSeedModules
        .map(name => modules.find(module => module.label.toLowerCase() === name))
        .filter((module): module is ModulePick => !!module);

    const results = await Promise.all(
        preferred.map(async module => {
            const result = await runJson(context, ['eat', module.modulePath]);
            const exports = unwrapListPayload<ExportHit>(result.data, 'exports');
            return result.error || !exports.length
                ? []
                : exports;
        }),
    );

    const names = new Set<string>();
    for (const exports of results) {
        for (const hit of exports) {
            const name = hit.name?.trim();
            if (name) names.add(name);
        }
    }

    const sorted = [...names].sort((a, b) => a.localeCompare(b));
    if (sorted.length) {
        symbolCache.set(locateIndexStateKey, sorted);
        await context.globalState.update(locateIndexStateKey, sorted);
    }
    return sorted;
}

async function pickModule(): Promise<ModulePick | undefined> {
    const items = await getModulePicks();
    const picked = await vscode.window.showQuickPick(items, {
        title: 'RESX Dump',
        placeHolder: 'Select a module',
        matchOnDescription: true,
        matchOnDetail: true,
    });
    return picked;
}

async function pickDumpTarget(context: vscode.ExtensionContext, module: ModulePick): Promise<DumpTargetPick | undefined> {
    const opts = resxRunOpts();
    const [eatResult, symsResult] = await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: `RESX: loading exports and PDB symbols for ${module.label}`,
        cancellable: false,
    }, async () => Promise.all([
        runJson(context, ['eat', module.modulePath], opts),
        runJson(context, ['syms', module.modulePath], opts),
    ]));

    if (eatResult.error && symsResult.error) {
        void vscode.window.showErrorMessage(`Failed to load exports and symbols for ${module.label}.`);
        return undefined;
    }

    const exports = unwrapListPayload<ExportHit>(eatResult.data, 'exports');
    const symbols = unwrapListPayload<SymbolHit>(symsResult.data, 'symbols');
    const merged = new Map<string, DumpTargetPick>();

    for (const hit of exports) {
        const name = hit.name?.trim();
        if (!name) continue;
        const key = name.toLowerCase();
        merged.set(key, {
            name,
            rva: hit.rva,
            source: 'export',
            kind: 'export',
            detail: hit.forward_to || `${module.label} export`,
        });
    }

    for (const hit of symbols) {
        const name = hit.name?.trim();
        if (!name) continue;
        const key = name.toLowerCase();
        const prev = merged.get(key);
        if (prev?.source === 'export') continue;
        merged.set(key, {
            name,
            rva: hit.rva,
            source: 'symbol',
            kind: hit.kind || 'symbol',
            detail: hit.type_name || `${module.label} PDB symbol`,
        });
    }

    const candidates = [...merged.values()].sort((a, b) => (a.name || '').localeCompare(b.name || ''));
    if (!candidates.length) {
        const typed = await vscode.window.showInputBox({
            title: 'RESX Dump',
            prompt: `No exports or symbols returned for ${module.label}. Enter a function name manually`,
            placeHolder: 'PsOpenProcess',
            ignoreFocusOut: true,
        });
        return typed?.trim() ? { name: typed.trim(), source: 'symbol' } : undefined;
    }

    const items = candidates.map(hit => ({
        label: hit.name || '',
        description: hit.rva || '',
        detail: `${hit.kind || hit.source} · ${hit.detail || module.label}`,
        hit,
    }));

    const picked = await vscode.window.showQuickPick(items, {
        title: 'RESX Dump',
        placeHolder: `Select an export or symbol from ${module.label}`,
        matchOnDescription: true,
        matchOnDetail: true,
    });

    if (picked?.hit) return picked.hit;

    const typed = await vscode.window.showInputBox({
        title: 'RESX Dump',
        prompt: `Enter an export or symbol name in ${module.label}`,
        placeHolder: 'PsOpenProcess',
        ignoreFocusOut: true,
    });
    return typed?.trim() ? { name: typed.trim(), source: 'symbol' } : undefined;
}

async function getModulePicks(): Promise<ModulePick[]> {
    if (moduleCache) return moduleCache;

    const roots = candidateModuleRoots();
    const seen = new Map<string, ModulePick>();
    for (const root of roots) {
        const files = await readModuleDir(root);
        for (const file of files) {
            const label = path.basename(file);
            const key = file.toLowerCase();
            if (seen.has(key)) continue;
            seen.set(key, {
                label,
                description: path.basename(path.dirname(file)),
                detail: file,
                moduleArg: label,
                modulePath: file,
            });
        }
    }

    moduleCache = [...seen.values()].sort((a, b) => a.label.localeCompare(b.label));
    return moduleCache;
}

function candidateModuleRoots(): string[] {
    const roots = new Set<string>();
    const systemRoot = process.env.SystemRoot || 'C:\\Windows';
    roots.add(path.join(systemRoot, 'System32'));
    roots.add(path.join(systemRoot, 'System32', 'drivers'));
    roots.add(path.join(systemRoot, 'SysWOW64'));

    const folders = vscode.workspace.workspaceFolders || [];
    for (const folder of folders) {
        roots.add(folder.uri.fsPath);
    }

    return [...roots];
}

async function readModuleDir(root: string): Promise<string[]> {
    try {
        const entries = await fs.readdir(root, { withFileTypes: true });
        return entries
            .filter(entry => entry.isFile() && /\.(dll|exe|sys)$/i.test(entry.name))
            .map(entry => path.join(root, entry.name));
    } catch {
        return [];
    }
}
