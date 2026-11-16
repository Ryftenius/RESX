import * as fs from 'fs/promises';
import * as path from 'path';
import * as vscode from 'vscode';
import { ResxEditorProvider } from './editor';
import { unwrapListPayload } from './payloads';
import { normalizeAddress } from './reports';
import { ReportPanel } from './reportPanel';
import { resxVersion, runResx, runResxText } from './runner';
import { configuredPdbFile, sharedOptions } from './settings';

interface LocateHit {
    dll?: string;
    dll_path?: string;
    name?: string;
    rva?: string;
    source?: string;
    from_pdb?: boolean;
    syscall_number?: string;
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
    type_name?: string;
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
    modulePath: string;
}

interface LocateSuggestion {
    label: string;
    description: string;
    detail: string;
    query: string;
}

/** Viewer tabs reachable from the command palette and explorer menus. */
const TAB_COMMANDS: Array<{ id: string; tab: string }> = [
    { id: 'resx.behavior', tab: 'behavior' },
    { id: 'resx.strings', tab: 'strings' },
    { id: 'resx.evidence', tab: 'evidence' },
    { id: 'resx.driver', tab: 'driver' },
    { id: 'resx.entropy', tab: 'entropy' },
    { id: 'resx.search', tab: 'search' },
    { id: 'resx.reconstructCfg', tab: 'flow' },
];

let moduleCache: ModulePick[] | null = null;
const symbolCache = new Map<string, string[]>();
const locateIndexStateKey = 'resx.locateIndex.v2';
const locateIndexSeedModules = [
    'ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'advapi32.dll', 'user32.dll', 'gdi32.dll', 'ws2_32.dll',
    'ole32.dll', 'combase.dll', 'rpcrt4.dll', 'crypt32.dll', 'bcrypt.dll', 'secur32.dll', 'shell32.dll',
    'shlwapi.dll', 'wininet.dll', 'winhttp.dll', 'netapi32.dll', 'iphlpapi.dll',
];

function isResxImagePath(filePath: string): boolean {
    return /\.(dll|exe|sys|bin|efi|scr|cpl|ocx|drv)$/i.test(filePath);
}

export function registerResxCommands(context: vscode.ExtensionContext): vscode.Disposable[] {
    ReportPanel.setOpenImageHandler(async (filePath, rva, label) => {
        await ResxEditorProvider.open(vscode.Uri.file(filePath), rva ? { rva: normalizeAddress(rva) ?? rva, sourceLabel: label || rva } : undefined);
    });

    const register = (id: string, fn: (...args: any[]) => unknown) => vscode.commands.registerCommand(id, fn);
    return [
        register('resx.openBinaryFile', (uri?: vscode.Uri) => openBinaryFile(uri)),
        register('resx.locate', () => openLocate(context, 'locate')),
        register('resx.locateSymbol', () => openLocate(context, 'locate-sym')),
        register('resx.dump', () => openDump(context)),
        register('resx.scan', (uri?: vscode.Uri) => openScanReport(context, uri)),
        register('resx.apiLookup', (name?: string) => apiLookup(context, name)),
        register('resx.configureHeaders', () => configureHeaders(context)),
        register('resx.diff', (uri?: vscode.Uri, uris?: vscode.Uri[]) => diffImages(context, uri, uris)),
        register('resx.index', (uri?: vscode.Uri) => indexCorpus(context, uri)),
        register('resx.hunt', (uri?: vscode.Uri) => huntSimilar(context, uri)),
        register('resx.payload', (uri?: vscode.Uri) => decodePayload(context, uri)),
        register('resx.patch', (uri?: vscode.Uri) => patchImage(context, uri)),
        register('resx.showVersion', () => showVersion(context)),
        register('resx.openSettings', () => vscode.commands.executeCommand('workbench.action.openSettings', '@ext:ryftenius.resx-vscode')),
        ...TAB_COMMANDS.map(({ id, tab }) => register(id, (uri?: vscode.Uri) => openTab(uri, tab))),
    ];
}

async function openBinaryFile(uri?: vscode.Uri): Promise<void> {
    const target = await pickImageUri(uri, 'Select image to open in RESX');
    if (target) await ResxEditorProvider.open(target);
}

/** Shows a viewer tab: in the active viewer when no file is given, else in the file's viewer. */
async function openTab(uri: vscode.Uri | undefined, tab: string): Promise<void> {
    if (!(uri instanceof vscode.Uri) && await ResxEditorProvider.showTabInActive(tab)) return;
    const target = await pickImageUri(uri instanceof vscode.Uri ? uri : undefined, 'Select image to analyze');
    if (target) await ResxEditorProvider.open(target, { tab });
}

async function pickImageUri(uri: vscode.Uri | undefined, title: string): Promise<vscode.Uri | undefined> {
    if (uri?.scheme === 'file' && isResxImagePath(uri.fsPath)) return uri;
    const activeViewer = ResxEditorProvider.activeImagePath();
    if (!uri && activeViewer) return vscode.Uri.file(activeViewer);
    const active = vscode.window.activeTextEditor?.document.uri;
    if (active?.scheme === 'file' && isResxImagePath(active.fsPath)) return active;
    const picked = await vscode.window.showOpenDialog({
        canSelectMany: false,
        filters: { 'Windows PE images': ['dll', 'exe', 'sys', 'bin', 'efi', 'scr', 'cpl', 'ocx', 'drv'], 'All files': ['*'] },
        title,
    });
    return picked?.[0];
}

async function pickFolder(uri: vscode.Uri | undefined, title: string): Promise<vscode.Uri | undefined> {
    if (uri?.scheme === 'file') {
        try {
            const stat = await fs.stat(uri.fsPath);
            return stat.isDirectory() ? uri : vscode.Uri.file(path.dirname(uri.fsPath));
        } catch {
            return uri;
        }
    }
    if (vscode.workspace.workspaceFolders?.length === 1) {
        const ws = vscode.workspace.workspaceFolders[0].uri;
        const choice = await vscode.window.showQuickPick([
            { label: `$(folder) ${path.basename(ws.fsPath) || ws.fsPath}`, description: ws.fsPath, uri: ws },
            { label: '$(folder-opened) Choose another folder…', description: '', uri: undefined as vscode.Uri | undefined },
        ], { title });
        if (!choice) return undefined;
        if (choice.uri) return choice.uri;
    }
    const picked = await vscode.window.showOpenDialog({ canSelectMany: false, canSelectFiles: false, canSelectFolders: true, title });
    return picked?.[0];
}

async function openScanReport(context: vscode.ExtensionContext, uri?: vscode.Uri): Promise<void> {
    const root = await pickFolder(uri, 'Select folder to scan');
    if (!root) return;
    const maxFiles = vscode.workspace.getConfiguration('resx').get<number>('scanMaxFiles', 200);
    ReportPanel.show(context, {
        kind: 'scan',
        title: `Scan ${path.basename(root.fsPath) || root.fsPath}`,
        subtitle: root.fsPath,
        run: token => runResx(context, 'scan', [root.fsPath], ['--max-files', String(Math.max(1, maxFiles))], sharedOptions({ apiArgs: false }), { token }),
    });
}

async function apiLookup(context: vscode.ExtensionContext, initial?: string): Promise<void> {
    const name = typeof initial === 'string' && initial.trim()
        ? initial.trim()
        : (await vscode.window.showInputBox({
            title: 'RESX API Lookup',
            prompt: 'Windows API name (uses the configured SDK headers)',
            placeHolder: 'VirtualAlloc, CreateFileW or kernel32!OpenProcess',
            ignoreFocusOut: true,
        }))?.trim();
    if (!name) return;
    const probe = await runResx(context, 'api', [name]);
    if (probe.error && /header|sdk|config --headers/i.test(probe.error)) {
        const action = await vscode.window.showWarningMessage(`RESX: ${probe.error}`, 'Configure SDK Headers');
        if (action) await configureHeaders(context);
        return;
    }
    let first: typeof probe | undefined = probe;
    ReportPanel.show(context, {
        kind: 'api',
        title: `API ${name}`,
        run: token => {
            const ready = first;
            first = undefined;
            return ready ? Promise.resolve(ready) : runResx(context, 'api', [name], [], {}, { token });
        },
    });
}

async function configureHeaders(context: vscode.ExtensionContext): Promise<void> {
    const kits = await findSdkIncludeDirs();
    const items: Array<vscode.QuickPickItem & { value?: string; browse?: boolean }> = [
        ...kits.map(dir => ({ label: `$(library) ${path.basename(dir)}`, description: dir, value: dir })),
        { label: '$(folder-opened) Browse for an SDK Include directory…', browse: true },
        { label: '$(circle-slash) Disable SDK header enrichment', value: 'off' },
    ];
    const choice = await vscode.window.showQuickPick(items, {
        title: 'RESX: Windows SDK headers',
        placeHolder: 'Select the Windows SDK Include directory RESX uses for API prototypes and --args',
    });
    if (!choice) return;
    let value = choice.value;
    if (choice.browse) {
        const picked = await vscode.window.showOpenDialog({ canSelectMany: false, canSelectFiles: false, canSelectFolders: true, title: 'Select Windows SDK Include directory (e.g. ...\\Include\\10.0.26100.0)' });
        value = picked?.[0]?.fsPath;
    }
    if (!value) return;
    const result = await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: value === 'off' ? 'RESX: disabling SDK headers' : 'RESX: indexing SDK headers',
    }, () => runResxText(context, ['config', '--headers', value!]));
    if (!result.ok) {
        void vscode.window.showErrorMessage(`RESX config failed: ${result.error}`);
        return;
    }
    void vscode.window.showInformationMessage(value === 'off'
        ? 'RESX SDK header enrichment disabled.'
        : `RESX SDK headers set to ${value}. Enable "Recover arguments" (resx.apiArguments) to see recovered call arguments.`);
}

async function findSdkIncludeDirs(): Promise<string[]> {
    const roots = [
        path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Windows Kits', '10', 'Include'),
        path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Windows Kits', '10', 'Include'),
    ];
    const found: string[] = [];
    for (const root of roots) {
        try {
            for (const entry of await fs.readdir(root, { withFileTypes: true })) {
                if (entry.isDirectory() && /^10\.\d+\.\d+\.\d+$/.test(entry.name)) found.push(path.join(root, entry.name));
            }
        } catch {
            // No SDK in this location.
        }
    }
    return found.sort((a, b) => path.basename(b).localeCompare(path.basename(a), undefined, { numeric: true }));
}

async function diffImages(context: vscode.ExtensionContext, uri?: vscode.Uri, uris?: vscode.Uri[]): Promise<void> {
    let images = (Array.isArray(uris) ? uris : uri ? [uri] : []).filter(u => u?.scheme === 'file').map(u => u.fsPath);
    if (images.length < 2) {
        const first = images[0] ?? (await pickImageUri(undefined, 'Select the first image to compare'))?.fsPath;
        if (!first) return;
        const picked = await vscode.window.showOpenDialog({
            canSelectMany: true,
            defaultUri: vscode.Uri.file(path.dirname(first)),
            filters: { 'Windows PE images': ['dll', 'exe', 'sys', 'bin'], 'All files': ['*'] },
            title: `Compare ${path.basename(first)} with…`,
        });
        if (!picked?.length) return;
        images = [first, ...picked.map(p => p.fsPath)];
    }
    const mode = await vscode.window.showQuickPick([
        { label: 'balanced', description: 'Default matching profile' },
        { label: 'fast', description: 'Fewer signals, quicker' },
        { label: 'deep', description: 'More signals and candidates' },
    ], { title: 'RESX Diff: matching profile' });
    if (!mode) return;
    const names = images.map(i => path.basename(i));
    ReportPanel.show(context, {
        kind: 'diff',
        title: `Diff ${names.join(' ↔ ')}`,
        subtitle: images.join('\n'),
        run: token => runResx(context, 'diff', images, ['--mode', mode.label], sharedOptions({ apiArgs: false }), { token }),
    });
}

async function pickCorpusDb(save: boolean, near?: string): Promise<string | undefined> {
    const defaultUri = vscode.Uri.file(path.join(near || vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || process.cwd(), 'resx-corpus.json'));
    if (save) {
        return (await vscode.window.showSaveDialog({ defaultUri, filters: { 'RESX corpus': ['json'] }, title: 'Corpus database to create' }))?.fsPath;
    }
    const picked = await vscode.window.showOpenDialog({ canSelectMany: false, defaultUri, filters: { 'RESX corpus': ['json'] }, title: 'Corpus database to search' });
    return picked?.[0]?.fsPath;
}

async function indexCorpus(context: vscode.ExtensionContext, uri?: vscode.Uri): Promise<void> {
    const root = await pickFolder(uri, 'Select folder to index');
    if (!root) return;
    const db = await pickCorpusDb(true, root.fsPath);
    if (!db) return;
    ReportPanel.show(context, {
        kind: 'index',
        title: `Index ${path.basename(root.fsPath) || root.fsPath}`,
        subtitle: `${root.fsPath} → ${db}`,
        run: token => runResx(context, 'index', [root.fsPath], ['--db', db], sharedOptions({ apiArgs: false }), { token }),
    });
}

async function huntSimilar(context: vscode.ExtensionContext, uri?: vscode.Uri): Promise<void> {
    const sample = await pickImageUri(uri, 'Select the sample to rank against a corpus');
    if (!sample) return;
    const db = await pickCorpusDb(false, path.dirname(sample.fsPath));
    if (!db) return;
    ReportPanel.show(context, {
        kind: 'hunt',
        title: `Hunt ${path.basename(sample.fsPath)}`,
        subtitle: `corpus ${db}`,
        run: token => runResx(context, 'hunt', [sample.fsPath], ['--db', db], sharedOptions({ apiArgs: false }), { token }),
    });
}

async function decodePayload(context: vscode.ExtensionContext, uri?: vscode.Uri): Promise<void> {
    let input = uri?.scheme === 'file' ? uri.fsPath : undefined;
    if (!input) {
        input = (await vscode.window.showOpenDialog({ canSelectMany: false, title: 'Select the encoded payload file' }))?.[0]?.fsPath;
    }
    if (!input) return;
    const codec = await vscode.window.showQuickPick(
        ['auto', 'zlib', 'gzip', 'deflate', 'base64', 'hex', 'aes-cbc'].map(label => ({ label, description: label === 'auto' ? 'Detect zlib/gzip framing' : '' })),
        { title: 'RESX Payload: codec' },
    );
    if (!codec) return;
    const flags = ['--codec', codec.label];
    if (codec.label === 'aes-cbc') {
        const key = (await vscode.window.showOpenDialog({ canSelectMany: false, title: 'Select the raw AES key file' }))?.[0]?.fsPath;
        if (!key) return;
        const iv = await vscode.window.showInputBox({
            title: 'RESX Payload: AES IV',
            prompt: 'IV as 32 hex digits',
            ignoreFocusOut: true,
            validateInput: v => /^[0-9a-f]{32}$/i.test(v.trim()) ? undefined : 'Enter exactly 32 hex digits',
        });
        if (!iv) return;
        const pkcs7 = await vscode.window.showQuickPick(['Remove PKCS#7 padding', 'Keep padding'], { title: 'RESX Payload: padding' });
        if (!pkcs7) return;
        flags.push('--key-file', key, '--iv-hex', iv.trim());
        if (pkcs7.startsWith('Remove')) flags.push('--pkcs7');
    }
    const range = await vscode.window.showInputBox({
        title: 'RESX Payload: source range (optional)',
        prompt: 'OFFSET or OFFSET,LENGTH in bytes; leave empty for the whole file',
        ignoreFocusOut: true,
        validateInput: v => !v.trim() || /^\s*\d+\s*(,\s*\d+\s*)?$/.test(v) ? undefined : 'Use OFFSET or OFFSET,LENGTH (decimal)',
    });
    if (range === undefined) return;
    if (range.trim()) {
        const [offset, length] = range.split(',').map(s => s.trim());
        flags.push('--offset', offset);
        if (length) flags.push('--length', length);
    }
    const parent = (await vscode.window.showOpenDialog({
        canSelectMany: false, canSelectFiles: false, canSelectFolders: true,
        defaultUri: vscode.Uri.file(path.dirname(input)),
        title: 'Folder that will contain the new output directory',
    }))?.[0]?.fsPath;
    if (!parent) return;
    const outDir = await uniqueDirectory(path.join(parent, `${path.basename(input)}.resx-payload`));
    flags.push('--out-dir', outDir);
    ReportPanel.show(context, {
        kind: 'payload',
        title: `Payload ${path.basename(input)}`,
        subtitle: `${codec.label} → ${outDir}`,
        run: token => runResx(context, 'payload', [input!], flags, {}, { token }),
    });
}

async function uniqueDirectory(base: string): Promise<string> {
    for (let i = 0; i < 1000; i++) {
        const candidate = i ? `${base}-${i}` : base;
        try {
            await fs.access(candidate);
        } catch {
            return candidate;
        }
    }
    return `${base}-${Date.now()}`;
}

async function patchImage(context: vscode.ExtensionContext, uri?: vscode.Uri): Promise<void> {
    const image = await pickImageUri(uri, 'Select the image to patch');
    if (!image) return;
    const address = await vscode.window.showInputBox({
        title: 'RESX Patch: address',
        prompt: 'RVA (0x1000), va:0x140001000 or file:0x400',
        ignoreFocusOut: true,
        validateInput: v => normalizeAddress(v) ? undefined : 'Enter an RVA, va:0x… or file:0x… address',
    });
    if (!address) return;
    const hexInput = (prompt: string, optional: boolean) => vscode.window.showInputBox({
        title: 'RESX Patch',
        prompt,
        ignoreFocusOut: true,
        validateInput: v => (optional && !v.trim()) || /^(?:[0-9a-f]{2}\s*)+$/i.test(v.trim()) ? undefined : 'Enter hex bytes, e.g. 90 90 or c3',
    });
    const bytes = await hexInput('Replacement bytes as hex', false);
    if (!bytes) return;
    const expect = await hexInput('Expected current bytes (optional; the patch is refused if they differ)', true);
    if (expect === undefined) return;
    const flags = ['--at', normalizeAddress(address)!, '--bytes', bytes.replace(/\s+/g, '')];
    if (expect.trim()) flags.push('--expect', expect.replace(/\s+/g, ''));
    const checksum = await vscode.window.showQuickPick(['Keep the PE checksum', 'Recalculate the PE checksum'], { title: 'RESX Patch: checksum' });
    if (!checksum) return;
    if (checksum.startsWith('Recalculate')) flags.push('--update-checksum');

    const plan = await runResx(context, 'patch', [image.fsPath], [...flags, '--dry-run'], sharedOptions({ apiArgs: false }));
    if (plan.error) {
        void vscode.window.showErrorMessage(`RESX patch plan failed: ${plan.error}`);
        return;
    }
    const p = plan.payload || {};
    const out = String(p.output_path || '').replace(/^\\\\\?\\/, '');
    const confirm = await vscode.window.showWarningMessage(
        `Write a patched copy of ${path.basename(image.fsPath)}?`,
        {
            modal: true,
            detail: `${p.address?.section || ''} RVA ${p.address?.rva || address} (file ${p.address?.file_offset || '?'})\n`
                + `${p.bytes?.original || '?'} → ${p.bytes?.replacement || bytes}\n\nOutput: ${out}\nThe source image is not modified.`,
        },
        'Write Patched Copy',
    );
    if (confirm !== 'Write Patched Copy') {
        ReportPanel.show(context, { kind: 'patch', title: `Patch plan ${path.basename(image.fsPath)}`, run: async () => plan });
        return;
    }
    ReportPanel.show(context, {
        kind: 'patch',
        title: `Patch ${path.basename(image.fsPath)}`,
        run: token => runResx(context, 'patch', [image.fsPath], flags, sharedOptions({ apiArgs: false }), { token }),
    });
}

async function showVersion(context: vscode.ExtensionContext): Promise<void> {
    const info = await resxVersion(context);
    if (info.error) {
        void vscode.window.showErrorMessage(`RESX analyzer unavailable: ${info.error}`);
        return;
    }
    void vscode.window.showInformationMessage(`RESX ${info.version} · ${info.exe}`);
}

async function openLocate(context: vscode.ExtensionContext, kind: 'locate' | 'locate-sym'): Promise<void> {
    const query = await pickLocateQuery(context, kind);
    if (!query) return;
    const result = await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: `RESX: ${kind} ${query}`,
        cancellable: true,
    }, (_p, token) => runResx(context, kind, [query], [], sharedOptions({ apiArgs: false, noPdb: kind === 'locate' }), { token }));
    if (result.cancelled) return;
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
    await ResxEditorProvider.open(vscode.Uri.file(hit.dll_path), {
        func: hit.name || query,
        rva: hit.rva || undefined,
        dll: hit.dll || undefined,
        dllPath: hit.dll_path || undefined,
        sourceLabel: hit.name || query,
    });
}

async function openDump(context: vscode.ExtensionContext): Promise<void> {
    const module = await pickModule();
    if (!module) return;
    const func = await pickDumpTarget(context, module);
    if (!func) return;
    await ResxEditorProvider.open(vscode.Uri.file(module.modulePath), {
        func: func.name || '',
        rva: func.rva || undefined,
        dll: module.label,
        dllPath: module.modulePath,
        sourceLabel: func.name || '',
        loadSymbols: true,
    });
}

async function pickLocateHit(hits: LocateHit[], title: string): Promise<LocateHit | undefined> {
    if (hits.length === 1) return hits[0];
    const items = hits.map(hit => ({
        label: `${hit.dll || 'unknown'}!${hit.name || '?'}`,
        description: [hit.rva, hit.source, hit.syscall_number ? `syscall ${hit.syscall_number}` : ''].filter(Boolean).join(' · '),
        detail: hit.dll_path || '',
        hit,
    }));
    const picked = await vscode.window.showQuickPick(items, { title, placeHolder: 'Select a resolved location', matchOnDescription: true, matchOnDetail: true });
    return picked?.hit;
}

async function pickLocateQuery(context: vscode.ExtensionContext, kind: 'locate' | 'locate-sym'): Promise<string | undefined> {
    const title = kind === 'locate' ? 'RESX Locate' : 'RESX Locate Symbol';
    const placeHolder = kind === 'locate' ? 'Search for an API or export name' : 'Search for an API, export, or symbol name';
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
                    label: '$(sync~spin) Loading export suggestions…',
                    description: 'The export index is built in the background',
                    detail: 'Press Enter to run the typed query directly',
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
        quickPick.onDidChangeValue(() => refreshItems());
        quickPick.onDidAccept(() => finalize((quickPick.selectedItems[0]?.query || quickPick.value.trim()) || undefined));
        quickPick.onDidHide(() => finalize(undefined));
        quickPick.show();

        void getLocateSuggestions(context, kind).then(items => {
            if (settled) return;
            suggestions = items;
            refreshItems();
        });
    });
}

function buildLocateItems(suggestions: LocateSuggestion[], rawValue: string, fallback: string): LocateSuggestion[] {
    const value = rawValue.trim();
    const normalized = value.toLowerCase();
    const matches = normalized
        ? suggestions.filter(item => item.query.toLowerCase().includes(normalized)).slice(0, 50)
        : suggestions.slice(0, 20);
    const items: LocateSuggestion[] = [value
        ? { label: `$(search) Locate "${value}"`, description: 'Run RESX with the typed query', detail: 'Press Enter to search directly', query: value }
        : { label: `$(search) Try "${fallback}"`, description: 'Run RESX with a direct query', detail: 'Type to narrow the suggestion list', query: fallback }];
    for (const match of matches) {
        if (match.query.toLowerCase() !== normalized) items.push(match);
    }
    return items;
}

async function getLocateSuggestions(context: vscode.ExtensionContext, kind: 'locate' | 'locate-sym'): Promise<LocateSuggestion[]> {
    const exports = await getLocateIndex(context);
    const items = exports.map(name => ({ label: name, description: '', detail: '', query: name }));
    if (kind === 'locate-sym') {
        for (const name of ['RtlpHeapHandleError', 'KiSystemCall64', 'LdrLoadDll', 'RtlAllocateHeap']) {
            if (!exports.includes(name)) items.unshift({ label: name, description: '', detail: '', query: name });
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
    const results = await Promise.all(preferred.map(async module => {
        const result = await runResx(context, 'eat', [module.modulePath], [], { noPdb: true });
        return result.error ? [] : unwrapListPayload<ExportHit>(result.data, 'exports');
    }));
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
    return vscode.window.showQuickPick(items, { title: 'RESX Dump', placeHolder: 'Select a module', matchOnDescription: true, matchOnDetail: true });
}

async function pickDumpTarget(context: vscode.ExtensionContext, module: ModulePick): Promise<DumpTargetPick | undefined> {
    const opts = sharedOptions({ apiArgs: false });
    const [eatResult, symsResult] = await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: `RESX: loading exports and PDB symbols for ${module.label}`,
    }, () => Promise.all([
        runResx(context, 'eat', [module.modulePath], [], { ...opts, noPdb: true }),
        runResx(context, 'syms', [module.modulePath], [], { ...opts, pdbFile: configuredPdbFile() }),
    ]));
    if (eatResult.error && symsResult.error) {
        void vscode.window.showErrorMessage(`Failed to load exports and symbols for ${module.label}.`);
        return undefined;
    }
    const merged = new Map<string, DumpTargetPick>();
    for (const hit of unwrapListPayload<ExportHit>(eatResult.data, 'exports')) {
        const name = hit.name?.trim();
        if (name) merged.set(name.toLowerCase(), { name, rva: hit.rva, source: 'export', kind: 'export', detail: hit.forward_to || `${module.label} export` });
    }
    for (const hit of unwrapListPayload<SymbolHit>(symsResult.data, 'symbols')) {
        const name = hit.name?.trim();
        if (!name || merged.get(name.toLowerCase())?.source === 'export') continue;
        merged.set(name.toLowerCase(), { name, rva: hit.rva, source: 'symbol', kind: hit.kind || 'symbol', detail: hit.type_name || `${module.label} PDB symbol` });
    }
    const manual = async () => {
        const typed = await vscode.window.showInputBox({
            title: 'RESX Dump',
            prompt: `Enter an export or symbol name, or an RVA, in ${module.label}`,
            placeHolder: 'PsOpenProcess or 0x1000',
            ignoreFocusOut: true,
        });
        const value = typed?.trim();
        if (!value) return undefined;
        const rva = normalizeAddress(value);
        return rva && /^(?:0x)?[0-9a-f]+$/i.test(value) ? { rva, name: value, source: 'symbol' as const } : { name: value, source: 'symbol' as const };
    };
    const candidates = [...merged.values()].sort((a, b) => (a.name || '').localeCompare(b.name || ''));
    if (!candidates.length) return manual();
    const picked = await vscode.window.showQuickPick(candidates.map(hit => ({
        label: hit.name || '',
        description: hit.rva || '',
        detail: `${hit.kind || hit.source} · ${hit.detail || module.label}`,
        hit,
    })), { title: 'RESX Dump', placeHolder: `Select an export or symbol from ${module.label}`, matchOnDescription: true, matchOnDetail: true });
    return picked?.hit ?? manual();
}

async function getModulePicks(): Promise<ModulePick[]> {
    if (moduleCache) return moduleCache;
    const seen = new Map<string, ModulePick>();
    for (const root of candidateModuleRoots()) {
        for (const file of await readModuleDir(root)) {
            const key = file.toLowerCase();
            if (seen.has(key)) continue;
            seen.set(key, { label: path.basename(file), description: path.basename(path.dirname(file)), detail: file, modulePath: file });
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
    for (const dir of vscode.workspace.getConfiguration('resx').get<string[]>('imagePaths', [])) {
        if (typeof dir === 'string' && dir.trim()) roots.add(dir.trim());
    }
    for (const folder of vscode.workspace.workspaceFolders || []) roots.add(folder.uri.fsPath);
    return [...roots];
}

async function readModuleDir(root: string): Promise<string[]> {
    try {
        const entries = await fs.readdir(root, { withFileTypes: true });
        return entries.filter(entry => entry.isFile() && /\.(dll|exe|sys)$/i.test(entry.name)).map(entry => path.join(root, entry.name));
    } catch {
        return [];
    }
}
