import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { clampInt, dumpFlags, SharedOptions } from './cli';
import { filterTerms, isReportId, normalizeAddress, normalizeTarget, planReport } from './reports';
import { nonceValue, openJsonDocument } from './reportPanel';
import { getRunTraceHistory, resxVersion, RunResult, runResx, subscribeRunTrace } from './runner';
import { configuredPdbFile, sharedOptions, viewerDefaults } from './settings';

export interface PendingNavigation {
    func?: string;
    rva?: string;
    dll?: string;
    dllPath?: string;
    sourceLabel?: string;
    loadSymbols?: boolean;
    /** Top-level tab to show once the viewer is ready. */
    tab?: string;
}

const RESX_PRESENCE_TABS = [
    'overview', 'entry', 'triage', 'behavior', 'sections', 'exports', 'imports', 'symbols', 'types',
    'strings', 'evidence', 'driver', 'entropy', 'search', 'flow', 'scan', 'dump', 'dev',
] as const;
const RESX_DUMP_PRESENCE_SUBTABS = ['disasm', 'calls', 'xrefs', 'callers', 'strings', 'cfg', 'recomp', 'hex'] as const;

function isResxPresenceTab(value: unknown): value is (typeof RESX_PRESENCE_TABS)[number] {
    return typeof value === 'string' && (RESX_PRESENCE_TABS as readonly string[]).includes(value);
}

function isResxDumpPresenceSubtab(value: unknown): value is (typeof RESX_DUMP_PRESENCE_SUBTABS)[number] {
    return typeof value === 'string' && (RESX_DUMP_PRESENCE_SUBTABS as readonly string[]).includes(value);
}

function normalizeModuleArg(name: string): string {
    if (/\.(dll|exe|sys)$/i.test(name)) return name;
    if (/^(ntoskrnl|ntkrnlmp|ntkrnlpa|ntkrpamp)$/i.test(name)) return `${name}.exe`;
    return `${name}.dll`;
}

function kernelFamilyCandidates(name?: string): string[] {
    const normalized = normalizeModuleArg(name || '');
    if (!/^(ntoskrnl|ntkrnlmp|ntkrnlpa|ntkrpamp)\.exe$/i.test(normalized)) return [];
    return ['ntoskrnl.exe', 'ntkrnlmp.exe', 'ntkrnlpa.exe', 'ntkrpamp.exe'];
}

function moduleCandidateVariants(name?: string): string[] {
    const raw = String(name || '').trim();
    if (!raw) return [];
    const base = raw.replace(/\.(dll|exe|sys)$/i, '');
    return uniqueValues([normalizeModuleArg(raw), ...kernelFamilyCandidates(raw), `${base}.dll`, `${base}.exe`, `${base}.sys`, raw]);
}

function uniqueValues(values: Array<string | undefined | null>): string[] {
    const out: string[] = [];
    const seen = new Set<string>();
    for (const value of values) {
        const raw = String(value || '').trim();
        if (!raw || seen.has(raw.toLowerCase())) continue;
        seen.add(raw.toLowerCase());
        out.push(raw);
    }
    return out;
}

function parseForwardedExportTarget(error?: string): { dll: string; func: string } | null {
    const match = (error || '').match(/forwarded export(?:\s+|[^\r\nA-Za-z0-9_.]+)([A-Za-z0-9_.]+)\.([A-Za-z0-9_@$]+)/i);
    return match ? { dll: normalizeModuleArg(match[1]), func: match[2] } : null;
}

/** Per-dump options the viewer may set; everything is validated here. */
interface DumpView {
    callDepth: number;
    hostile: boolean;
    apiArgs: boolean;
    ssa: boolean;
    callsOnly: string[];
    callsExclude: string[];
}

function dumpView(msg: any): DumpView {
    const defaults = viewerDefaults();
    return {
        callDepth: clampInt(msg?.funcsDepth ?? msg?.callDepth ?? defaults.callDepth, 1, 8),
        hostile: typeof msg?.hostile === 'boolean' ? msg.hostile : defaults.hostile,
        apiArgs: typeof msg?.apiArgs === 'boolean' ? msg.apiArgs : defaults.apiArgs,
        ssa: msg?.ssa === true,
        callsOnly: filterTerms(msg?.callsOnly),
        callsExclude: filterTerms(msg?.callsExclude),
    };
}

export class ResxEditorProvider implements vscode.CustomReadonlyEditorProvider {
    public static readonly viewType = 'resx.binaryViewer';
    public static readonly binViewType = 'resx.binaryViewer.bin';
    private static readonly panelByPath = new Map<string, vscode.WebviewPanel>();
    private static readonly pendingNavigation = new Map<string, PendingNavigation>();
    private static activePathKey: string | undefined;

    public static register(context: vscode.ExtensionContext): vscode.Disposable {
        const options = {
            supportsMultipleEditorsPerDocument: false,
            webviewOptions: { retainContextWhenHidden: true },
        };
        return vscode.Disposable.from(
            vscode.window.registerCustomEditorProvider(ResxEditorProvider.viewType, new ResxEditorProvider(context), options),
            vscode.window.registerCustomEditorProvider(ResxEditorProvider.binViewType, new ResxEditorProvider(context), options),
        );
    }

    public static viewTypeForUri(uri: vscode.Uri): string {
        return /\.bin$/i.test(uri.fsPath) ? ResxEditorProvider.binViewType : ResxEditorProvider.viewType;
    }

    /** Opens `uri` in the viewer and applies `target` once it is ready. */
    public static async open(uri: vscode.Uri, target?: PendingNavigation): Promise<void> {
        if (target) {
            const key = uri.fsPath.toLowerCase();
            if (!ResxEditorProvider.panelByPath.has(key)) ResxEditorProvider.pendingNavigation.set(key, target);
        }
        await vscode.commands.executeCommand('vscode.openWith', uri, ResxEditorProvider.viewTypeForUri(uri));
        if (target) await ResxEditorProvider.navigateTo(uri, target);
    }

    public static async navigateTo(uri: vscode.Uri, target: PendingNavigation): Promise<void> {
        const key = uri.fsPath.toLowerCase();
        const panel = ResxEditorProvider.panelByPath.get(key);
        if (panel) {
            ResxEditorProvider.pendingNavigation.delete(key);
            await panel.webview.postMessage({ type: 'external_navigate', ...target });
            panel.reveal(panel.viewColumn, false);
            return;
        }
        ResxEditorProvider.pendingNavigation.set(key, target);
    }

    public static activePanel(): vscode.WebviewPanel | undefined {
        return ResxEditorProvider.activePathKey ? ResxEditorProvider.panelByPath.get(ResxEditorProvider.activePathKey) : undefined;
    }

    /** File path of the most recently active viewer. */
    public static activeImagePath(): string | undefined {
        const panel = ResxEditorProvider.activePanel();
        return panel ? (panel as vscode.WebviewPanel & { resxPath?: string }).resxPath : undefined;
    }

    public static async refreshActive(): Promise<boolean> {
        const panel = ResxEditorProvider.activePanel();
        if (!panel) return false;
        panel.reveal(panel.viewColumn, false);
        await panel.webview.postMessage({ type: 'refresh_requested' });
        return true;
    }

    /** Shows a tab in the active viewer; returns false when no viewer is open. */
    public static async showTabInActive(tab: string): Promise<boolean> {
        const panel = ResxEditorProvider.activePanel();
        if (!panel) return false;
        panel.reveal(panel.viewColumn, false);
        await panel.webview.postMessage({ type: 'show_tab', tab });
        return true;
    }

    /** Re-sends viewer defaults after a settings change. */
    public static broadcastSettings(): void {
        const settings = { type: 'viewer_settings', ...viewerDefaults() };
        for (const panel of ResxEditorProvider.panelByPath.values()) void panel.webview.postMessage(settings);
    }

    constructor(private readonly context: vscode.ExtensionContext) {}

    async openCustomDocument(uri: vscode.Uri): Promise<vscode.CustomDocument> {
        return { uri, dispose: () => {} };
    }

    async resolveCustomEditor(document: vscode.CustomDocument, webviewPanel: vscode.WebviewPanel): Promise<void> {
        const webview = webviewPanel.webview;
        webview.options = {
            enableScripts: true,
            localResourceRoots: [vscode.Uri.joinPath(this.context.extensionUri, 'media')],
        };

        const filePath = document.uri.fsPath;
        const fileName = path.basename(filePath);
        const docKey = filePath.toLowerCase();
        (webviewPanel as vscode.WebviewPanel & { resxPath?: string }).resxPath = filePath;

        webview.html = this.buildHtml(webview, fileName);
        ResxEditorProvider.panelByPath.set(docKey, webviewPanel);
        if (webviewPanel.active) ResxEditorProvider.activePathKey = docKey;
        webviewPanel.onDidChangeViewState(event => {
            if (event.webviewPanel.active) ResxEditorProvider.activePathKey = docKey;
        });

        const reportTokens = new Map<string, vscode.CancellationTokenSource>();
        const traceSubscription = subscribeRunTrace(entry => { void webview.postMessage({ type: 'dev_log_append', entry }); });
        webviewPanel.onDidDispose(() => {
            ResxEditorProvider.panelByPath.delete(docKey);
            if (ResxEditorProvider.activePathKey === docKey) ResxEditorProvider.activePathKey = undefined;
            traceSubscription.dispose();
            for (const cts of reportTokens.values()) cts.cancel();
        });

        const send = (msg: object): void => { void webview.postMessage(msg); };
        // Symbol settings chosen in the viewer's symbol panel; they replace the configured ones.
        let viewerSymbols: Pick<SharedOptions, 'symPaths' | 'pdbFile' | 'symServer'> | undefined;
        let symReloadToken = 0;

        const isRootImage = (target?: string): boolean => !target || path.resolve(target).toLowerCase() === docKey;
        const optionsFor = (target?: string, overrides: Partial<SharedOptions> = {}): SharedOptions => {
            const base = sharedOptions(overrides);
            const symbols = viewerSymbols ?? {};
            const pdbFile = symbols.pdbFile ?? configuredPdbFile();
            return {
                ...base,
                symPaths: symbols.symPaths?.length ? symbols.symPaths : base.symPaths,
                symServer: symbols.symServer || base.symServer,
                pdbFile: isRootImage(target) ? pdbFile : undefined,
                ...overrides,
            };
        };

        const tokenFor = (key: string): vscode.CancellationTokenSource => {
            reportTokens.get(key)?.cancel();
            const cts = new vscode.CancellationTokenSource();
            reportTokens.set(key, cts);
            return cts;
        };

        const publishPresence = async (value: unknown): Promise<void> => {
            if (!webviewPanel.active || !value || typeof value !== 'object') return;
            const payload = value as { topTab?: unknown; dumpSubTab?: unknown; functionName?: unknown };
            if (!isResxPresenceTab(payload.topTab)) return;
            const dumpSubTab = payload.topTab === 'dump' && isResxDumpPresenceSubtab(payload.dumpSubTab) ? payload.dumpSubTab : undefined;
            const functionName = payload.topTab === 'dump' && typeof payload.functionName === 'string'
                ? payload.functionName.trim().slice(0, 256) || undefined
                : undefined;
            try {
                await vscode.commands.executeCommand('vscord.resx.updatePresence', { topTab: payload.topTab, dumpSubTab, functionName });
            } catch {
                // VSCord is optional; RESX remains fully functional without it.
            }
        };

        const runInitialAnalysis = (forceLoadSymbols?: boolean): void => {
            const loadSymbols = forceLoadSymbols ?? viewerDefaults().loadSymbolsOnOpen;
            const opts = optionsFor(filePath);
            const fast = { ...opts, noPdb: true };
            const symsTitle = `RESX: loading PDB symbols for ${fileName}`;
            const symbolRun = (command: 'syms' | 'types') => runResx(this.context, command, [filePath], [], loadSymbols ? opts : fast);

            void runResx(this.context, 'peinfo', [filePath], [], fast).then(r => send({ type: 'peinfo', ...r }));
            void runResx(this.context, 'eat', [filePath], [], fast).then(r => send({ type: 'eat', ...r }));
            void runResx(this.context, 'iat', [filePath], [], fast).then(r => send({ type: 'iat', ...r }));
            void runResx(this.context, 'pechk', [filePath], [], fast).then(r => send({ type: 'pechk', ...r }));
            void runResx(this.context, 'intelli', [filePath], [], { ...fast, apiArgs: false }).then(r => send({ type: 'intelli', ...r }));
            void (loadSymbols ? symbolRun('types') : Promise.resolve<RunResult>({ data: { types: [] } })).then(r => send({ type: 'types', ...r }));
            void (loadSymbols
                ? vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: symsTitle }, () => symbolRun('syms'))
                : symbolRun('syms')
            ).then(r => send({ type: 'syms', ...r }));
        };

        const runDump = async (target: string, func: string | undefined, at: string | undefined, view: DumpView, token: vscode.CancellationToken): Promise<RunResult> => {
            const opts = optionsFor(target, { hostile: view.hostile, apiArgs: view.apiArgs });
            const flags = (t: string) => dumpFlags({ image: t, at, callDepth: view.callDepth, callsOnly: view.callsOnly, callsExclude: view.callsExclude, ssa: view.ssa });
            const operands = (t: string, f?: string) => (f ? [t, f] : [t]);
            let result = await runResx(this.context, 'dump', operands(target, func), flags(target), opts, { token });

            // Older analyzers stop at forwarders; follow them to the implementing module.
            const visited = new Set<string>();
            for (let hop = 0; hop < 6 && func && !result.cancelled; hop++) {
                const forwarded = result.error ? parseForwardedExportTarget(result.error) : null;
                if (!forwarded) break;
                let advanced = false;
                for (const candidate of moduleCandidateVariants(forwarded.dll)) {
                    const key = `${candidate.toLowerCase()}!${forwarded.func.toLowerCase()}`;
                    if (visited.has(key)) continue;
                    visited.add(key);
                    result = await runResx(this.context, 'dump', [candidate, forwarded.func], flags(candidate), optionsFor(candidate, { hostile: view.hostile, apiArgs: view.apiArgs }), { token });
                    advanced = true;
                    if (!result.error || parseForwardedExportTarget(result.error)) break;
                }
                if (!advanced) break;
            }

            // RVAs reported against a kernel alias may only map in a sibling kernel image.
            if (at && result.error && /not in any section/i.test(result.error)) {
                for (const candidate of kernelFamilyCandidates(path.basename(target))) {
                    if (candidate.toLowerCase() === path.basename(target).toLowerCase()) continue;
                    result = await runResx(this.context, 'dump', [candidate], flags(candidate), optionsFor(candidate, { hostile: view.hostile, apiArgs: view.apiArgs }), { token });
                    if (!result.error) break;
                }
            }
            return result;
        };

        const sendReport = (id: string, requestId: unknown, result: RunResult, extra: object = {}): void => {
            send({
                type: 'report_result',
                id,
                requestId,
                data: result.data,
                payload: result.payload ?? result.data,
                error: result.cancelled ? 'Cancelled.' : result.error,
                cancelled: !!result.cancelled,
                ...extra,
            });
        };

        webview.onDidReceiveMessage(async (msg) => {
            switch (msg?.command) {
                case 'dump':
                case 'dump_at_rva': {
                    const target = typeof msg.dllPath === 'string' && msg.dllPath
                        ? msg.dllPath
                        : typeof msg.dll === 'string' && msg.dll ? msg.dll : filePath;
                    const at = msg.command === 'dump_at_rva' ? normalizeAddress(msg.rva) : null;
                    const func = msg.command === 'dump' ? normalizeTarget(msg.func) : null;
                    if (!at && !func) {
                        send({ type: 'dump_result', requestId: msg.requestId, cacheKey: msg.cacheKey, error: 'Invalid dump target.' });
                        break;
                    }
                    const cts = msg.prefetch ? new vscode.CancellationTokenSource() : tokenFor('dump');
                    const result = await runDump(target, func ?? undefined, at ?? undefined, dumpView(msg), cts.token);
                    if (result.cancelled) break;
                    send({
                        type: 'dump_result',
                        func: msg.func ?? msg.label,
                        sourceLabel: msg.sourceLabel ?? msg.label,
                        requestId: msg.requestId,
                        cacheKey: msg.cacheKey,
                        prefetch: !!msg.prefetch,
                        ...result,
                    });
                    break;
                }

                case 'report': {
                    if (!isReportId(msg.id)) break;
                    const target = typeof msg.image === 'string' && msg.image ? msg.image : filePath;
                    const plan = planReport(msg.id, target, msg.params && typeof msg.params === 'object' ? msg.params : {});
                    if ('error' in plan) {
                        sendReport(msg.id, msg.requestId, { data: null, error: plan.error });
                        break;
                    }
                    const apiArgs = plan.usesApiArgs && (typeof msg.params?.apiArgs === 'boolean' ? msg.params.apiArgs : viewerDefaults().apiArgs);
                    const hostile = typeof msg.params?.hostile === 'boolean' ? msg.params.hostile : viewerDefaults().hostile;
                    const cts = tokenFor(`report:${msg.id}`);
                    const result = await vscode.window.withProgress({
                        location: vscode.ProgressLocation.Window,
                        title: `RESX: ${plan.title}`,
                    }, () => runResx(this.context, plan.command, plan.operands, plan.flags, optionsFor(target, { apiArgs, hostile }), { token: cts.token }));
                    sendReport(msg.id, msg.requestId, result, { argsEnabled: apiArgs, params: msg.params });
                    break;
                }

                case 'cancel_report': {
                    const key = msg.id === 'dump' ? 'dump' : `report:${msg.id}`;
                    reportTokens.get(key)?.cancel();
                    break;
                }

                case 'yara_pick': {
                    const picked = await vscode.window.showOpenDialog({
                        canSelectMany: true,
                        canSelectFiles: true,
                        canSelectFolders: true,
                        filters: { 'YARA rules': ['yar', 'yara', 'json'], 'All files': ['*'] },
                        title: 'Select YARA rule files or folders',
                    });
                    if (!picked?.length) break;
                    const rules = picked.map(u => u.fsPath);
                    send({ type: 'report_pending', id: 'yara' });
                    const cts = tokenFor('report:yara');
                    const result = await runResx(this.context, 'yara', [filePath, ...rules], [], optionsFor(filePath), { token: cts.token });
                    sendReport('yara', msg.requestId, result, { rules });
                    break;
                }

                case 'diff_pick': {
                    const picked = await vscode.window.showOpenDialog({
                        canSelectMany: false,
                        filters: { 'Windows PE images': ['dll', 'exe', 'sys', 'bin'], 'All files': ['*'] },
                        defaultUri: vscode.Uri.file(path.dirname(filePath)),
                        title: `Compare ${fileName} with…`,
                    });
                    if (picked?.[0]) await vscode.commands.executeCommand('resx.diff', document.uri, [document.uri, picked[0]]);
                    break;
                }

                case 'api_lookup': {
                    const name = normalizeTarget(msg.name);
                    if (name) await vscode.commands.executeCommand('resx.apiLookup', name);
                    break;
                }

                case 'reload_syms': {
                    const reloadToken = ++symReloadToken;
                    viewerSymbols = {
                        symPaths: Array.isArray(msg.symPaths) ? msg.symPaths.filter((p: unknown) => typeof p === 'string') : [],
                        pdbFile: typeof msg.pdbFile === 'string' && msg.pdbFile ? msg.pdbFile : undefined,
                        symServer: typeof msg.symServer === 'string' && msg.symServer.trim() ? msg.symServer.trim() : undefined,
                    };
                    const opts = optionsFor(filePath, { reloadSymbols: true });
                    const result = await vscode.window.withProgress({
                        location: vscode.ProgressLocation.Notification,
                        title: `RESX: loading PDB symbols for ${fileName}`,
                    }, () => runResx(this.context, 'syms', [filePath], [], opts));
                    if (reloadToken !== symReloadToken) break;
                    send({ type: 'syms', ...result });
                    const typesResult = await runResx(this.context, 'types', [filePath], [], optionsFor(filePath));
                    if (reloadToken !== symReloadToken) break;
                    send({ type: 'types', ...typesResult });
                    break;
                }

                case 'reconstruct_cfg': {
                    const plan = planReport('reconstruct', filePath, msg.params && typeof msg.params === 'object' ? msg.params : {});
                    if ('error' in plan) break;
                    const cts = tokenFor('report:reconstruct');
                    const result = await vscode.window.withProgress({
                        location: vscode.ProgressLocation.Notification,
                        title: `RESX: reconstructing startup flow for ${fileName}`,
                        cancellable: true,
                    }, (_p, token) => {
                        token.onCancellationRequested(() => cts.cancel());
                        return runResx(this.context, plan.command, plan.operands, plan.flags, optionsFor(filePath), { token: cts.token });
                    });
                    send({ type: 'reconstruct_cfg_result', ...result, error: result.cancelled ? 'Cancelled.' : result.error });
                    break;
                }

                case 'scan_path': {
                    const root = typeof msg.path === 'string' && msg.path.trim() ? msg.path.trim() : path.dirname(filePath);
                    const cts = tokenFor('report:scan');
                    const result = await vscode.window.withProgress({
                        location: vscode.ProgressLocation.Notification,
                        title: `RESX: scanning ${path.basename(root) || root}`,
                        cancellable: true,
                    }, (_p, token) => {
                        token.onCancellationRequested(() => cts.cancel());
                        const maxFiles = clampInt(vscode.workspace.getConfiguration('resx').get<number>('scanMaxFiles', 200), 1, 100000);
                        return runResx(this.context, 'scan', [root], ['--max-files', String(maxFiles)], optionsFor(root, { apiArgs: false }), { token: cts.token });
                    });
                    send({ type: 'scan_result', root, ...result, error: result.cancelled ? 'Cancelled.' : result.error });
                    break;
                }

                case 'refresh':
                    runInitialAnalysis();
                    break;

                case 'open_image': {
                    if (typeof msg.path !== 'string' || !fs.existsSync(msg.path)) break;
                    const rva = normalizeAddress(msg.rva) ?? undefined;
                    await ResxEditorProvider.open(vscode.Uri.file(msg.path), rva ? { rva, sourceLabel: msg.label || rva } : undefined);
                    break;
                }

                case 'open_recomp':
                case 'open_text_report': {
                    const doc = await vscode.workspace.openTextDocument({
                        language: msg.command === 'open_recomp' ? 'c' : (typeof msg.language === 'string' ? msg.language : 'plaintext'),
                        content: typeof msg.content === 'string' ? msg.content : '',
                    });
                    await vscode.window.showTextDocument(doc, { preview: false, viewColumn: vscode.ViewColumn.Beside });
                    break;
                }

                case 'open_json':
                    await openJsonDocument(msg.data);
                    break;

                case 'copy':
                    if (typeof msg.text === 'string') await vscode.env.clipboard.writeText(msg.text);
                    break;

                case 'pdb_browse_file': {
                    const uris = await vscode.window.showOpenDialog({ canSelectMany: false, filters: { 'PDB files': ['pdb'], 'All files': ['*'] }, title: 'Select PDB file' });
                    send({ type: 'file_picked', kind: 'pdb_file', path: uris?.[0]?.fsPath ?? null });
                    break;
                }

                case 'pdb_browse_folder': {
                    const uris = await vscode.window.showOpenDialog({ canSelectMany: false, canSelectFiles: false, canSelectFolders: true, title: 'Select symbol search path' });
                    send({ type: 'file_picked', kind: 'sym_path', path: uris?.[0]?.fsPath ?? null });
                    break;
                }

                case 'scan_browse_folder': {
                    const uris = await vscode.window.showOpenDialog({ canSelectMany: false, canSelectFiles: false, canSelectFolders: true, title: 'Select folder to scan' });
                    send({ type: 'file_picked', kind: 'scan_root', path: uris?.[0]?.fsPath ?? null });
                    break;
                }

                case 'open_settings':
                    await vscode.commands.executeCommand('workbench.action.openSettings', '@ext:ryftenius.resx-vscode');
                    break;

                case 'ready': {
                    await publishPresence(msg);
                    const version = await resxVersion(this.context);
                    send({ type: 'viewer_settings', ...viewerDefaults(), version: version.version, versionError: version.error, imagePath: filePath });
                    send({ type: 'dev_log_history', entries: getRunTraceHistory() });
                    const pending = ResxEditorProvider.pendingNavigation.get(docKey);
                    if (pending) {
                        ResxEditorProvider.pendingNavigation.delete(docKey);
                        send({ type: 'external_navigate', ...pending });
                    }
                    break;
                }

                case 'presence_context':
                    await publishPresence(msg);
                    break;
            }
        });

        const pending = ResxEditorProvider.pendingNavigation.get(docKey);
        runInitialAnalysis(!!pending?.loadSymbols || viewerDefaults().loadSymbolsOnOpen);
    }

    private buildHtml(webview: vscode.Webview, fileName: string): string {
        const nonce = nonceValue();
        const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, 'media', 'main.js'));
        const styleUri = webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, 'media', 'style.css'));
        const csp = [`default-src 'none'`, `style-src ${webview.cspSource}`, `img-src ${webview.cspSource}`, `script-src 'nonce-${nonce}' ${webview.cspSource}`].join('; ');
        const tab = (id: string, label: string, extra = '', cls = '') => `<button class="tab${id === 'overview' ? ' active' : ''}${cls ? ` ${cls}` : ''}" data-tab="${id}" ${extra}>${label}</button>`;
        const panel = (id: string, text: string) => `<div id="panel-${id}" class="panel${id === 'overview' ? ' active' : ''}">${text ? `<p class="loading">${text}</p>` : ''}</div>`;
        const analyzing = 'Analyzing&hellip;';
        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link href="${styleUri}" rel="stylesheet">
  <title>${escapeHtml(fileName)}</title>
</head>
<body>
  <div id="topbar">
    <span id="fname" title="${escapeHtml(fileName)}">${escapeHtml(fileName)}</span>
    <nav id="tabs">
      ${tab('overview', 'Overview')}
      ${tab('entry', 'Entry')}
      ${tab('triage', 'Triage')}
      ${tab('behavior', 'Behavior')}
      ${tab('sections', 'Sections')}
      ${tab('exports', 'Exports')}
      ${tab('imports', 'Imports')}
      ${tab('symbols', 'Symbols')}
      ${tab('types', 'Types')}
      ${tab('strings', 'Strings')}
      ${tab('evidence', 'Evidence')}
      ${tab('driver', 'Driver', 'id="tab-driver"', 'hidden')}
      ${tab('entropy', 'Entropy')}
      ${tab('search', 'Search')}
      ${tab('flow', 'Flow')}
      ${tab('scan', 'Scan')}
      ${tab('dump', 'Dump', 'id="tab-dump" style="display:none"')}
      <button class="tab tab-dev" data-tab="dev">Dev</button>
    </nav>
    <button id="opts-btn" class="topbar-btn" title="Analysis options">&#9881; Options</button>
    <button id="pdb-btn" class="topbar-btn" title="Symbol &amp; PDB settings">Symbols</button>
    <button id="export-btn" class="topbar-btn" title="Export current view">&#10515; Export</button>
  </div>
  <div id="panels">
    ${panel('overview', analyzing)}
    ${panel('entry', analyzing)}
    ${panel('triage', analyzing)}
    ${panel('behavior', 'Behavior triage runs when this tab is opened.')}
    ${panel('sections', analyzing)}
    ${panel('exports', analyzing)}
    ${panel('imports', analyzing)}
    ${panel('symbols', analyzing)}
    ${panel('types', analyzing)}
    ${panel('strings', 'String extraction runs when this tab is opened.')}
    ${panel('evidence', 'API contract evidence runs when this tab is opened.')}
    ${panel('driver', 'Driver analysis runs when this tab is opened.')}
    ${panel('entropy', 'Entropy runs when this tab is opened.')}
    ${panel('search', '')}
    ${panel('flow', 'Run reconstruct-cfg to build startup flow.')}
    ${panel('scan', 'Run scan to discover fuzz candidates.')}
    ${panel('dev', 'Waiting for RESX commands&hellip;')}
    ${panel('dump', '')}
  </div>
  <script type="module" nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
    }
}

function escapeHtml(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
