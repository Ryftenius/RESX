import * as vscode from 'vscode';
import * as path from 'path';
import { unwrapObjectPayload } from './payloads';
import { getRunTraceHistory, runJson, RunOptions, subscribeRunTrace } from './runner';

interface PendingNavigation {
    func?: string;
    rva?: string;
    dll?: string;
    dllPath?: string;
    sourceLabel?: string;
    loadSymbols?: boolean;
}

function normalizeModuleArg(name: string): string {
    if (/\.(dll|exe|sys)$/i.test(name)) return name;
    if (/^(ntoskrnl|ntkrnlmp|ntkrnlpa|ntkrpamp)$/i.test(name)) return `${name}.exe`;
    if (/^hal$/i.test(name)) return `${name}.dll`;
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
    const lower = raw.toLowerCase();
    const base = raw.replace(/\.(dll|exe|sys)$/i, '');
    return uniqueValues([
        normalizeModuleArg(raw),
        ...kernelFamilyCandidates(raw),
        `${base}.dll`,
        `${base}.exe`,
        `${base}.sys`,
        raw,
    ]);
}

function uniqueValues(values: Array<string | undefined | null>): string[] {
    const out: string[] = [];
    const seen = new Set<string>();
    for (const value of values) {
        const raw = String(value || '').trim();
        if (!raw) continue;
        const key = raw.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(raw);
    }
    return out;
}

function parseForwardedExportTarget(error?: string): { dll: string; func: string } | null {
    const text = error || '';
    const match = text.match(/forwarded export(?:\s+|[^\r\nA-Za-z0-9_.]+)([A-Za-z0-9_.]+)\.([A-Za-z0-9_@$]+)/i);
    if (!match) return null;
    return {
        dll: normalizeModuleArg(match[1]),
        func: match[2],
    };
}

async function runDumpWithForwardFallback(
    context: vscode.ExtensionContext,
    args: string[],
    opts?: RunOptions
): Promise<ReturnType<typeof runJson>> {
    let result = await runJson(context, args, opts);
    const visited = new Set<string>();

    for (let hop = 0; hop < 6; hop++) {
        const forwarded = result.error ? parseForwardedExportTarget(result.error) : null;
        if (!forwarded) return result;

        const candidates = moduleCandidateVariants(forwarded.dll);

        let advanced = false;
        for (const candidate of candidates) {
            const key = `${candidate.toLowerCase()}!${forwarded.func.toLowerCase()}`;
            if (visited.has(key)) continue;
            visited.add(key);
            result = await runJson(
                context,
                ['dump', candidate, forwarded.func, '--cfg', 'text', '--funcs-depth', String(opts?.funcsDepth || 1), '--strings', '--xrefs', '--recomp'],
                opts
            );
            advanced = true;
            if (!result.error) return result;
            if (parseForwardedExportTarget(result.error)) break;
        }
        if (!advanced) break;
    }

    return result;
}

async function runDumpAtRvaWithFallback(
    context: vscode.ExtensionContext,
    targetPath: string,
    rva: string,
    dllHint: string | undefined,
    opts?: RunOptions
): Promise<ReturnType<typeof runJson>> {
    const baseArgs = ['--at', rva, '--cfg', 'text', '--funcs-depth', String(opts?.funcsDepth || 1), '--strings', '--xrefs', '--recomp'];
    let result = await runJson(context, ['dump', targetPath, ...baseArgs], opts);
    if (!result.error || !/not in any section/i.test(result.error)) return result;

    const aliasCandidates = uniqueValues([
        dllHint,
        ...kernelFamilyCandidates(dllHint),
    ]);
    for (const candidate of aliasCandidates) {
        if (candidate.toLowerCase() === targetPath.toLowerCase()) continue;
        result = await runJson(context, ['dump', candidate, ...baseArgs], opts);
        if (!result.error) return result;
    }
    return result;
}

async function runSymsWithProgress(
    context: vscode.ExtensionContext,
    args: string[],
    opts: RunOptions,
    title: string,
): Promise<ReturnType<typeof runJson>> {
    return vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title,
        cancellable: false,
    }, async () => runJson(context, args, opts));
}

export class ResxEditorProvider implements vscode.CustomReadonlyEditorProvider {
    public static readonly viewType = 'resx.binaryViewer';
    private static readonly panelByPath = new Map<string, vscode.WebviewPanel>();
    private static readonly pendingNavigation = new Map<string, PendingNavigation>();

    public static register(context: vscode.ExtensionContext): vscode.Disposable {
        return vscode.window.registerCustomEditorProvider(
            ResxEditorProvider.viewType,
            new ResxEditorProvider(context),
            {
                supportsMultipleEditorsPerDocument: false,
                webviewOptions: { retainContextWhenHidden: true },
            }
        );
    }

    public static async navigateTo(uri: vscode.Uri, target: PendingNavigation): Promise<void> {
        const key = uri.fsPath.toLowerCase();
        const panel = ResxEditorProvider.panelByPath.get(key);
        if (panel) {
            await panel.webview.postMessage({ type: 'external_navigate', ...target });
            panel.reveal(panel.viewColumn, false);
            return;
        }
        ResxEditorProvider.pendingNavigation.set(key, target);
    }

    constructor(private readonly context: vscode.ExtensionContext) {}

    async openCustomDocument(uri: vscode.Uri): Promise<vscode.CustomDocument> {
        return { uri, dispose: () => {} };
    }

    async resolveCustomEditor(
        document: vscode.CustomDocument,
        webviewPanel: vscode.WebviewPanel
    ): Promise<void> {
        const webview = webviewPanel.webview;
        webview.options = {
            enableScripts: true,
            localResourceRoots: [vscode.Uri.joinPath(this.context.extensionUri, 'media')],
        };

        const filePath = document.uri.fsPath;
        const fileName = path.basename(filePath);
        const docKey = filePath.toLowerCase();
        const nonce = getNonce();

        webview.html = this.buildHtml(webview, fileName, nonce);
        ResxEditorProvider.panelByPath.set(docKey, webviewPanel);
        const traceSubscription = subscribeRunTrace((entry) => {
            void webview.postMessage({ type: 'dev_log_append', entry });
        });
        webviewPanel.onDidDispose(() => {
            ResxEditorProvider.panelByPath.delete(docKey);
            traceSubscription.dispose();
        });

        const send = (msg: object): void => { webview.postMessage(msg); };
        let symReloadToken = 0;

        function cfgOpts(): RunOptions {
            const cfg = vscode.workspace.getConfiguration('resx');
            return {
                symPaths: cfg.get<string[]>('symbolPaths', []),
                pdbFile:  cfg.get<string>('pdbFile', '') || undefined,
            };
        }

        webview.onDidReceiveMessage(async (msg) => {
            switch (msg.command) {

                case 'dump': {
                    const target = msg.dllPath || msg.dll || filePath;
                    const args = ['dump', target, msg.func,
                        '--cfg', 'text', '--funcs-depth', String(msg.funcsDepth || 1), '--strings', '--xrefs', '--recomp'];
                    const result = await runDumpWithForwardFallback(this.context, args, { ...cfgOpts(), funcsDepth: msg.funcsDepth || 1 });
                    send({
                        type: 'dump_result',
                        func: msg.func,
                        sourceLabel: msg.sourceLabel,
                        requestId: msg.requestId,
                        cacheKey: msg.cacheKey,
                        prefetch: !!msg.prefetch,
                        ...result
                    });
                    break;
                }

                case 'explain': {
                    const result = await runJson(this.context, ['explain', msg.name, '--api']);
                    const d = unwrapObjectPayload<any>(result.data, 'explain');
                    const useful = d && (d.exact_match || d.prefix || (d.chunks && d.chunks.length > 0));
                    send({ type: 'explain_result', name: msg.name, data: useful ? d : null });
                    break;
                }

                case 'reload_syms': {
                    const reloadToken = ++symReloadToken;
                    const opts: RunOptions = {
                        symPaths: msg.symPaths || [],
                        pdbFile:  msg.pdbFile  || undefined,
                    };
                    const symsCmd = ['syms', filePath, '--reload'];
                    if (msg.symServer) symsCmd.push('--sym-server', msg.symServer);
                    const result = await runSymsWithProgress(
                        this.context,
                        symsCmd,
                        opts,
                        `RESX: loading PDB symbols for ${path.basename(filePath)}`,
                    );
                    if (reloadToken !== symReloadToken) break;
                    send({ type: 'syms', ...result });
                    const typesResult = await runJson(this.context, ['types', filePath], opts);
                    if (reloadToken !== symReloadToken) break;
                    send({ type: 'types', ...typesResult });
                    break;
                }

                case 'dump_at_rva': {
                    const target = msg.dllPath || filePath;
                    const result = await runDumpAtRvaWithFallback(this.context, target, msg.rva, msg.dll, { ...cfgOpts(), funcsDepth: msg.funcsDepth || 1 });
                    send({
                        type: 'dump_result',
                        func: msg.label,
                        sourceLabel: msg.label,
                        requestId: msg.requestId,
                        cacheKey: msg.cacheKey,
                        prefetch: !!msg.prefetch,
                        ...result
                    });
                    break;
                }

                case 'open_recomp': {
                    const doc = await vscode.workspace.openTextDocument({
                        language: 'c',
                        content: msg.content || '',
                    });
                    await vscode.window.showTextDocument(doc, {
                        preview: false,
                        viewColumn: vscode.ViewColumn.Beside,
                    });
                    break;
                }

                case 'open_text_report': {
                    const doc = await vscode.workspace.openTextDocument({
                        language: msg.language || 'text',
                        content: msg.content || '',
                    });
                    await vscode.window.showTextDocument(doc, {
                        preview: false,
                        viewColumn: vscode.ViewColumn.Beside,
                    });
                    break;
                }

                case 'pdb_browse_file': {
                    const uris = await vscode.window.showOpenDialog({
                        canSelectMany: false,
                        filters: { 'PDB files': ['pdb'], 'All files': ['*'] },
                        title: 'Select PDB file',
                    });
                    send({ type: 'file_picked', kind: 'pdb_file', path: uris?.[0]?.fsPath ?? null });
                    break;
                }

                case 'pdb_browse_folder': {
                    const uris = await vscode.window.showOpenDialog({
                        canSelectMany: false,
                        canSelectFiles: false,
                        canSelectFolders: true,
                        title: 'Select symbol search path',
                    });
                    send({ type: 'file_picked', kind: 'sym_path', path: uris?.[0]?.fsPath ?? null });
                    break;
                }

                case 'ready': {
                    const pending = ResxEditorProvider.pendingNavigation.get(docKey);
                    send({ type: 'dev_log_history', entries: getRunTraceHistory() });
                    if (pending) {
                        ResxEditorProvider.pendingNavigation.delete(docKey);
                        send({ type: 'external_navigate', ...pending });
                    }
                    break;
                }
            }
        });

        const pending = ResxEditorProvider.pendingNavigation.get(docKey);
        const cfg = vscode.workspace.getConfiguration('resx');
        const loadSymbols = !!pending?.loadSymbols || cfg.get<boolean>('loadSymbolsOnOpen', false);
        const opts = cfgOpts();
        const symsArgs = loadSymbols ? ['syms', filePath] : ['syms', filePath, '--no-pdb'];

        Promise.all([
            runJson(this.context, ['peinfo', filePath], opts).then(r => send({ type: 'peinfo', ...r })),
            runJson(this.context, ['eat',    filePath], opts).then(r => send({ type: 'eat',    ...r })),
            runJson(this.context, ['iat',    filePath], opts).then(r => send({ type: 'iat',    ...r })),
            runJson(this.context, ['intelli',filePath], opts).then(r => send({ type: 'intelli',...r })),
            (loadSymbols
                ? runJson(this.context, ['types', filePath], opts)
                : Promise.resolve({ data: [] })
            ).then(r => send({ type: 'types', ...r })),
            (loadSymbols
                ? runSymsWithProgress(
                    this.context,
                    symsArgs,
                    opts,
                    `RESX: loading PDB symbols for ${path.basename(filePath)}`,
                )
                : runJson(this.context, symsArgs, opts)
            ).then(r => send({ type: 'syms', ...r })),
        ]).catch(() => {});
    }

    private buildHtml(webview: vscode.Webview, fileName: string, nonce: string): string {
        const scriptUri = webview.asWebviewUri(
            vscode.Uri.joinPath(this.context.extensionUri, 'media', 'main.js')
        );
        const styleUri = webview.asWebviewUri(
            vscode.Uri.joinPath(this.context.extensionUri, 'media', 'style.css')
        );
        const csp = [
            `default-src 'none'`,
            `style-src ${webview.cspSource}`,
            `script-src 'nonce-${nonce}' ${webview.cspSource}`,
        ].join('; ');

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
    <span id="fname">${escapeHtml(fileName)}</span>
    <nav id="tabs">
      <button class="tab active" data-tab="overview">Overview</button>
      <button class="tab" data-tab="entry">Entry</button>
      <button class="tab" data-tab="triage">Triage</button>
      <button class="tab" data-tab="sections">Sections</button>
      <button class="tab" data-tab="exports">Exports</button>
      <button class="tab" data-tab="imports">Imports</button>
      <button class="tab" data-tab="symbols">Symbols</button>
      <button class="tab" data-tab="types">Types</button>
      <button class="tab" id="tab-dump" data-tab="dump" style="display:none">Dump</button>
      <button class="tab tab-dev" data-tab="dev">Dev</button>
    </nav>
    <button id="export-btn" title="Export current view">&#10515; Export</button>
    <button id="pdb-btn" title="Symbol &amp; PDB settings">&#9881; Symbols</button>
  </div>
  <div id="panels">
    <div id="panel-overview"  class="panel active"><p class="loading">Analyzing&hellip;</p></div>
    <div id="panel-entry"     class="panel"><p class="loading">Analyzing&hellip;</p></div>
    <div id="panel-triage"    class="panel"><p class="loading">Analyzing&hellip;</p></div>
    <div id="panel-sections"  class="panel"><p class="loading">Analyzing&hellip;</p></div>
    <div id="panel-exports"   class="panel"><p class="loading">Analyzing&hellip;</p></div>
    <div id="panel-imports"   class="panel"><p class="loading">Analyzing&hellip;</p></div>
    <div id="panel-symbols"   class="panel"><p class="loading">Analyzing&hellip;</p></div>
    <div id="panel-types"     class="panel"><p class="loading">Analyzing&hellip;</p></div>
    <div id="panel-dev"       class="panel"><p class="loading">Waiting for RESX commands&hellip;</p></div>
    <div id="panel-dump"      class="panel"></div>
  </div>
  <script type="module" nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
    }
}

function getNonce(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let out = '';
    for (let i = 0; i < 32; i++) {
        out += chars[Math.floor(Math.random() * chars.length)];
    }
    return out;
}

function escapeHtml(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
