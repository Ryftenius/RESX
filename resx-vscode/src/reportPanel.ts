import { randomBytes } from 'crypto';
import * as fs from 'fs';
import * as vscode from 'vscode';
import { RunResult } from './runner';

export interface ReportJob {
    kind: string;
    title: string;
    subtitle?: string;
    argsEnabled?: boolean;
    run(token: vscode.CancellationToken): Promise<RunResult>;
}

/** Opens a viewer at `path` (optionally at `rva`); provided by the extension entry point. */
export type OpenImageHandler = (path: string, rva?: string, label?: string) => Promise<void>;

/** Standalone panel for reports that are not tied to one open image. */
export class ReportPanel {
    private static openImage: OpenImageHandler | undefined;
    private cts: vscode.CancellationTokenSource | undefined;
    private ready = false;
    private last: object | undefined;

    public static setOpenImageHandler(handler: OpenImageHandler): void {
        ReportPanel.openImage = handler;
    }

    public static show(context: vscode.ExtensionContext, job: ReportJob): ReportPanel {
        const panel = vscode.window.createWebviewPanel(
            'resx.report',
            job.title,
            vscode.ViewColumn.Active,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'media')],
            },
        );
        const report = new ReportPanel(context, panel, job);
        void report.run();
        return report;
    }

    private constructor(
        private readonly context: vscode.ExtensionContext,
        private readonly panel: vscode.WebviewPanel,
        private readonly job: ReportJob,
    ) {
        panel.iconPath = vscode.Uri.joinPath(context.extensionUri, 'media', 'icon.svg');
        panel.webview.html = this.html();
        panel.onDidDispose(() => this.cts?.cancel());
        panel.webview.onDidReceiveMessage(async msg => {
            switch (msg?.command) {
                case 'ready':
                    this.ready = true;
                    if (this.last) void panel.webview.postMessage(this.last);
                    break;
                case 'rerun':
                    void this.run();
                    break;
                case 'cancel':
                    this.cts?.cancel();
                    break;
                case 'open_json':
                    await openJsonDocument(msg.data);
                    break;
                case 'copy':
                    if (typeof msg.text === 'string') await vscode.env.clipboard.writeText(msg.text);
                    break;
                case 'open_image':
                    if (typeof msg.path === 'string' && msg.path && fs.existsSync(msg.path)) {
                        await ReportPanel.openImage?.(msg.path, typeof msg.rva === 'string' ? msg.rva : undefined, typeof msg.label === 'string' ? msg.label : undefined);
                    }
                    break;
            }
        });
    }

    private post(message: object): void {
        this.last = message;
        if (this.ready) void this.panel.webview.postMessage(message);
    }

    private async run(): Promise<void> {
        this.cts?.cancel();
        const cts = new vscode.CancellationTokenSource();
        this.cts = cts;
        const base = { kind: this.job.kind, title: this.job.title, subtitle: this.job.subtitle, argsEnabled: this.job.argsEnabled };
        this.post({ type: 'loading', ...base });
        const result = await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `RESX: ${this.job.title}`,
            cancellable: true,
        }, async (_progress, token) => {
            token.onCancellationRequested(() => cts.cancel());
            return this.job.run(cts.token);
        });
        if (this.cts !== cts) return;
        this.post({
            type: 'report',
            ...base,
            payload: result.payload ?? result.data,
            data: result.data,
            error: result.cancelled ? 'Cancelled.' : result.error,
        });
    }

    private html(): string {
        const webview = this.panel.webview;
        const nonce = nonceValue();
        const script = webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, 'media', 'report.js'));
        const style = webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, 'media', 'style.css'));
        const csp = [`default-src 'none'`, `style-src ${webview.cspSource}`, `img-src ${webview.cspSource}`, `script-src 'nonce-${nonce}' ${webview.cspSource}`].join('; ');
        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link href="${style}" rel="stylesheet">
  <title>RESX report</title>
</head>
<body class="report-page">
  <div id="report-root" class="panel active"></div>
  <script type="module" nonce="${nonce}" src="${script}"></script>
</body>
</html>`;
    }
}

export async function openJsonDocument(data: unknown): Promise<void> {
    const doc = await vscode.workspace.openTextDocument({ language: 'json', content: JSON.stringify(data ?? {}, null, 2) });
    await vscode.window.showTextDocument(doc, { preview: false, viewColumn: vscode.ViewColumn.Beside });
}

export function nonceValue(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const bytes = randomBytes(32);
    return Array.from(bytes, b => chars[b % chars.length]).join('');
}
