import { button, errorBox, h, jsonButton, loading, renderKnownReport, toolbar } from './reports.js';
const vscode = acquireVsCodeApi();
const root = document.getElementById('report-root');
const ctx = {
    openJson: (data, title) => vscode.postMessage({ command: 'open_json', data, title }),
    copy: text => vscode.postMessage({ command: 'copy', text }),
    openImage: (path, rva, label) => vscode.postMessage({ command: 'open_image', path, rva, label }),
};
function render(msg) {
    root.innerHTML = '';
    root.append(h('h1', { class: 'report-title', text: msg.title }));
    if (msg.subtitle)
        root.append(h('div', { class: 'dim report-subtitle', text: msg.subtitle }));
    if (msg.type === 'loading') {
        root.append(loading(`Running ${msg.kind}…`));
        root.append(button('Cancel', () => vscode.postMessage({ command: 'cancel' })));
        return;
    }
    const actions = [
        button('Re-run', () => vscode.postMessage({ command: 'rerun' })),
        msg.data ? jsonButton(ctx, msg.data, msg.title) : null,
    ];
    root.append(toolbar(msg.kind, ...actions));
    if (msg.error) {
        root.append(errorBox(msg.error));
        return;
    }
    const body = h('div', { class: 'report-body' });
    root.append(body);
    try {
        renderKnownReport(msg.kind, body, msg.payload ?? {}, ctx, { argsEnabled: msg.argsEnabled });
    }
    catch (error) {
        body.append(errorBox(`Could not render this report: ${error instanceof Error ? error.message : String(error)}. Use Open JSON to inspect it.`));
    }
    vscode.setState(msg);
}
window.addEventListener('message', event => {
    const msg = event.data;
    if (msg && (msg.type === 'report' || msg.type === 'loading'))
        render(msg);
});
const restored = vscode.getState();
if (restored?.type === 'report')
    render(restored);
vscode.postMessage({ command: 'ready' });
