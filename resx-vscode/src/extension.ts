import * as vscode from 'vscode';
import { registerResxCommands } from './commands';
import { ResxEditorProvider } from './editor';

export function activate(context: vscode.ExtensionContext): void {
    context.subscriptions.push(ResxEditorProvider.register(context));
    context.subscriptions.push(...registerResxCommands(context));

    context.subscriptions.push(
        vscode.commands.registerCommand('resx.refreshBinary', async () => {
            const refreshed = await ResxEditorProvider.refreshActive();
            if (!refreshed) {
                void vscode.window.showInformationMessage('Open a RESX binary viewer before refreshing analysis.');
            }
        })
    );
}

export function deactivate(): void {}
