import * as vscode from 'vscode';
import { registerResxCommands } from './commands';
import { ResxEditorProvider } from './editor';

export function activate(context: vscode.ExtensionContext): void {
    context.subscriptions.push(ResxEditorProvider.register(context));
    context.subscriptions.push(...registerResxCommands(context));

    context.subscriptions.push(
        vscode.commands.registerCommand('resx.refreshBinary', () => {
            vscode.commands.executeCommand('workbench.action.revertFile');
        })
    );
}

export function deactivate(): void {}
