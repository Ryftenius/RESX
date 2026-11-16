import * as vscode from 'vscode';
import { clampInt, SharedOptions } from './cli';

export interface ViewerDefaults {
    hostile: boolean;
    apiArgs: boolean;
    callDepth: number;
    loadSymbolsOnOpen: boolean;
}

function cfg(): vscode.WorkspaceConfiguration {
    return vscode.workspace.getConfiguration('resx');
}

function stringList(value: unknown): string[] {
    return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string' && !!v.trim()).map(v => v.trim()) : [];
}

/**
 * Shared RESX options from settings. `pdbFile` applies to the image the viewer opened,
 * never to other modules reached by navigation.
 */
export function sharedOptions(overrides: Partial<SharedOptions> = {}): SharedOptions {
    const c = cfg();
    const maxInsns = c.get<number>('maxInstructions', 500);
    return {
        lookupPaths: stringList(c.get('imagePaths', [])),
        symPaths: stringList(c.get('symbolPaths', [])),
        symServer: c.get<string>('symbolServer', '') || undefined,
        pdbFile: undefined,
        apiArgs: c.get<boolean>('apiArguments', false),
        noHeaders: !c.get<boolean>('useSdkHeaders', true),
        maxInsns: Number.isFinite(maxInsns) ? Math.max(0, Math.floor(maxInsns)) : undefined,
        ...overrides,
    };
}

export function configuredPdbFile(): string | undefined {
    return cfg().get<string>('pdbFile', '') || undefined;
}

export function viewerDefaults(): ViewerDefaults {
    const c = cfg();
    return {
        hostile: c.get<boolean>('hostile', false),
        apiArgs: c.get<boolean>('apiArguments', false),
        callDepth: clampInt(c.get<number>('callDepth', 1), 1, 8),
        loadSymbolsOnOpen: c.get<boolean>('loadSymbolsOnOpen', false),
    };
}
