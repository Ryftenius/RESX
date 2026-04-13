const TOP_TABS = new Set([
    'overview',
    'entry',
    'triage',
    'sections',
    'exports',
    'imports',
    'symbols',
    'types',
    'dump',
    'dev',
]);

const DUMP_TABS = new Set(['disasm', 'calls', 'xrefs', 'strings', 'cfg', 'recomp', 'hex']);

export interface PersistedUiState {
    topTab: string;
    dumpSubTab: string;
    asmMetaWidth: number;
}

export function coercePersistedUiState(raw: unknown): PersistedUiState {
    const data = raw && typeof raw === 'object' ? raw as Record<string, unknown> : {};
    const topTab = typeof data.topTab === 'string' && TOP_TABS.has(data.topTab)
        ? data.topTab
        : 'overview';
    const dumpSubTab = typeof data.dumpSubTab === 'string' && DUMP_TABS.has(data.dumpSubTab)
        ? data.dumpSubTab
        : 'disasm';
    const asmMetaWidth = Number.isFinite(Number(data.asmMetaWidth))
        ? Math.max(160, Math.min(520, Number(data.asmMetaWidth)))
        : 280;
    return {
        topTab,
        dumpSubTab,
        asmMetaWidth,
    };
}

export function buildPersistedUiState(state: Partial<PersistedUiState>): PersistedUiState {
    return coercePersistedUiState(state);
}
