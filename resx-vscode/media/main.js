import { renderCfgVisual } from './cfg.js';
import { createSearchBar as _searchBar, wireSearch as _wireSearch, sortTable } from './tables.js';
import { unwrapListPayload, unwrapObjectPayload } from './payloads.js';
import { buildPersistedUiState, coercePersistedUiState } from './view-state.js';
'use strict';
const vscode = acquireVsCodeApi();
const persistedUiState = coercePersistedUiState(vscode.getState());
vscode.postMessage({ command: 'ready' });
const PREFIX_MAP = [
    ['FsRtl', 'io'], ['Psp', 'process'], ['Exp', 'exec'], ['Cmp', 'config'],
    ['Obp', 'object'], ['Sep', 'security'], ['Etw', 'trace'], ['Wmi', 'trace'],
    ['Hal', 'hal'], ['Dbg', 'debug'], ['Ldr', 'loader'], ['Rtl', 'runtime'],
    ['Nt', 'syscall'], ['Zw', 'syscall'], ['Ps', 'process'], ['Ex', 'exec'],
    ['Ke', 'kernel'], ['Ki', 'kernel'], ['Se', 'security'], ['Ob', 'object'],
    ['Mm', 'memory'], ['Io', 'io'], ['Cm', 'config'], ['Cc', 'cache'],
    ['Po', 'power'],
];
const PREFIX_LABELS = {
    syscall: 'Native API / Syscall', kernel: 'Kernel Primitive',
    memory: 'Memory Manager', io: 'I/O / Filesystem', security: 'Security',
    object: 'Object Manager', loader: 'PE Loader (Ldr)', trace: 'ETW / WMI Tracing',
    runtime: 'Runtime Library', debug: 'Debug Support', hal: 'Hardware Abstraction Layer',
    process: 'Process Manager', config: 'Configuration Manager (Registry)',
    power: 'Power Manager', cache: 'Cache Manager', exec: 'Executive Support',
};
const CALL_MNEMS = new Set(['call', 'callf']);
const RET_MNEMS = new Set(['ret', 'retn', 'retf', 'iret', 'iretd', 'iretq', 'retfw']);
const JCC_MNEMS = new Set(['je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae',
    'jb', 'jbe', 'jc', 'jnc', 'jo', 'jno', 'js', 'jns', 'jp', 'jnp', 'jcxz', 'jecxz', 'jrcxz', 'loop', 'loope', 'loopne']);
const JMP_MNEMS = new Set(['jmp', 'jmpf']);
const PRIV_MNEMS = new Set(['hlt', 'cli', 'sti', 'in', 'out', 'ins', 'outs', 'rdmsr', 'wrmsr',
    'rdpmc', 'rdtsc', 'lidt', 'lgdt', 'lldt', 'ltr', 'invd', 'wbinvd', 'invlpg', 'clts', 'sgdt', 'sidt', 'sldt', 'str', 'cpuid']);
const REGS = new Set([
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d',
    'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w',
    'al', 'bl', 'cl', 'dl', 'ah', 'bh', 'ch', 'dh', 'sil', 'dil', 'bpl', 'spl',
    'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7',
    'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15',
    'ymm0', 'ymm1', 'ymm2', 'ymm3', 'ymm4', 'ymm5', 'ymm6', 'ymm7',
    'zmm0', 'zmm1', 'zmm2', 'zmm3', 'rip', 'eflags', 'cs', 'ds', 'es', 'fs', 'gs', 'ss',
    'dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7', 'cr0', 'cr2', 'cr3', 'cr4', 'cr8',
]);
const C_KEYWORDS = new Set(['if', 'else', 'while', 'for', 'do', 'return', 'int', 'void',
    'unsigned', 'signed', 'char', 'short', 'long', 'struct', 'union', 'typedef', 'enum',
    'goto', 'break', 'continue', 'switch', 'case', 'default', 'const', 'static', 'extern',
    'register', 'volatile', 'sizeof', '__int64', '__int32', '__int16', '__int8', '__cdecl',
    '__stdcall', '__fastcall', '__attribute__', 'nullptr', 'inline', 'auto', 'restrict']);
const C_WIN_TYPES = new Set(['BOOL', 'BOOLEAN', 'BYTE', 'CHAR', 'DWORD', 'DWORD64', 'DWORD32',
    'HANDLE', 'HMODULE', 'HINSTANCE', 'HWND', 'HKEY', 'LONG', 'LONGLONG', 'LPVOID', 'LPSTR',
    'LPCSTR', 'LPWSTR', 'LPCWSTR', 'PBYTE', 'PDWORD', 'PVOID', 'QWORD', 'ULONG', 'ULONG64',
    'USHORT', 'VOID', 'WCHAR', 'WORD', 'NTSTATUS', 'HRESULT', 'FARPROC', 'SIZE_T', 'SSIZE_T',
    'TRUE', 'FALSE', 'NULL', 'WINAPI', 'NTAPI', 'CALLBACK', 'APIENTRY', 'STDMETHODCALLTYPE',
    'PHANDLE', 'PULONG', 'INT64', 'UINT64', 'INT32', 'UINT32', 'INT16', 'UINT16', 'INT8', 'UINT8']);
const STATUS_NAMES = new Map([
    ['0x0', 'STATUS_SUCCESS'],
    ['0x103', 'STATUS_PENDING'],
    ['0x104', 'STATUS_REPARSE'],
    ['0x80000005', 'STATUS_BUFFER_OVERFLOW'],
    ['0x80000006', 'STATUS_NO_MORE_FILES'],
    ['0xC0000005', 'STATUS_ACCESS_VIOLATION'],
    ['0xC0000008', 'STATUS_INVALID_HANDLE'],
    ['0xC000000D', 'STATUS_INVALID_PARAMETER'],
    ['0xC0000017', 'STATUS_NO_MEMORY'],
    ['0xC0000018', 'STATUS_CONFLICTING_ADDRESSES'],
    ['0xC0000022', 'STATUS_ACCESS_DENIED'],
    ['0xC0000023', 'STATUS_BUFFER_TOO_SMALL'],
    ['0xC0000034', 'STATUS_OBJECT_NAME_NOT_FOUND'],
    ['0xC0000035', 'STATUS_OBJECT_NAME_COLLISION'],
    ['0xC000003A', 'STATUS_OBJECT_PATH_NOT_FOUND'],
    ['0xC0000043', 'STATUS_SHARING_VIOLATION'],
    ['0xC000007A', 'STATUS_PROCEDURE_NOT_FOUND'],
    ['0xC000009A', 'STATUS_INSUFFICIENT_RESOURCES'],
    ['0xC00000BB', 'STATUS_NOT_SUPPORTED'],
    ['0xC0000135', 'STATUS_DLL_NOT_FOUND'],
    ['0xC0000139', 'STATUS_ENTRYPOINT_NOT_FOUND'],
    ['0xC0000142', 'STATUS_DLL_INIT_FAILED'],
    ['0xC0000225', 'STATUS_NOT_FOUND'],
]);
const DUMP_SUBTABS = ['disasm', 'calls', 'xrefs', 'strings', 'cfg', 'recomp', 'hex'];
const st = {
    navHistory: [],
    navPos: -1,
    dumpCache: new Map(),
    activeDumpRequestId: null,
    activeTopTab: persistedUiState.topTab,
    activeDumpSubTab: persistedUiState.dumpSubTab,
    explainCache: new Map(),
    explainPending: new Set(),
    iatIndex: new Map(),
    entryPoint: null,
    tooltip: null,
    tipTimer: null,
    ctxMenu: null,
    pdbPaths: [],
    pdbFile: '',
    symServer: '',
    rootDll: '',
    rootDllPath: '',
    currentDumpDll: '',
    currentDumpPath: '',
    apiDepth: 1,
    hostile: false,
    devLogs: [],
    reconstructRequested: false,
    scanRequested: false,
    scanRoot: '',
    currentPeInfo: null,
    typesByName: new Map(),
    asmMetaWidth: persistedUiState.asmMetaWidth,
    _lastHovered: null,
    _pendingTypeNav: null,
};
const $ = id => document.getElementById(id);
function persistUiState() {
    vscode.setState(buildPersistedUiState({
        topTab: st.activeTopTab,
        dumpSubTab: st.activeDumpSubTab,
        asmMetaWidth: st.asmMetaWidth,
    }));
}
function esc(s) {
    return String(s ?? '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function errBox(msg) {
    const d = document.createElement('div');
    d.className = 'err-box';
    d.textContent = msg;
    return d;
}
function kvRow(k, v) {
    const row = document.createElement('div');
    row.className = 'kv';
    row.innerHTML = `<span class="kv-k">${esc(k)}</span><span class="kv-v">${esc(String(v))}</span>`;
    return row;
}
function formatBytes(n) {
    if (n == null)
        return '—';
    const u = ['B', 'KB', 'MB', 'GB'];
    let i = 0, v = Number(n);
    while (v >= 1024 && i < 3) {
        v /= 1024;
        i++;
    }
    return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}
function fmtDevTime(iso) {
    const d = iso ? new Date(iso) : null;
    if (!d || Number.isNaN(d.getTime()))
        return '—';
    return d.toLocaleTimeString([], { hour12: false });
}
function normalizeRva(rva) {
    if (rva == null)
        return null;
    const raw = String(rva).trim();
    if (!raw)
        return null;
    const hex = raw.replace(/^0x/i, '').toUpperCase();
    return `0x${hex.padStart(8, '0')}`;
}
function normalizeImportName(name) {
    const raw = String(name || '').trim();
    if (!raw)
        return '';
    return raw.replace(/^(__?imp_)+/i, '');
}
function canonicalTypeName(name) {
    let raw = String(name || '').trim();
    if (!raw)
        return '';
    raw = raw
        .replace(/\b(?:const|volatile|struct|class|union|enum)\b\s*/gi, '')
        .replace(/\b(?:__ptr64|__unaligned|__restrict|__cdecl|__stdcall|__fastcall|__thiscall|__vectorcall)\b\s*/gi, '')
        .trim();
    while (raw) {
        const next = raw
            .replace(/\s*(?:const|volatile)\s*$/i, '')
            .replace(/\s*[*&]+\s*$/g, '')
            .replace(/\s*\[[^\]]*\]\s*$/g, '')
            .trim();
        if (next === raw)
            break;
        raw = next;
    }
    return raw.toLowerCase();
}
function scoreTypeEntry(entry) {
    const members = entry?.members?.length || 0;
    const refs = entry?.symbol_count || 0;
    const concrete = /^(struct|class|union|enum)$/i.test(String(entry?.kind || '')) ? 100 : 0;
    const sized = entry?.size ? 4 : 0;
    return concrete + sized + members * 3 + refs;
}
function rememberTypeEntry(map, key, entry) {
    if (!key)
        return;
    const prev = map.get(key);
    if (!prev || scoreTypeEntry(entry) > scoreTypeEntry(prev)) {
        map.set(key, entry);
    }
}
function normalizeModuleName(name) {
    const raw = String(name || '').trim();
    if (!raw)
        return null;
    if (/\.(dll|exe|sys)$/i.test(raw))
        return raw;
    if (/^(ntoskrnl|ntkrnlmp|ntkrnlpa|ntkrpamp)$/i.test(raw))
        return `${raw}.exe`;
    if (/^hal$/i.test(raw))
        return `${raw}.dll`;
    return `${raw}.dll`;
}
function moduleFamily(name) {
    const normalized = normalizeModuleName(name);
    if (!normalized)
        return '';
    const lower = normalized.toLowerCase();
    if (['ntoskrnl.exe', 'ntkrnlmp.exe', 'ntkrnlpa.exe', 'ntkrpamp.exe'].includes(lower)) {
        return 'nt-kernel';
    }
    if (lower === 'hal.dll') {
        return 'hal';
    }
    return lower;
}
function basenamePath(p) {
    const raw = String(p || '').trim();
    if (!raw)
        return '';
    const parts = raw.split(/[/\\]+/);
    return parts[parts.length - 1] || '';
}
function moduleScope(entry) {
    const pathScope = String(entry?.dllPath || '').trim().toLowerCase();
    if (pathScope)
        return `path:${pathScope}`;
    const dllScope = moduleFamily(entry?.dll || '');
    if (dllScope)
        return `dll:${dllScope}`;
    return 'doc:current';
}
function sameImageModule(left, right) {
    const a = normalizeModuleName(left);
    const b = normalizeModuleName(right);
    return !!(a && b && moduleFamily(a) === moduleFamily(b));
}
function stripScopedName(name) {
    const raw = String(name || '').trim();
    if (!raw)
        return '';
    if (raw.includes('!'))
        return raw.split('!').pop();
    if (raw.includes('.'))
        return raw.split('.').pop();
    return raw;
}
function resolveNavigationTarget(funcName, dll = null) {
    const cleaned = normalizeImportName(funcName);
    const inferredDll = dll || st.iatIndex.get(cleaned) || st.iatIndex.get(funcName) || null;
    return { func: cleaned || funcName, dll: normalizeModuleName(inferredDll) };
}
function dumpCacheKey(entry) {
    const scope = moduleScope(entry);
    const depth = Math.max(1, Math.min(5, Number(entry?.funcsDepth || 1) || 1));
    const hostile = st.hostile ? ':hostile' : '';
    if (entry?.rva)
        return `rva:${scope}:${normalizeRva(entry.rva)}:depth:${depth}${hostile}`;
    const dll = entry?.dll ? String(entry.dll).toLowerCase() : '';
    const fn = entry?.fn ? String(entry.fn).toLowerCase() : '';
    return `fn:${scope}:${dll}!${fn}:depth:${depth}${hostile}`;
}
function startupBadgeLabel(entry) {
    const kind = String(entry?.kind || '').toLowerCase();
    if (kind.includes('real main'))
        return 'Main';
    if (kind.includes('entry point'))
        return 'EP';
    if (kind.includes('tls'))
        return 'TLS';
    if (kind.includes('handoff'))
        return 'Handoff';
    if (kind.includes('chain'))
        return 'Chain';
    if (kind.includes('xl'))
        return 'XL';
    return String(entry?.kind || 'Start').split(/\s+/)[0];
}
function startupDepth(entry) {
    const source = String(entry?.source || '');
    const match = source.match(/depth\s+(\d+)/i);
    return match ? Number(match[1]) : 99;
}
function startupCategory(entry) {
    const kind = String(entry?.kind || '').toLowerCase();
    if (kind.includes('entry point'))
        return 'pe-entry';
    if (kind.includes('tls'))
        return 'tls';
    if (kind.includes('real main'))
        return 'real-main';
    if (kind.includes('handoff'))
        return 'handoff';
    if (kind.includes('chain'))
        return 'chain';
    if (kind.includes('xl'))
        return 'xl';
    return 'other';
}
function startupRvaValue(entry) {
    return parseAddressValue(entry?.rva) ?? 0n;
}
function summarizeStartupRoutines(startupRoutines = []) {
    const entries = Array.isArray(startupRoutines) ? startupRoutines.slice() : [];
    const peEntry = entries.find(entry => startupCategory(entry) === 'pe-entry') || null;
    const tlsCallbacks = entries.filter(entry => startupCategory(entry) === 'tls');
    const handoffs = entries
        .filter(entry => {
        const category = startupCategory(entry);
        return category === 'handoff' || category === 'chain';
    })
        .sort((a, b) => startupDepth(a) - startupDepth(b) || (startupRvaValue(a) < startupRvaValue(b) ? -1 : 1));
    const mainCandidates = entries.filter(entry => startupCategory(entry) === 'real-main');
    const bootstrap = handoffs[0] || null;
    const handoffAnchors = handoffs.map(startupRvaValue);
    const scoreMainCandidate = entry => {
        let score = 0;
        const source = String(entry?.source || '').toLowerCase();
        const note = String(entry?.note || '').toLowerCase();
        const section = String(entry?.section || '').toLowerCase();
        const rva = startupRvaValue(entry);
        if (source.includes('lea'))
            score += 18;
        if (source.includes('mov'))
            score += 8;
        if (source.includes('push'))
            score += 4;
        if (section === '.text' || section === 'text')
            score += 14;
        if (note.includes('callback or main routine'))
            score += 12;
        if (rva >= 0x1000n)
            score += 8;
        const isAligned = (rva & 0xfn) === 0n;
        if (isAligned)
            score += 6;
        if ((rva & 1n) !== 0n)
            score -= 18;
        const depth = startupDepth(entry);
        if (depth !== 99) {
            if (depth <= 1)
                score += 24;
            else if (depth <= 2)
                score += 12;
            else if (depth >= 4)
                score -= 12;
        }
        let nearest = null;
        for (const anchor of handoffAnchors) {
            const delta = anchor > rva ? anchor - rva : rva - anchor;
            if (nearest == null || delta < nearest)
                nearest = delta;
        }
        if (nearest != null) {
            if (nearest <= 0x40n)
                score += 32;
            else if (nearest <= 0x200n)
                score += 20;
            else if (nearest <= 0x2000n)
                score += 10;
            else if (nearest <= 0x10000n)
                score += 4;
        }
        return score;
    };
    const rankedMains = mainCandidates
        .map(entry => ({ entry, score: scoreMainCandidate(entry) }))
        .sort((a, b) => b.score - a.score || (startupRvaValue(a.entry) < startupRvaValue(b.entry) ? -1 : 1));
    return {
        peEntry,
        tlsCallbacks,
        bootstrap,
        expectedMain: rankedMains[0]?.entry || null,
        alternateMains: rankedMains.slice(1, 4).map(item => item.entry),
        rankedMains: rankedMains.map(item => item.entry),
        rawEntries: entries,
        chainCount: handoffs.length,
    };
}
function appendStartupTarget(container, label, entry, extra = '') {
    if (!entry)
        return;
    const row = document.createElement('div');
    row.className = 'startup-row';
    const key = document.createElement('div');
    key.className = 'startup-key';
    key.textContent = label;
    const value = document.createElement('div');
    value.className = 'startup-value';
    const link = document.createElement('span');
    link.className = 'fn-link';
    link.textContent = `${entry.rva}`;
    link.title = entry.note || `Disassemble ${entry.kind} at ${entry.rva}`;
    link.addEventListener('click', () => navigateRva(entry.rva, `${entry.kind}@${entry.rva}`));
    value.appendChild(link);
    const meta = [];
    if (entry.section)
        meta.push(entry.section);
    if (entry.source)
        meta.push(entry.source);
    if (extra)
        meta.push(extra);
    if (meta.length) {
        const metaEl = document.createElement('div');
        metaEl.className = 'startup-meta';
        metaEl.textContent = meta.join(' · ');
        value.appendChild(metaEl);
    }
    if (entry.note) {
        const note = document.createElement('div');
        note.className = 'startup-note';
        note.textContent = entry.note;
        value.appendChild(note);
    }
    row.append(key, value);
    container.appendChild(row);
    return { row, value };
}
function setTabVisible(id, visible) {
    const btn = document.querySelector(`.tab[data-tab="${id}"]`);
    if (!btn)
        return;
    btn.classList.toggle('hidden', !visible);
    if (!visible && st.activeTopTab === id) {
        activateTab('overview');
    }
}
function renderEntryPanel(d) {
    const panel = $('panel-entry');
    panel.innerHTML = '';
    const startupSummary = summarizeStartupRoutines(d.startup_routines || []);
    setTabVisible('entry', startupSummary.rawEntries.length > 0);
    if (!startupSummary.rawEntries.length) {
        panel.innerHTML = '<p class="no-data">No startup or entry analysis.</p>';
        return;
    }
    const startupCard = _card('Program Entry');
    startupCard.card.style.gridColumn = '1 / -1';
    appendStartupTarget(startupCard.body, 'PE Entry', startupSummary.peEntry);
    if (startupSummary.bootstrap) {
        const kind = startupCategory(startupSummary.bootstrap) === 'handoff' ? 'runtime bootstrap' : 'startup chain';
        appendStartupTarget(startupCard.body, 'Runtime Bootstrap', startupSummary.bootstrap, kind);
    }
    const primaryMain = startupSummary.expectedMain;
    if (primaryMain) {
        const primary = appendStartupTarget(startupCard.body, 'Expected Real Main', primaryMain, 'best heuristic match');
        if (startupSummary.alternateMains.length && primary) {
            const altDetails = document.createElement('details');
            altDetails.className = 'startup-alt';
            const altSummary = document.createElement('summary');
            altSummary.textContent = `Alternate main candidates (${startupSummary.alternateMains.length})`;
            altDetails.appendChild(altSummary);
            startupSummary.alternateMains.forEach((entry, idx) => {
                appendStartupTarget(altDetails, `Alt Main ${idx + 1}`, entry, 'alternate candidate');
            });
            primary.value.appendChild(altDetails);
        }
    }
    startupSummary.tlsCallbacks.forEach((cb, i) => {
        const label = startupSummary.tlsCallbacks.length > 1 ? `TLS Callback ${i + 1}` : 'TLS Callback';
        appendStartupTarget(startupCard.body, label, cb);
    });
    const a = d.analysis || {};
    const stackSummary = [];
    if (a.runtime)
        stackSummary.push(`runtime: ${a.runtime}`);
    if (a.likely_toolchains?.length)
        stackSummary.push(`toolchain: ${a.likely_toolchains.join(', ')}`);
    if (a.likely_components?.length)
        stackSummary.push(`components: ${a.likely_components.join(', ')}`);
    if (stackSummary.length) {
        const stack = document.createElement('div');
        stack.className = 'startup-stack';
        stack.textContent = stackSummary.join(' | ');
        startupCard.body.appendChild(stack);
    }
    const rawDetails = document.createElement('details');
    rawDetails.className = 'startup-raw';
    const summary = document.createElement('summary');
    summary.textContent = `Raw startup evidence (${startupSummary.rawEntries.length} entries, ${startupSummary.chainCount} startup branches)`;
    rawDetails.appendChild(summary);
    startupSummary.rawEntries.forEach(entry => {
        const row = document.createElement('div');
        row.className = 'startup-raw-row';
        const label = document.createElement('span');
        label.className = 'startup-raw-kind';
        label.textContent = `${entry.kind}`;
        const link = document.createElement('span');
        link.className = 'fn-link';
        link.textContent = `${entry.rva}`;
        link.title = entry.note || `Disassemble ${entry.kind} at ${entry.rva}`;
        link.addEventListener('click', () => navigateRva(entry.rva, `${entry.kind}@${entry.rva}`));
        const meta = document.createElement('span');
        meta.className = 'startup-raw-meta';
        meta.textContent = [entry.section || '', entry.source || '', entry.note || '']
            .filter(Boolean)
            .join(' · ');
        row.append(label, link, meta);
        rawDetails.appendChild(row);
    });
    startupCard.body.appendChild(rawDetails);
    panel.appendChild(startupCard.card);
}
function prefixClass(name) {
    for (const [pfx, cls] of PREFIX_MAP) {
        if (name.length > pfx.length &&
            name.slice(0, pfx.length) === pfx &&
            /^[A-Z]/.test(name[pfx.length]))
            return cls;
    }
    return null;
}
function mnemonicClass(mnem) {
    const m = mnem.toLowerCase();
    if (CALL_MNEMS.has(m))
        return 'asm-kw-call';
    if (RET_MNEMS.has(m))
        return 'asm-kw-ret';
    if (JCC_MNEMS.has(m))
        return 'asm-kw-jcc';
    if (JMP_MNEMS.has(m))
        return 'asm-kw-jmp';
    if (m === 'nop' || m === 'pause')
        return 'asm-kw-nop';
    if (PRIV_MNEMS.has(m))
        return 'asm-kw-priv';
    if (m.startsWith('v') || m.startsWith('p') && m.length > 4)
        return 'asm-kw-simd';
    return 'asm-kw';
}
function cfgMnemonicClass(mnem) {
    const m = mnem.toLowerCase();
    if (CALL_MNEMS.has(m))
        return 'cfg-mnem-call';
    if (RET_MNEMS.has(m))
        return 'cfg-mnem-ret';
    if (JCC_MNEMS.has(m))
        return 'cfg-mnem-jcc';
    if (JMP_MNEMS.has(m))
        return 'cfg-mnem-jmp';
    if (m === 'nop')
        return 'cfg-mnem-nop';
    return '';
}
function registerFamily(reg) {
    const r = String(reg || '').toLowerCase();
    const fams = [
        ['rax', ['rax', 'eax', 'ax', 'al', 'ah']],
        ['rbx', ['rbx', 'ebx', 'bx', 'bl', 'bh']],
        ['rcx', ['rcx', 'ecx', 'cx', 'cl', 'ch']],
        ['rdx', ['rdx', 'edx', 'dx', 'dl', 'dh']],
        ['rsi', ['rsi', 'esi', 'si', 'sil']],
        ['rdi', ['rdi', 'edi', 'di', 'dil']],
        ['rbp', ['rbp', 'ebp', 'bp', 'bpl']],
        ['rsp', ['rsp', 'esp', 'sp', 'spl']],
        ['r8', ['r8', 'r8d', 'r8w', 'r8b']],
        ['r9', ['r9', 'r9d', 'r9w', 'r9b']],
        ['r10', ['r10', 'r10d', 'r10w', 'r10b']],
        ['r11', ['r11', 'r11d', 'r11w', 'r11b']],
        ['r12', ['r12', 'r12d', 'r12w', 'r12b']],
        ['r13', ['r13', 'r13d', 'r13w', 'r13b']],
        ['r14', ['r14', 'r14d', 'r14w', 'r14b']],
        ['r15', ['r15', 'r15d', 'r15w', 'r15b']],
        ['rip', ['rip', 'eip', 'ip']],
    ];
    for (const [fam, names] of fams) {
        if (names.includes(r))
            return fam;
    }
    return r;
}
function collectRegisters(text) {
    const matches = String(text || '').match(/\b([re]?(?:ax|bx|cx|dx|si|di|bp|sp)|r(?:[8-9]|1[0-5])(?:d|w|b)?|[abcd][lh]|[cdefgs]s|rip|eip|xmm\d+|ymm\d+|zmm\d+)\b/gi) || [];
    return [...new Set(matches.map(registerFamily).filter(Boolean))];
}
function summarizeRegisters(insns) {
    const state = new Map();
    const usage = new Map();
    for (const insn of insns) {
        const text = String(insn.text || '');
        const [mnemRaw, ...restParts] = text.split(/\s+/);
        const mnem = String(mnemRaw || '').toLowerCase();
        const operandText = restParts.join(' ');
        const parts = operandText.split(',').map(s => s.trim()).filter(Boolean);
        const regs = collectRegisters(text);
        regs.forEach(reg => usage.set(reg, (usage.get(reg) || 0) + 1));
        const dst = parts[0] || '';
        const src = parts.slice(1).join(', ');
        const dstRegMatch = dst.match(/^(?:[a-z]{2,4}\s+ptr\s+)?([A-Za-z0-9]+)$/i);
        const dstReg = dstRegMatch ? registerFamily(dstRegMatch[1]) : null;
        if (!dstReg || !REGS.has(String(dstRegMatch?.[1] || '').toLowerCase()))
            continue;
        let summary = '';
        if (mnem === 'mov' || mnem === 'lea') {
            summary = src || operandText;
        }
        else if (mnem === 'xor' && parts.length >= 2 && registerFamily(parts[0]) === registerFamily(parts[1])) {
            summary = '0';
        }
        else if (mnem === 'call') {
            summary = 'call result';
        }
        else if (mnem === 'pop') {
            summary = 'stack value';
        }
        else if (mnem === 'and' || mnem === 'or' || mnem === 'add' || mnem === 'sub' || mnem === 'shl' || mnem === 'shr') {
            summary = `${mnem} ${src}`.trim();
        }
        if (summary) {
            state.set(dstReg, { summary, rva: insn.rva });
        }
    }
    return [...usage.entries()]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .slice(0, 12)
        .map(([reg]) => ({
        reg,
        summary: state.get(reg)?.summary || 'used',
        rva: state.get(reg)?.rva || '',
    }));
}
function summarizeStack(insns) {
    const slots = new Map();
    let frameSize = null;
    let shadowSpace = false;
    for (const insn of insns.slice(0, 80)) {
        const text = String(insn.text || '');
        const lower = text.toLowerCase();
        const subRsp = lower.match(/^sub\s+rsp,\s*([0-9a-f]+)h$/i);
        if (subRsp && frameSize == null) {
            frameSize = `0x${subRsp[1].toUpperCase()}`;
        }
        if (/^\s*mov\s+\[rsp\+20h\],/i.test(text)) {
            shadowSpace = true;
        }
        const memStore = text.match(/^(mov|lea)\s+\[(rsp|rbp)([+-][0-9A-Fa-f]+h?)?\],\s*(.+)$/i);
        if (!memStore)
            continue;
        const base = memStore[2].toLowerCase();
        const disp = (memStore[3] || '+0').replace(/\s+/g, '');
        const src = memStore[4].trim();
        const key = `${base}${disp}`;
        if (!slots.has(key)) {
            slots.set(key, {
                slot: `${base}${disp}`,
                value: src,
                rva: insn.rva,
            });
        }
    }
    const items = [...slots.values()]
        .sort((a, b) => a.slot.localeCompare(b.slot))
        .slice(0, 12);
    return { frameSize, shadowSpace, items };
}
function estimateHeaderMeta(insns, xrefs) {
    const stack = summarizeStack(insns);
    return {
        stackSize: stack.frameSize,
        xrefCount: Array.isArray(xrefs) ? xrefs.length : 0,
    };
}
function parseHexValue(value) {
    const raw = String(value || '').trim();
    if (!raw)
        return NaN;
    return raw.startsWith('0x') || raw.startsWith('0X') ? parseInt(raw, 16) : parseInt(raw, 10);
}
function parseAddressValue(value) {
    const raw = String(value || '').trim();
    if (!raw)
        return null;
    const normalized = raw.replace(/h$/i, '');
    try {
        if (/^[-+]?0x[0-9A-Fa-f]+$/i.test(normalized))
            return BigInt(normalized);
        if (/^[-+]?[0-9A-Fa-f]+$/i.test(normalized) && /[A-Fa-f]/.test(normalized))
            return BigInt(`0x${normalized}`);
        if (/^[-+]?\d+$/.test(normalized))
            return BigInt(normalized);
    }
    catch {
        return null;
    }
    return null;
}
function formatAddressHex(value, minWidth = 1) {
    const sign = value < 0n ? '-' : '';
    const hex = (value < 0n ? -value : value).toString(16).toUpperCase().padStart(minWidth, '0');
    return `${sign}0x${hex}`;
}
function decodeStatusLiteral(value) {
    const parsed = parseAddressValue(value);
    if (parsed == null)
        return null;
    const key = formatAddressHex(parsed).toUpperCase();
    return STATUS_NAMES.get(key) || null;
}
function detectCurrentSyscallInfo(d, fallbackLabel) {
    const dll = String(d?.dll || '').toLowerCase();
    const fn = String(d?.function || fallbackLabel || '').trim();
    if (!dll.includes('ntdll') || !/^(Nt|Zw)[A-Za-z0-9_@$]+$/.test(fn))
        return null;
    const insns = Array.isArray(d?.instructions) ? d.instructions : [];
    const hasSyscall = insns.some(insn => /^syscall$/i.test(String(insn.text || '').trim())
        || /^sysenter$/i.test(String(insn.text || '').trim())
        || /^int\s+2Eh$/i.test(String(insn.text || '').trim()));
    if (!hasSyscall)
        return null;
    let serviceNumber = '';
    for (const insn of insns.slice(0, 12)) {
        const text = String(insn.text || '').trim();
        const mov = text.match(/^mov\s+(?:eax|rax|ax|al),\s*(?:0x)?([0-9A-Fa-f]+)$/i);
        if (mov) {
            serviceNumber = `0x${mov[1].toUpperCase()}`;
            break;
        }
    }
    const kernelSymbol = fn.startsWith('Zw') ? `Nt${fn.slice(2)}` : fn;
    return {
        service_number: serviceNumber || '',
        kernel_module: 'ntoskrnl.exe',
        kernel_symbol: kernelSymbol,
        kernel_rva: '',
    };
}
function findSectionForRva(sections, rva) {
    const target = parseAddressValue(rva);
    if (target == null)
        return null;
    for (const sec of sections || []) {
        const start = parseAddressValue(sec.rva);
        const virtualSize = parseAddressValue(sec.virtual_size);
        const rawSize = parseAddressValue(sec.raw_size);
        if (start == null || virtualSize == null || rawSize == null)
            continue;
        const size = virtualSize > rawSize ? virtualSize : rawSize;
        if (target >= start && target < start + size)
            return sec;
    }
    return null;
}
function shortenAddressForImage(rawValue, sections, imageBase) {
    const raw = String(rawValue || '').trim();
    if (!/^(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h)$/i.test(raw))
        return null;
    const normalized = /^0x/i.test(raw) ? raw : `0x${raw.replace(/h$/i, '')}`;
    const absolute = parseAddressValue(normalized);
    if (absolute == null)
        return null;
    const base = parseAddressValue(imageBase);
    let rva = absolute;
    if (base != null && absolute >= base)
        rva = absolute - base;
    if (rva < 0n)
        rva = absolute;
    const section = findSectionForRva(sections, formatAddressHex(rva));
    if (!section)
        return null;
    const secBase = parseAddressValue(section.rva);
    if (secBase == null)
        return null;
    const offset = rva >= secBase ? rva - secBase : 0n;
    return {
        raw,
        short: `${section.name}+${formatAddressHex(offset)}`,
        section: section.name,
        rva: formatAddressHex(rva),
    };
}
function simplifyArgumentValue(raw, sections = [], imageBase = '') {
    const text = String(raw || '').trim();
    if (!text)
        return '';
    const status = decodeStatusLiteral(text);
    if (status)
        return status;
    const shortened = shortenAddressForImage(text, sections, imageBase);
    if (shortened)
        return shortened.short;
    return text
        .replace(/\b(?:qword|dword|word|byte|xmmword|ymmword|zmmword)\s+ptr\b/gi, '')
        .replace(/\s+/g, ' ')
        .trim();
}
function parseIntegerValue(value) {
    const raw = String(value || '').trim();
    if (!raw)
        return null;
    if (/^-?\d+$/.test(raw)) {
        try {
            return BigInt(raw);
        }
        catch {
            return null;
        }
    }
    if (/^(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h)$/i.test(raw)) {
        return parseAddressValue(raw);
    }
    return null;
}
function parseStringRefEntry(text) {
    const raw = String(text || '').trim();
    if (!raw)
        return null;
    const match = raw.match(/^(0x[0-9A-Fa-f]+)(?:\s+len\s+(0x[0-9A-Fa-f]+))?\s+→\s+(L?"(?:[^"\\]|\\.)*")$/);
    if (!match)
        return null;
    return {
        rva: normalizeRva(match[1]),
        len: match[2] ? normalizeRva(match[2]) : '',
        value: match[3],
    };
}
function buildStringRefMaps(strings = []) {
    const byRva = new Map();
    const byRvaLen = new Map();
    for (const entry of strings || []) {
        const parsed = parseStringRefEntry(entry);
        if (!parsed)
            continue;
        if (!byRva.has(parsed.rva))
            byRva.set(parsed.rva, parsed.value);
        if (parsed.len)
            byRvaLen.set(`${parsed.rva}:${parsed.len.toLowerCase()}`, parsed.value);
    }
    return { byRva, byRvaLen };
}
function resolveOperandRva(raw, sections = [], imageBase = '') {
    const text = String(raw || '').trim();
    if (!text)
        return '';
    const addressMatch = text.match(/(?:^|[\[\s,])(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h)(?:$|[\]\s,])/i);
    if (addressMatch) {
        const shortened = shortenAddressForImage(addressMatch[1], sections, imageBase);
        if (shortened?.rva)
            return normalizeRva(shortened.rva);
    }
    const sectionMatch = text.match(/\[?([.A-Za-z0-9_$]+)\+(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h)\]?/);
    if (!sectionMatch)
        return '';
    const section = (sections || []).find(sec => String(sec?.name || '').toLowerCase() === sectionMatch[1].toLowerCase());
    const sectionBase = parseAddressValue(section?.rva);
    const offset = parseIntegerValue(sectionMatch[2]);
    if (sectionBase == null || offset == null)
        return '';
    return formatAddressHex(sectionBase + offset);
}
function inferRegisterValueBefore(insns, idx, reg, sections = [], imageBase = '', semanticNotes = new Map(), stringRefs = { byRva: new Map(), byRvaLen: new Map() }) {
    const want = registerFamily(reg);
    for (let i = idx - 1, seen = 0; i >= 0 && seen < 20; i--, seen++) {
        const text = String(insns[i]?.text || '').trim();
        if (!text)
            continue;
        const mov = text.match(/^(mov|lea)\s+([A-Za-z0-9]+)\s*,\s*(.+)$/i);
        if (mov && registerFamily(mov[2]) === want) {
            const semantic = semanticNotes.get(normalizeRva(insns[i]?.rva));
            if (semantic)
                return semantic;
            const sourceRva = resolveOperandRva(mov[3], sections, imageBase);
            if (sourceRva) {
                const literal = stringRefs.byRva?.get(sourceRva);
                if (literal)
                    return literal;
            }
            if (insns[i]?.comment)
                return simplifyArgumentValue(insns[i].comment, sections, imageBase);
            return simplifyArgumentValue(mov[3], sections, imageBase);
        }
        const zero = text.match(/^xor\s+([A-Za-z0-9]+)\s*,\s*([A-Za-z0-9]+)$/i);
        if (zero && registerFamily(zero[1]) === want && registerFamily(zero[2]) === want) {
            return '0';
        }
        const pop = text.match(/^pop\s+([A-Za-z0-9]+)$/i);
        if (pop && registerFamily(pop[1]) === want) {
            return 'stack value';
        }
    }
    return '';
}
function inferCallArguments(insns, callRva, arch, sections = [], imageBase = '', semanticNotes = new Map(), stringRefs = { byRva: new Map(), byRvaLen: new Map() }) {
    const targetRva = normalizeRva(callRva);
    const idx = insns.findIndex(insn => normalizeRva(insn?.rva) === targetRva);
    if (idx < 0)
        return [];
    if (String(arch || '').includes('64')) {
        return ['rcx', 'rdx', 'r8', 'r9']
            .map(reg => {
            const value = inferRegisterValueBefore(insns, idx, reg, sections, imageBase, semanticNotes, stringRefs);
            return value ? `${reg}=${value}` : '';
        })
            .filter(Boolean);
    }
    const args = [];
    for (let i = idx - 1, seen = 0; i >= 0 && seen < 12 && args.length < 6; i--, seen++) {
        const text = String(insns[i]?.text || '').trim();
        if (!text)
            continue;
        if (/^(call|jmp|ret)\b/i.test(text))
            break;
        const push = text.match(/^push\s+(.+)$/i);
        if (push) {
            args.unshift(`arg${args.length}=${simplifyArgumentValue(push[1], sections, imageBase)}`);
            continue;
        }
        if (!/^(mov|lea|xor)\b/i.test(text))
            break;
    }
    return args;
}
function resolveCallStringSlices(args, stringRefs, sections = [], imageBase = '') {
    const parsed = new Map();
    for (const arg of args || []) {
        const parts = String(arg).split('=');
        const key = String(parts[0] || '').trim().toLowerCase();
        const value = parts.slice(1).join('=').trim();
        if (key && value)
            parsed.set(key, value);
    }
    const pairs = [['rcx', 'rdx'], ['r8', 'r9'], ['arg0', 'arg1'], ['arg2', 'arg3']];
    for (const [ptrReg, lenReg] of pairs) {
        const ptrValue = parsed.get(ptrReg);
        const lenValue = parsed.get(lenReg);
        if (!ptrValue || !lenValue)
            continue;
        const rva = resolveOperandRva(ptrValue, sections, imageBase);
        const len = parseIntegerValue(lenValue);
        if (!rva || len == null)
            continue;
        const exact = stringRefs.byRvaLen?.get(`${normalizeRva(rva)}:${normalizeRva(`0x${len.toString(16)}`)?.toLowerCase()}`);
        if (exact)
            return { literal: exact, pointer: ptrReg, length: lenReg };
        const fallback = stringRefs.byRva?.get(normalizeRva(rva));
        if (fallback)
            return { literal: fallback, pointer: ptrReg, length: lenReg };
    }
    return null;
}
function buildCallArgumentNotes(insns, apiCalls, arch, sections = [], imageBase = '', strings = []) {
    const notes = new Map();
    const semanticNotes = buildHeuristicInsnNotes(insns || []);
    const stringRefs = buildStringRefMaps(strings || []);
    for (const call of apiCalls || []) {
        let args = inferCallArguments(insns || [], call?.rva, arch, sections, imageBase, semanticNotes, stringRefs);
        const stringSlice = resolveCallStringSlices(args, stringRefs, sections, imageBase);
        if (stringSlice) {
            args = args.map(arg => {
                const key = String(arg).split('=')[0].trim().toLowerCase();
                if (key === stringSlice.pointer)
                    return `${key}=${stringSlice.literal}`;
                return arg;
            });
        }
        const semanticCall = summarizeCallSemantics(call, args);
        const callNotes = semanticCall ? [semanticCall] : (args.length ? [args.join(', ')] : []);
        if (callNotes.length)
            notes.set(normalizeRva(call.rva), callNotes);
    }
    return notes;
}
function parseSemanticValue(raw) {
    const text = String(raw || '').trim();
    if (!text)
        return null;
    const typed = text.match(/^([A-Za-z0-9_.*]+)::(.+)$/);
    if (typed) {
        return { type: typed[1], expr: typed[2] };
    }
    return { type: '', expr: text };
}
function semanticValue(type, expr) {
    return type ? `${type}::${expr}` : String(expr || '');
}
function semanticExpr(raw) {
    return parseSemanticValue(raw)?.expr || String(raw || '').trim();
}
function semanticType(raw) {
    return parseSemanticValue(raw)?.type || '';
}
function cleanCommentText(text) {
    return String(text || '').replace(/^\s*;\s*/, '').trim();
}
function sanitizeSemanticNote(raw) {
    let text = cleanCommentText(String(raw || ''));
    if (!text)
        return '';
    text = text.replace(/^[^:;]+::/, '');
    let prev = '';
    while (text !== prev) {
        prev = text;
        text = text
            .replace(/\+0x0(?=\+|$)/g, '')
            .replace(/->Flink->Flink/g, '->Flink')
            .replace(/->Blink->Blink/g, '->Blink')
            .replace(/\s{2,}/g, ' ')
            .trim();
    }
    return text;
}
function composeSemanticComment(baseComment, semantic) {
    const base = cleanCommentText(baseComment);
    const sem = sanitizeSemanticNote(semantic);
    if (!sem)
        return base;
    if (!base)
        return sem;
    if (base === sem || base.includes(sem))
        return base;
    if (sem.includes(base))
        return sem;
    const target = base.includes('=>') ? base.split('=>').pop().trim() : base;
    if (/^load\s+/i.test(sem) && target) {
        return `${sem} from ${target}`;
    }
    if (/^[A-Z][A-Za-z0-9_.]+$/.test(sem) && target && /^([A-Z][A-Za-z0-9_.]+)$/.test(target)) {
        return sem;
    }
    return `${sem} (${target})`;
}
function mapKnownField(baseType, offsetHex) {
    const off = String(offsetHex || '').toUpperCase();
    const map = {
        'TEB*': {
            '30': ['TEB.Self', 'TEB*'],
            '58': ['TEB.ThreadLocalStoragePointer', 'PVOID*'],
            '60': ['TEB.ProcessEnvironmentBlock', 'PEB*'],
        },
        'PEB*': {
            '2': ['PEB.BeingDebugged', 'BOOLEAN'],
            '10': ['PEB.ImageBaseAddress', 'PVOID'],
            '18': ['PEB.Ldr', 'PEB_LDR_DATA*'],
            '20': ['PEB.ProcessParameters', 'RTL_USER_PROCESS_PARAMETERS*'],
            '68': ['PEB.ApiSetMap', 'API_SET_NAMESPACE*'],
        },
        'PEB_LDR_DATA*': {
            '10': ['PEB_LDR_DATA.InLoadOrderModuleList', 'LIST_ENTRY* loader head'],
            '20': ['PEB_LDR_DATA.InMemoryOrderModuleList', 'LIST_ENTRY* memory-order head'],
            '30': ['PEB_LDR_DATA.InInitializationOrderModuleList', 'LIST_ENTRY* init-order head'],
        },
        'LDR_DATA_TABLE_ENTRY*': {
            '0': ['LDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Flink', 'LDR_DATA_TABLE_ENTRY*'],
            '8': ['LDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Blink', 'LDR_DATA_TABLE_ENTRY*'],
            '10': ['LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks.Flink', 'LDR_DATA_TABLE_ENTRY*'],
            '18': ['LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks.Blink', 'LDR_DATA_TABLE_ENTRY*'],
            '20': ['LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks.Flink', 'LDR_DATA_TABLE_ENTRY*'],
            '28': ['LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks.Blink', 'LDR_DATA_TABLE_ENTRY*'],
            '30': ['LDR_DATA_TABLE_ENTRY.DllBase', 'PVOID'],
            '38': ['LDR_DATA_TABLE_ENTRY.EntryPoint', 'PVOID'],
            '40': ['LDR_DATA_TABLE_ENTRY.SizeOfImage', 'ULONG'],
            '48': ['LDR_DATA_TABLE_ENTRY.FullDllName', 'UNICODE_STRING'],
            '50': ['LDR_DATA_TABLE_ENTRY.BaseDllName', 'UNICODE_STRING'],
            '60': ['LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer', 'PCWSTR'],
            '68': ['LDR_DATA_TABLE_ENTRY.Flags', 'ULONG'],
        },
        'LIST_ENTRY* loader head': {
            '0': ['InLoadOrderModuleList.Flink', 'LDR_DATA_TABLE_ENTRY*'],
            '8': ['InLoadOrderModuleList.Blink', 'LDR_DATA_TABLE_ENTRY*'],
        },
        'LIST_ENTRY* memory-order head': {
            '0': ['InMemoryOrderModuleList.Flink', 'LDR_DATA_TABLE_ENTRY*'],
            '8': ['InMemoryOrderModuleList.Blink', 'LDR_DATA_TABLE_ENTRY*'],
        },
        'LIST_ENTRY* init-order head': {
            '0': ['InInitializationOrderModuleList.Flink', 'LDR_DATA_TABLE_ENTRY*'],
            '8': ['InInitializationOrderModuleList.Blink', 'LDR_DATA_TABLE_ENTRY*'],
        },
        'LDR_DATA_TABLE_ENTRY.InLoadOrderLinks*': {
            '0': ['LDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Flink', 'LDR_DATA_TABLE_ENTRY*'],
            '8': ['LDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Blink', 'LDR_DATA_TABLE_ENTRY*'],
        },
        'LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks*': {
            '0': ['LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks.Flink', 'LDR_DATA_TABLE_ENTRY*'],
            '8': ['LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks.Blink', 'LDR_DATA_TABLE_ENTRY*'],
        },
        'LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks*': {
            '0': ['LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks.Flink', 'LDR_DATA_TABLE_ENTRY*'],
            '8': ['LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks.Blink', 'LDR_DATA_TABLE_ENTRY*'],
        },
        'UNICODE_STRING': {
            '0': ['UNICODE_STRING.Length', 'USHORT'],
            '2': ['UNICODE_STRING.MaximumLength', 'USHORT'],
            '8': ['UNICODE_STRING.Buffer', 'PCWSTR'],
        },
        'RTL_USER_PROCESS_PARAMETERS*': {
            '60': ['RTL_USER_PROCESS_PARAMETERS.ImagePathName', 'UNICODE_STRING'],
            '70': ['RTL_USER_PROCESS_PARAMETERS.CommandLine', 'UNICODE_STRING'],
        },
    };
    return map[baseType]?.[off] || null;
}
function summarizeCallSemantics(call, args) {
    const label = normalizeImportName(stripScopedName(call?.label || '')).toLowerCase();
    const argValues = args.map(arg => String(arg).split('=').slice(1).join('=').trim()).filter(Boolean);
    if (!label || !argValues.length)
        return '';
    const printable = value => {
        if (/BaseDllName\.Buffer/.test(value))
            return 'current_module_name';
        if (/FullDllName\.Buffer/.test(value))
            return 'current_module_path';
        return value;
    };
    if (['wcsicmp', '_wcsicmp', 'wcscmp', '_wcscmp', 'strcmp', '_strcmp', 'stricmp', '_stricmp'].includes(label) && argValues.length >= 2) {
        const a = printable(argValues[0]);
        const b = printable(argValues[1]);
        return `${stripScopedName(call.label || label)}(${a}, ${b})`;
    }
    if (['lstrcmpiw', 'lstrcmpi', 'rtlcompareunicodestring'].includes(label) && argValues.length >= 2) {
        return `${stripScopedName(call.label || label)}(${argValues[0]}, ${argValues[1]})`;
    }
    return '';
}
function buildCallCommentMap(callArgumentNotes) {
    const map = new Map();
    for (const [rva, notes] of callArgumentNotes || new Map()) {
        const primary = Array.isArray(notes) ? notes[0] : '';
        if (primary)
            map.set(normalizeRva(rva), primary);
    }
    return map;
}
function annotateRecompText(text, apiCalls, callCommentMap) {
    let out = String(text || '');
    for (const call of apiCalls || []) {
        const summary = callCommentMap.get(normalizeRva(call?.rva));
        const label = stripScopedName(call?.label || '');
        if (!summary || !label)
            continue;
        const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const patterns = [
            new RegExp(`(result\\s*=\\s*${escaped}\\s*\\(\\)\\s*;)(\\s*//.*)?$`, 'm'),
            new RegExp(`(return\\s+${escaped}\\s*\\(\\)\\s*;)(\\s*//.*)?$`, 'm'),
        ];
        for (const re of patterns) {
            if (re.test(out)) {
                out = out.replace(re, (_, stmt, existing) => `${stmt}${existing || ''}  // ${summary}`);
                break;
            }
        }
    }
    return out;
}
function buildHeuristicInsnNotes(insns) {
    const regState = new Map();
    const notes = new Map();
    const setState = (reg, value) => {
        if (!reg)
            return;
        regState.set(registerFamily(reg), value);
    };
    const getState = (reg) => reg ? regState.get(registerFamily(reg)) || '' : '';
    const setNote = (rva, note) => {
        if (rva && note)
            notes.set(rva, sanitizeSemanticNote(note));
    };
    const classifyUnlinkStore = (destState, destOff, srcState, srcFallback) => {
        const destType = semanticType(destState);
        const srcType = semanticType(srcState);
        const srcExpr = semanticExpr(srcState || srcFallback);
        const off = String(destOff || '0').toUpperCase();
        if (srcExpr === '0') {
            if (destType === 'LDR_DATA_TABLE_ENTRY*' && (off === '0' || off === '8'))
                return 'clear InLoadOrderLinks';
            if (destType === 'LDR_DATA_TABLE_ENTRY*' && (off === '10' || off === '18'))
                return 'clear InMemoryOrderLinks';
            if (destType === 'LDR_DATA_TABLE_ENTRY*' && (off === '20' || off === '28'))
                return 'clear InInitializationOrderLinks';
        }
        if (destType === 'LDR_DATA_TABLE_ENTRY*' && off === '0' && srcType === 'LDR_DATA_TABLE_ENTRY*')
            return 'unlink InLoadOrderLinks: previous->Flink = next';
        if (destType === 'LDR_DATA_TABLE_ENTRY*' && off === '8' && srcType === 'LDR_DATA_TABLE_ENTRY*')
            return 'unlink InLoadOrderLinks: next->Blink = previous';
        if (destType === 'LDR_DATA_TABLE_ENTRY*' && off === '10' && srcType === 'LDR_DATA_TABLE_ENTRY*')
            return 'unlink InMemoryOrderLinks: previous->Flink = next';
        if (destType === 'LDR_DATA_TABLE_ENTRY*' && off === '18' && srcType === 'LDR_DATA_TABLE_ENTRY*')
            return 'unlink InMemoryOrderLinks: next->Blink = previous';
        if (destType === 'LDR_DATA_TABLE_ENTRY*' && off === '20' && srcType === 'LDR_DATA_TABLE_ENTRY*')
            return 'unlink InInitializationOrderLinks: previous->Flink = next';
        if (destType === 'LDR_DATA_TABLE_ENTRY*' && off === '28' && srcType === 'LDR_DATA_TABLE_ENTRY*')
            return 'unlink InInitializationOrderLinks: next->Blink = previous';
        return '';
    };
    for (const insn of insns || []) {
        const text = String(insn?.text || '').trim();
        const lower = text.toLowerCase();
        const rvaKey = normalizeRva(insn?.rva);
        let note = '';
        if (/^mov\s+\w+,\s*gs:\[60h\]$/i.test(text) || /^mov\s+\w+,\s*fs:\[30h\]$/i.test(text)) {
            const assignedReg = text.match(/^mov\s+([A-Za-z0-9]+),/i)?.[1] || '';
            setState(assignedReg, semanticValue('PEB*', 'process environment block'));
            note = 'load PEB';
        }
        else if (/^mov\s+\w+,\s*gs:\[30h\]$/i.test(text) || /^mov\s+\w+,\s*fs:\[18h\]$/i.test(text)) {
            const assignedReg = text.match(/^mov\s+([A-Za-z0-9]+),/i)?.[1] || '';
            setState(assignedReg, semanticValue('TEB*', 'thread environment block'));
            note = 'load TEB';
        }
        else if (/^mov\s+\w+,\s*\[(?:[A-Za-z0-9_.$]+)\]$/i.test(text) && /\.rdata/i.test(String(insn?.comment || ''))) {
            const assignedReg = text.match(/^mov\s+([A-Za-z0-9]+),/i)?.[1] || '';
            const literal = String(insn.comment || '').trim();
            setState(assignedReg, semanticValue('PCSTR', literal));
            note = `load string ${literal}`;
        }
        else if (/^lea\s+\w+,\s*\[(?:[A-Za-z0-9_.]+\+)?0x?[0-9A-Fa-f]+h?\]$/i.test(text) && /L"/.test(String(insn?.comment || ''))) {
            const assignedReg = text.match(/^lea\s+([A-Za-z0-9]+),/i)?.[1] || '';
            const stringValue = String(insn.comment || '').replace(/^.*?(L".*")$/, '$1');
            setState(assignedReg, semanticValue('PCWSTR', stringValue));
            note = `load string ${stringValue}`;
        }
        else {
            const movReg = text.match(/^mov\s+([A-Za-z0-9]+)\s*,\s*([A-Za-z0-9]+)$/i);
            if (movReg) {
                const srcState = getState(movReg[2]);
                if (srcState) {
                    setState(movReg[1], srcState);
                    note = semanticExpr(srcState);
                }
            }
            const movField = text.match(/^(mov|lea)\s+([A-Za-z0-9]+)\s*,\s*\[([A-Za-z0-9]+)([+-]([0-9A-Fa-f]+)h?)?\]$/i);
            if (movField && !note) {
                const assignedReg = movField[2];
                const baseReg = movField[3];
                const off = (movField[5] || '0').toUpperCase();
                const baseState = getState(baseReg);
                const baseType = semanticType(baseState);
                const field = mapKnownField(baseType, off);
                if (field) {
                    const [expr, nextType] = field;
                    setState(assignedReg, semanticValue(nextType, expr));
                    note = expr;
                }
                else if (/LIST_ENTRY/.test(baseType) && off === '0') {
                    setState(assignedReg, semanticValue(baseType, `${semanticExpr(baseState)}->Flink`));
                    note = `${semanticExpr(baseState)}->Flink`;
                }
                else if (/LIST_ENTRY/.test(baseType) && off === '8') {
                    setState(assignedReg, semanticValue(baseType, `${semanticExpr(baseState)}->Blink`));
                    note = `${semanticExpr(baseState)}->Blink`;
                }
                else if (baseState) {
                    setState(assignedReg, semanticValue('', `${semanticExpr(baseState)}+0x${off}`));
                    note = `${semanticExpr(baseState)}+0x${off}`;
                }
            }
            const addList = text.match(/^add\s+([A-Za-z0-9]+),\s*10h$/i);
            if (addList && !note) {
                const baseState = getState(addList[1]);
                if (semanticType(baseState) === 'PEB_LDR_DATA*') {
                    setState(addList[1], semanticValue('LIST_ENTRY* loader head', 'PEB_LDR_DATA.InLoadOrderModuleList'));
                    note = 'PEB_LDR_DATA.InLoadOrderModuleList';
                }
                else if (baseState) {
                    setState(addList[1], semanticValue(semanticType(baseState), `${semanticExpr(baseState)}+0x10`));
                    note = `${semanticExpr(baseState)}+0x10`;
                }
            }
            const addField = text.match(/^add\s+([A-Za-z0-9]+),\s*([0-9A-Fa-f]+)h$/i);
            if (addField && !note) {
                const baseState = getState(addField[1]);
                if (baseState) {
                    const off = addField[2].toUpperCase();
                    const field = mapKnownField(semanticType(baseState), off);
                    if (field) {
                        const [expr, nextType] = field;
                        setState(addField[1], semanticValue(nextType, expr));
                        note = expr;
                    }
                    else {
                        setState(addField[1], semanticValue(semanticType(baseState), `${semanticExpr(baseState)}+0x${off}`));
                        note = `${semanticExpr(baseState)}+0x${off}`;
                    }
                }
            }
            const movList = text.match(/^mov\s+([A-Za-z0-9]+)\s*,\s*\[([A-Za-z0-9]+)\]$/i);
            if (movList && !note) {
                const baseState = getState(movList[2]);
                const baseType = semanticType(baseState);
                if (baseType === 'LIST_ENTRY* loader head') {
                    setState(movList[1], semanticValue('LDR_DATA_TABLE_ENTRY*', 'current module entry'));
                    note = 'load current module entry from InLoadOrderModuleList';
                }
                else if (baseType === 'LIST_ENTRY* memory-order head') {
                    setState(movList[1], semanticValue('LDR_DATA_TABLE_ENTRY*', 'current module entry'));
                    note = 'load current module entry from InMemoryOrderModuleList';
                }
                else if (baseType === 'LIST_ENTRY* init-order head') {
                    setState(movList[1], semanticValue('LDR_DATA_TABLE_ENTRY*', 'current module entry'));
                    note = 'load current module entry from InInitializationOrderModuleList';
                }
                else if (baseType === 'LDR_DATA_TABLE_ENTRY*') {
                    setState(movList[1], semanticValue('LDR_DATA_TABLE_ENTRY*', 'next module entry'));
                    note = 'advance to next module entry';
                }
                else if (/LIST_ENTRY/.test(baseType)) {
                    const expr = semanticExpr(baseState);
                    const nextType = baseType;
                    setState(movList[1], semanticValue(nextType, `${expr}->Flink`));
                    note = `${expr}->Flink`;
                }
            }
            const subContainer = text.match(/^sub\s+([A-Za-z0-9]+)\s*,\s*([0-9A-Fa-f]+)h$/i);
            if (subContainer && !note) {
                const baseState = getState(subContainer[1]);
                const baseType = semanticType(baseState);
                const off = subContainer[2].toUpperCase();
                if (baseType === 'LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks*' && off === '10') {
                    setState(subContainer[1], semanticValue('LDR_DATA_TABLE_ENTRY*', 'current module entry'));
                    note = 'recover module entry from InMemoryOrderLinks';
                }
                else if (baseType === 'LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks*' && off === '20') {
                    setState(subContainer[1], semanticValue('LDR_DATA_TABLE_ENTRY*', 'current module entry'));
                    note = 'recover module entry from InInitializationOrderLinks';
                }
                else if (/LDR_DATA_TABLE_ENTRY\./.test(baseType) || /LDR_DATA_TABLE_ENTRY\./.test(semanticExpr(baseState))) {
                    setState(subContainer[1], semanticValue('LDR_DATA_TABLE_ENTRY*', 'container record'));
                    note = 'recover LDR_DATA_TABLE_ENTRY from list link';
                }
            }
            const movStore = text.match(/^mov\s+\[([A-Za-z0-9]+)(?:\+([0-9A-Fa-f]+)h)?\]\s*,\s*([A-Za-z0-9]+)$/i);
            if (movStore && !note) {
                const destState = getState(movStore[1]);
                const srcState = getState(movStore[3]);
                note = classifyUnlinkStore(destState, movStore[2] || '0', srcState, movStore[3]);
            }
            const cmpList = text.match(/^cmp\s+([A-Za-z0-9]+)\s*,\s*([A-Za-z0-9]+)$/i);
            if (cmpList) {
                const left = getState(cmpList[1]);
                const right = getState(cmpList[2]);
                if ((semanticType(left) === 'LDR_DATA_TABLE_ENTRY*' && /loader head/.test(semanticType(right)))
                    || (semanticType(right) === 'LDR_DATA_TABLE_ENTRY*' && /loader head/.test(semanticType(left)))) {
                    note = 'check whether traversal reached the loader list head';
                }
                else if (/LIST_ENTRY|LDR_DATA_TABLE_ENTRY\./.test(`${left} ${right}`)) {
                    note = 'compare list links';
                }
            }
            const testList = text.match(/^test\s+([A-Za-z0-9]+)\s*,\s*([A-Za-z0-9]+)$/i);
            if (testList && semanticExpr(getState(testList[1])) === '0' && semanticExpr(getState(testList[2])) === '0') {
                note = 'null-check';
            }
        }
        setNote(rvaKey, note);
        if (/^(xor|sub)\s+([A-Za-z0-9]+)\s*,\s*([A-Za-z0-9]+)$/i.test(lower)) {
            const zero = text.match(/^(xor|sub)\s+([A-Za-z0-9]+)\s*,\s*([A-Za-z0-9]+)$/i);
            if (zero && registerFamily(zero[2]) === registerFamily(zero[3])) {
                setState(zero[2], semanticValue('', '0'));
            }
        }
    }
    return notes;
}
function fnLink(name, opts = {}) {
    const cls = prefixClass(name);
    const el = document.createElement('span');
    el.className = 'fn-link' + (cls ? ` pfx-${cls}` : '');
    el.dataset.func = name;
    if (opts.dll)
        el.dataset.dll = opts.dll;
    el.textContent = name;
    el.addEventListener('mouseenter', e => startTooltip(name, e));
    el.addEventListener('mousemove', e => moveTooltip(e));
    el.addEventListener('mouseleave', () => hideTooltip());
    el.addEventListener('contextmenu', e => showCtxMenu(e, name, opts.dll || null));
    if (opts.rva) {
        el.addEventListener('click', () => navigateRva(opts.rva, name));
        el.addEventListener('dblclick', () => navigateRva(opts.rva, name));
    }
    else {
        el.addEventListener('click', () => navigate(name, opts.dll || null));
        el.addEventListener('dblclick', () => navigate(name, opts.dll || null));
    }
    return el;
}
document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t === btn));
        document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === `panel-${btn.dataset.tab}`));
        st.activeTopTab = btn.dataset.tab;
        persistUiState();
        if (btn.dataset.tab === 'flow') {
            ensureReconstructCfg();
        }
        if (btn.dataset.tab === 'scan') {
            ensureScanPanel();
        }
        if (btn.dataset.tab === 'types' && st._pendingTypeNav) {
            const pending = st._pendingTypeNav;
            st._pendingTypeNav = null;
            const list = document.querySelector('#panel-types .types-list');
            if (list) {
                for (const item of Array.from(list.querySelectorAll('.types-item'))) {
                    const name = (item.querySelector('.types-item-name')?.textContent || '').toLowerCase();
                    if (name === pending || name === canonicalTypeName(pending)) {
                        item.click();
                        item.scrollIntoView({ block: 'nearest' });
                        break;
                    }
                }
            }
        }
    });
});
$('export-btn')?.addEventListener('click', () => exportCurrentView());
if (st.activeTopTab && st.activeTopTab !== 'dump') {
    requestAnimationFrame(() => activateTab(st.activeTopTab));
}
function activateTab(id) {
    hideTooltip();
    const btn = document.querySelector(`.tab[data-tab="${id}"]`);
    if (btn)
        btn.dispatchEvent(new Event('click'));
}
function currentNavEntry() {
    return st.navPos >= 0 ? st.navHistory[st.navPos] : null;
}
function canNavBack() {
    const entry = currentNavEntry();
    return st.navPos > 0 || !!(entry?.originTab && entry.originTab !== 'dump');
}
function activateDumpSubTab(id) {
    const panel = $('panel-dump');
    if (!panel)
        return;
    const target = panel.querySelector(`.stab[data-stab="${id}"]:not(.hidden)`) || panel.querySelector('.stab:not(.hidden)');
    if (!target)
        return;
    panel.querySelectorAll('.stab').forEach(b => b.classList.toggle('active', b === target));
    const targetId = `stab-${target.dataset.stab}`;
    panel.querySelectorAll('.stab-panel').forEach(p => p.classList.toggle('active', p.id === targetId));
    st.activeDumpSubTab = target.dataset.stab || 'disasm';
    persistUiState();
}
function readDumpSubTabScroll(id) {
    const panel = $(`stab-${id}`);
    if (!(panel instanceof HTMLElement))
        return 0;
    if (id === 'disasm') {
        const insnPane = panel.querySelector('.asm-pane-insn');
        return insnPane instanceof HTMLElement ? insnPane.scrollTop : panel.scrollTop;
    }
    return panel.scrollTop;
}
function writeDumpSubTabScroll(id, top) {
    const panel = $(`stab-${id}`);
    if (!(panel instanceof HTMLElement))
        return;
    const next = Math.max(0, Number(top) || 0);
    if (id === 'disasm') {
        const insnPane = panel.querySelector('.asm-pane-insn');
        const metaPane = panel.querySelector('.asm-pane-meta');
        if (insnPane instanceof HTMLElement)
            insnPane.scrollTop = next;
        if (metaPane instanceof HTMLElement)
            metaPane.scrollTop = next;
        return;
    }
    panel.scrollTop = next;
}
function saveCurrentDumpViewState() {
    const entry = currentNavEntry();
    if (!entry)
        return;
    const scrollTopByTab = {};
    DUMP_SUBTABS.forEach(id => {
        scrollTopByTab[id] = readDumpSubTabScroll(id);
    });
    entry.viewState = {
        subTab: st.activeDumpSubTab || 'disasm',
        scrollTopByTab,
    };
}
function restoreDumpViewState(entry) {
    const saved = entry?.viewState;
    activateDumpSubTab(saved?.subTab || st.activeDumpSubTab || 'disasm');
    if (!saved?.scrollTopByTab)
        return;
    requestAnimationFrame(() => {
        DUMP_SUBTABS.forEach(id => {
            writeDumpSubTabScroll(id, saved.scrollTopByTab[id]);
        });
    });
}
function navigate(funcName, dll = null) {
    const target = resolveNavigationTarget(funcName, dll);
    const useCurrentPath = sameImageModule(target.dll, st.currentDumpDll) && !!st.currentDumpPath;
    const displayDll = useCurrentPath ? (st.currentDumpDll || target.dll) : (target.dll || st.currentDumpDll || null);
    const entry = {
        label: displayDll ? `${String(displayDll).replace(/\.(dll|exe|sys)$/i, '')}!${target.func}` : target.func,
        fn: target.func,
        dll: displayDll,
        dllPath: useCurrentPath ? st.currentDumpPath : (!target.dll && st.currentDumpPath ? st.currentDumpPath : null),
        rva: null,
        funcsDepth: st.apiDepth,
        originTab: st.activeTopTab !== 'dump' ? st.activeTopTab : (st.navHistory[st.navPos]?.originTab || null),
    };
    _navPush(entry);
    _requestDump(entry);
}
function navigateRva(rva, label) {
    const entry = {
        label: label || `@${rva}`,
        fn: null,
        dll: st.currentDumpDll || null,
        dllPath: st.currentDumpPath || null,
        rva: normalizeRva(rva),
        funcsDepth: st.apiDepth,
        originTab: st.activeTopTab !== 'dump' ? st.activeTopTab : (st.navHistory[st.navPos]?.originTab || null),
    };
    _navPush(entry);
    _requestDump(entry);
}
function navigateRootRva(rva, label) {
    const entry = {
        label: label || `@${rva}`,
        fn: null,
        dll: st.rootDll || null,
        dllPath: st.rootDllPath || null,
        rva: normalizeRva(rva),
        funcsDepth: st.apiDepth,
        originTab: st.activeTopTab !== 'dump' ? st.activeTopTab : (st.navHistory[st.navPos]?.originTab || null),
    };
    _navPush(entry);
    _requestDump(entry);
}
function navigateInRoot(funcName) {
    const entry = {
        label: funcName,
        fn: funcName,
        dll: st.rootDll || null,
        dllPath: st.rootDllPath || null,
        rva: null,
        funcsDepth: st.apiDepth,
        originTab: st.activeTopTab !== 'dump' ? st.activeTopTab : (st.navHistory[st.navPos]?.originTab || null),
    };
    _navPush(entry);
    _requestDump(entry);
}
function _navPush(entry) {
    saveCurrentDumpViewState();
    if (st.navPos < st.navHistory.length - 1)
        st.navHistory = st.navHistory.slice(0, st.navPos + 1);
    st.navHistory.push(entry);
    st.navPos = st.navHistory.length - 1;
    $('tab-dump').style.display = '';
    activateTab('dump');
}
function navBack() {
    if (st.navPos <= 0) {
        const originTab = currentNavEntry()?.originTab;
        if (originTab && originTab !== 'dump')
            activateTab(originTab);
        return;
    }
    saveCurrentDumpViewState();
    st.navPos--;
    _replayNav(st.navHistory[st.navPos]);
}
function navFwd() {
    if (st.navPos >= st.navHistory.length - 1)
        return;
    saveCurrentDumpViewState();
    st.navPos++;
    _replayNav(st.navHistory[st.navPos]);
}
function _replayNav(entry) {
    _requestDump(entry);
}
function _requestDump(entry, prefetch = false) {
    const cacheKey = dumpCacheKey(entry);
    if (!prefetch && st.dumpCache.has(cacheKey)) {
        const cached = st.dumpCache.get(cacheKey);
        if (cached?.error) {
            st.dumpCache.delete(cacheKey);
        }
        else {
            st.activeDumpRequestId = null;
            renderDump({ ...cached, prefetch: false });
            return;
        }
    }
    if (!prefetch)
        _showDumpLoading(entry.label);
    const request = {
        requestId: `${Date.now()}:${Math.random().toString(16).slice(2)}`,
        cacheKey,
        prefetch,
    };
    if (!prefetch)
        st.activeDumpRequestId = request.requestId;
    if (entry.rva) {
        vscode.postMessage({
            command: 'dump_at_rva',
            dll: entry.dll || st.currentDumpDll || null,
            dllPath: entry.dllPath || st.currentDumpPath || null,
            rva: normalizeRva(entry.rva),
            label: entry.label,
            funcsDepth: Math.max(1, Math.min(5, Number(entry.funcsDepth || st.apiDepth || 1) || 1)),
            hostile: st.hostile,
            ...request,
        });
    }
    else {
        vscode.postMessage({
            command: 'dump',
            func: entry.fn,
            dll: entry.dll,
            dllPath: entry.dllPath || null,
            sourceLabel: entry.label,
            funcsDepth: Math.max(1, Math.min(5, Number(entry.funcsDepth || st.apiDepth || 1) || 1)),
            hostile: st.hostile,
            ...request,
        });
    }
}
function _showDumpLoading(label) {
    hideTooltip();
    initDumpShell();
    document.querySelectorAll('.stab-panel').forEach(p => { p.innerHTML = ''; });
    $('stab-disasm').innerHTML = '<p class="loading">Disassembling…</p>';
    $('dump-header').innerHTML = `<span class="dump-fn">${esc(label)}</span>`;
    _updateNavUI();
}
function _updateNavUI() {
    const back = $('dump-back'), fwd = $('dump-fwd');
    if (back)
        back.disabled = !canNavBack();
    if (fwd)
        fwd.disabled = st.navPos >= st.navHistory.length - 1;
    const bc = $('dump-breadcrumb');
    if (!bc)
        return;
    bc.innerHTML = st.navHistory.map((e, i) => {
        const cls = i === st.navPos ? 'bc-item current' : 'bc-item';
        const sep = i > 0 ? '<span class="bc-sep">›</span>' : '';
        return `${sep}<span class="${cls}">${esc(e.label)}</span>`;
    }).join('');
}
let dumpShellBuilt = false;
function initDumpShell() {
    if (dumpShellBuilt)
        return;
    dumpShellBuilt = true;
    const panel = $('panel-dump');
    panel.innerHTML = `
            <div id="dump-nav">
                <button id="dump-back" class="nav-arrow nav-arrow-back" aria-label="Back" title="Back" disabled></button>
                <div id="dump-breadcrumb"></div>
                <button id="dump-fwd" class="nav-arrow nav-arrow-fwd" aria-label="Forward" title="Forward" disabled></button>
            </div>
            <div id="dump-header"></div>
            <div id="dump-stabs">
                <button class="stab active" data-stab="disasm">Disasm</button>
                <button class="stab hidden" data-stab="calls">API Calls</button>
                <button class="stab hidden" data-stab="xrefs">Xrefs</button>
                <button class="stab hidden" data-stab="strings">Strings</button>
                <button class="stab hidden" data-stab="cfg">CFG</button>
                <button class="stab hidden" data-stab="recomp">Recomp</button>
                <button class="stab hidden" data-stab="hex">Hex</button>
            </div>
            <div id="dump-content">
                <div id="stab-disasm"  class="stab-panel active"></div>
                <div id="stab-calls"   class="stab-panel"></div>
                <div id="stab-xrefs"   class="stab-panel"></div>
                <div id="stab-strings" class="stab-panel"></div>
                <div id="stab-cfg"     class="stab-panel" style="padding:0"></div>
                <div id="stab-recomp"  class="stab-panel"></div>
                <div id="stab-hex"     class="stab-panel"></div>
            </div>`;
    $('dump-back').addEventListener('click', navBack);
    $('dump-fwd').addEventListener('click', navFwd);
    panel.querySelectorAll('.stab').forEach(btn => {
        btn.addEventListener('click', () => {
            activateDumpSubTab(btn.dataset.stab || 'disasm');
        });
    });
}
function setCurrentDepth(depth) {
    st.apiDepth = Math.max(1, Math.min(5, Number(depth) || 1));
    const entry = currentNavEntry();
    if (entry)
        entry.funcsDepth = st.apiDepth;
}
function requestSymbolReload() {
    const serverInp = $('pdb-server-input');
    st.symServer = serverInp ? serverInp.value.trim() : st.symServer;
    vscode.postMessage({
        command: 'reload_syms',
        symPaths: st.pdbPaths,
        pdbFile: st.pdbFile,
        symServer: st.symServer,
    });
}
function parseXrefEntry(text) {
    const raw = String(text || '').trim();
    if (!raw)
        return null;
    const site = raw.match(/\[site\s+(0x[0-9A-Fa-f]+)\]/);
    const kind = raw.match(/^(CALL|JMP|STARTUP(?:-TLS)?)\b/);
    const owner = raw.match(/^(?:CALL|JMP|STARTUP(?:-TLS)?)\s+(.+?)\s+\[site\b/);
    const target = raw.match(/->\s+(.+?)\s+\[(?:target|IAT)\s+/);
    return {
        raw,
        siteRva: site ? normalizeRva(site[1]) : null,
        kind: kind ? kind[1] : '',
        owner: owner ? owner[1] : '',
        target: target ? target[1] : '',
    };
}
function parseApiCallTree(treeText) {
    const lines = String(treeText || '').split(/\r?\n/);
    const rows = [];
    let pending = null;
    for (const rawLine of lines) {
        const line = rawLine.trimEnd();
        const callMatch = line.match(/^(\s*(?:(?:│\s{3})|(?:\s{4}))*)([├└]──)\s+0x([0-9A-Fa-f]+)\s+(\w+)\s+(.+?)\s+(\[[^\]]+\](?:\s+\[[^\]]+\])*)\s*$/);
        if (callMatch) {
            const depth = (callMatch[1].match(/(?:│\s{3})|(?:\s{4})/g) || []).length;
            const target = callMatch[5].trim();
            const tag = callMatch[6].trim();
            const dllSplit = target.match(/^([A-Za-z0-9_.-]+)!(.+)$/);
            pending = {
                depth,
                rva: normalizeRva(`0x${callMatch[3]}`),
                kind: callMatch[4],
                label: dllSplit ? dllSplit[2] : target,
                dll: dllSplit ? dllSplit[1] : '',
                indirect: tag.replace(/^\[|\]$/g, '').replace(/\]\s+\[/g, ' · '),
                notes: [],
            };
            rows.push(pending);
            continue;
        }
        const detailMatch = line.match(/^\s*(?:(?:│\s{3})|(?:\s{4}))+(when|kernel):\s+(.+?)\s*$/);
        if (detailMatch && pending)
            pending.notes.push(`${detailMatch[1]} ${detailMatch[2]}`);
    }
    return rows;
}
function showCtxMenu(e, funcName, dll) {
    e.preventDefault();
    dismissCtxMenu();
    const navTarget = resolveNavigationTarget(funcName, dll);
    const menu = document.createElement('div');
    menu.id = 'ctx-menu';
    st.ctxMenu = menu;
    const add = (label, action) => {
        const item = document.createElement('div');
        item.className = 'ctx-item';
        item.textContent = label;
        item.addEventListener('click', () => { dismissCtxMenu(); action(); });
        menu.appendChild(item);
    };
    add(`Dump "${navTarget.func}"`, () => navigate(navTarget.func, null));
    const srcDll = navTarget.dll;
    if (srcDll)
        add(`View System API  (${srcDll.replace(/\.(dll|exe|sys)$/i, '')})`, () => navigate(funcName, srcDll));
    const sep = document.createElement('div');
    sep.className = 'ctx-sep';
    menu.appendChild(sep);
    add('Copy name', () => copyText(navTarget.func));
    if (srcDll)
        add(`Copy DLL!name`, () => copyText(`${srcDll}!${navTarget.func}`));
    document.body.appendChild(menu);
    const vw = window.innerWidth, vh = window.innerHeight;
    let x = e.clientX, y = e.clientY;
    if (x + 200 > vw)
        x = vw - 204;
    const h = menu.offsetHeight || 100;
    if (y + h > vh)
        y = vh - h - 4;
    menu.style.left = `${Math.max(0, x)}px`;
    menu.style.top = `${Math.max(0, y)}px`;
}
function showAddrCtxMenu(e, rawValue, shortValue) {
    e.preventDefault();
    dismissCtxMenu();
    const menu = document.createElement('div');
    menu.id = 'ctx-menu';
    st.ctxMenu = menu;
    const add = (label, action) => {
        const item = document.createElement('div');
        item.className = 'ctx-item';
        item.textContent = label;
        item.addEventListener('click', () => { dismissCtxMenu(); action(); });
        menu.appendChild(item);
    };
    add('Copy raw address', () => copyText(rawValue));
    if (shortValue && shortValue !== rawValue)
        add('Copy shortened address', () => copyText(shortValue));
    document.body.appendChild(menu);
    const vw = window.innerWidth, vh = window.innerHeight;
    let x = e.clientX, y = e.clientY;
    if (x + 220 > vw)
        x = vw - 224;
    const h = menu.offsetHeight || 80;
    if (y + h > vh)
        y = vh - h - 4;
    menu.style.left = `${Math.max(0, x)}px`;
    menu.style.top = `${Math.max(0, y)}px`;
}
function wireShortAddressSpans(root) {
    root.querySelectorAll('.asm-addr-short').forEach(addrEl => {
        const raw = addrEl.getAttribute('data-raw') || '';
        const short = addrEl.getAttribute('data-short') || raw;
        addrEl.addEventListener('contextmenu', evt => showAddrCtxMenu(evt, raw, short));
        addrEl.setAttribute('title', `${short}  |  raw ${raw}`);
    });
}
function shortenAddressMarkup(text, sections = [], imageBase = '') {
    let html = esc(text || '');
    html = html.replace(/\b(0[xX][0-9A-Fa-f]+|[0-9A-Fa-f]+h)\b/g, (rawHex) => {
        const shortened = shortenAddressForImage(rawHex, sections, imageBase);
        if (!shortened)
            return rawHex;
        return `<span class="asm-addr-short" data-raw="${esc(shortened.raw)}" data-short="${esc(shortened.short)}">${esc(shortened.short)}</span>`;
    });
    return html;
}
function dismissCtxMenu() {
    if (st.ctxMenu) {
        st.ctxMenu.remove();
        st.ctxMenu = null;
    }
}
function copyText(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
}
document.addEventListener('click', dismissCtxMenu);
document.addEventListener('contextmenu', e => {
    if (!e.target.closest('#ctx-menu'))
        dismissCtxMenu();
});
document.addEventListener('scroll', () => hideTooltip(), true);
window.addEventListener('blur', () => hideTooltip());
window.addEventListener('resize', () => hideTooltip());
document.addEventListener('visibilitychange', () => {
    if (document.hidden)
        hideTooltip();
});
function startTooltip(name, e) {
    if (st.tipTimer)
        clearTimeout(st.tipTimer);
    st._lastHovered = name;
    st.tipTimer = setTimeout(() => {
        const cached = st.explainCache.get(name);
        if (cached === null)
            return;
        if (cached !== undefined) {
            renderTooltip(name, cached, e);
            return;
        }
        if (!st.explainPending.has(name)) {
            st.explainPending.add(name);
            vscode.postMessage({ command: 'explain', name });
        }
    }, 380);
}
function moveTooltip(e) {
    if (st.tooltip)
        positionTooltip(e);
}
function hideTooltip() {
    if (st.tipTimer) {
        clearTimeout(st.tipTimer);
        st.tipTimer = null;
    }
    if (st.tooltip) {
        st.tooltip.remove();
        st.tooltip = null;
    }
    st._lastHovered = null;
}
document.addEventListener('mousemove', e => {
    if (!st.tooltip && !st.tipTimer)
        return;
    const target = e.target;
    if (target instanceof Element && target.closest('.fn-link'))
        return;
    hideTooltip();
});
function renderTooltip(name, data, e) {
    if (st.tooltip)
        st.tooltip.remove();
    const tip = document.createElement('div');
    tip.id = 'tooltip';
    st.tooltip = tip;
    const cls = prefixClass(name);
    tip.innerHTML = `<div class="tip-fn${cls ? ` pfx-${cls}` : ''}">${esc(name)}</div>`;
    if (data.prefix) {
        const p = data.prefix;
        tip.innerHTML += `<div class="tip-pfx">${esc(p.key)} · ${esc(PREFIX_LABELS[cls] || p.title)} · ${esc(p.layer)}</div>`;
    }
    tip.innerHTML += `<div class="tip-sum">${esc(data.summary)}</div>`;
    if (data.chunks?.length) {
        for (const c of data.chunks)
            tip.innerHTML += `<div class="tip-chunk"><span class="tip-chunk-tok">${esc(c.token)}</span><span>${esc(c.meaning)}</span></div>`;
    }
    if (data.notes?.length)
        tip.innerHTML += `<div class="tip-note">${esc(data.notes[0])}</div>`;
    document.body.appendChild(tip);
    positionTooltip(e || { clientX: window.innerWidth / 2, clientY: window.innerHeight / 2 });
}
function positionTooltip(e) {
    const tip = st.tooltip;
    if (!tip)
        return;
    const pad = 10, vw = window.innerWidth, vh = window.innerHeight;
    const tw = tip.offsetWidth || 300, th = tip.offsetHeight || 80;
    let x = e.clientX + 14, y = e.clientY + 14;
    if (x + tw > vw - pad)
        x = e.clientX - tw - 4;
    if (y + th > vh - pad)
        y = e.clientY - th - 4;
    tip.style.left = `${Math.max(pad, x)}px`;
    tip.style.top = `${Math.max(pad, y)}px`;
}
(function initPdbPanel() {
    const btn = $('pdb-btn');
    if (!btn)
        return;
    const panel = document.createElement('div');
    panel.id = 'pdb-panel';
    panel.innerHTML = `
            <div class="pdb-panel-header">
                <span>Symbol Settings</span>
                <button class="pdb-panel-close">&times;</button>
            </div>
            <div class="pdb-panel-body">
                <div class="pdb-section-title">Symbol Search Paths</div>
                <div id="pdb-paths-list"></div>
                <div class="pdb-input-row">
                    <input id="pdb-path-input" type="text" placeholder="C:\\Symbols">
                    <button class="btn-sm" id="pdb-add-path">Add</button>
                    <button class="btn-sm" id="pdb-browse-folder">Browse</button>
                </div>

                <div class="pdb-section-title">Symbol Server</div>
                <div class="pdb-input-row">
                    <input id="pdb-server-input" type="text"
                        placeholder="http://msdl.microsoft.com/download/symbols"
                        value="">
                </div>

                <div class="pdb-section-title">PDB File</div>
                <div class="pdb-file-field">
                    <span id="pdb-file-label">None selected</span>
                    <button class="btn-sm" id="pdb-browse-file">Browse&hellip;</button>
                    <button class="btn-sm danger" id="pdb-clear-file">Clear</button>
                </div>

                <button class="pdb-reload-btn" id="pdb-reload">&#8635; Reload Symbols</button>
            </div>`;
    document.body.appendChild(panel);
    panel.querySelector('.pdb-panel-close').addEventListener('click', () => panel.classList.remove('open'));
    btn.addEventListener('click', () => panel.classList.toggle('open'));
    _renderPathsList();
    $('pdb-add-path').addEventListener('click', () => {
        const inp = ($('pdb-path-input'));
        const val = inp.value.trim();
        if (val && !st.pdbPaths.includes(val)) {
            st.pdbPaths.push(val);
            _renderPathsList();
            inp.value = '';
        }
    });
    $('pdb-browse-folder').addEventListener('click', () => vscode.postMessage({ command: 'pdb_browse_folder' }));
    $('pdb-browse-file').addEventListener('click', () => vscode.postMessage({ command: 'pdb_browse_file' }));
    $('pdb-clear-file').addEventListener('click', () => {
        st.pdbFile = '';
        const lbl = $('pdb-file-label');
        if (lbl)
            lbl.textContent = 'None selected';
    });
    $('pdb-reload').addEventListener('click', () => {
        requestSymbolReload();
        $('panel-symbols').innerHTML = '<p class="loading">Loading symbols…</p>';
        panel.classList.remove('open');
        activateTab('symbols');
    });
})();
function _renderPathsList() {
    const list = $('pdb-paths-list');
    if (!list)
        return;
    list.innerHTML = '';
    if (!st.pdbPaths.length) {
        list.innerHTML = '<div class="no-data" style="margin-bottom:6px">No paths configured.</div>';
        return;
    }
    st.pdbPaths.forEach((p, i) => {
        const row = document.createElement('div');
        row.className = 'pdb-path-row';
        row.innerHTML = `<span title="${esc(p)}">${esc(p)}</span>`;
        const del = document.createElement('button');
        del.className = 'btn-sm danger';
        del.textContent = '✕';
        del.title = 'Remove';
        del.addEventListener('click', () => { st.pdbPaths.splice(i, 1); _renderPathsList(); });
        row.appendChild(del);
        list.appendChild(row);
    });
}
window.addEventListener('message', e => {
    const msg = e.data;
    switch (msg.type) {
        case 'peinfo':
            renderPeInfo(msg);
            break;
        case 'eat':
            renderEat(msg);
            break;
        case 'iat':
            renderIat(msg);
            break;
        case 'syms':
            renderSyms(msg);
            break;
        case 'types':
            renderTypes(msg);
            break;
        case 'intelli':
            renderTriage(msg);
            break;
        case 'reconstruct_cfg_result':
            renderReconstructCfg(msg);
            break;
        case 'scan_result':
            renderScan(msg);
            break;
        case 'dev_log_history':
            st.devLogs = Array.isArray(msg.entries) ? msg.entries.slice() : [];
            renderDevLogs();
            break;
        case 'dev_log_append':
            if (msg.entry) {
                st.devLogs.push(msg.entry);
                if (st.devLogs.length > 300)
                    st.devLogs.splice(0, st.devLogs.length - 300);
                renderDevLogs();
            }
            break;
        case 'dump_result':
            renderDump(msg);
            break;
        case 'explain_result':
            _handleExplain(msg);
            break;
        case 'file_picked':
            _handleFilePicked(msg);
            break;
        case 'refresh_requested':
            refreshAnalysisPanels();
            break;
        case 'external_navigate':
            if (msg.loadSymbols) {
                $('panel-symbols').innerHTML = '<p class="loading">Loading symbols…</p>';
                requestSymbolReload();
            }
            if (msg.rva)
                navigateRva(msg.rva, msg.sourceLabel || msg.func || msg.rva);
            else if (msg.func)
                navigate(msg.func, msg.dll || null);
            break;
    }
});
function refreshAnalysisPanels() {
    ['overview', 'entry', 'triage', 'sections', 'exports', 'imports', 'symbols', 'types'].forEach(id => {
        const panel = $(`panel-${id}`);
        if (panel)
            panel.innerHTML = '<p class="loading">Analyzing…</p>';
    });
    st.currentPeInfo = null;
    st.typesByName = new Map();
    st.iatIndex.clear();
    st.dumpCache.clear();
    st.reconstructRequested = false;
    st.scanRequested = false;
    $('panel-flow').innerHTML = '<p class="loading">Run reconstruct-cfg to build startup flow.</p>';
    $('panel-scan').innerHTML = '<p class="loading">Run scan to discover fuzz candidates.</p>';
    vscode.postMessage({ command: 'refresh' });
}
function _handleExplain(msg) {
    st.explainPending.delete(msg.name);
    st.explainCache.set(msg.name, msg.data || null);
    if (st._lastHovered === msg.name && msg.data)
        renderTooltip(msg.name, msg.data, null);
}
function _handleFilePicked(msg) {
    if (!msg.path)
        return;
    if (msg.kind === 'sym_path') {
        if (!st.pdbPaths.includes(msg.path)) {
            st.pdbPaths.push(msg.path);
            _renderPathsList();
        }
        const inp = $('pdb-path-input');
        if (inp)
            inp.value = msg.path;
    }
    else if (msg.kind === 'pdb_file') {
        st.pdbFile = msg.path;
        const lbl = $('pdb-file-label');
        if (lbl)
            lbl.textContent = msg.path.split(/[/\\]/).pop() || msg.path;
    }
    else if (msg.kind === 'scan_root') {
        st.scanRoot = msg.path;
        st.scanRequested = true;
        $('panel-scan').innerHTML = '<p class="loading">Scanning…</p>';
        activateTab('scan');
        vscode.postMessage({ command: 'scan_path', path: st.scanRoot });
    }
}
function ensureReconstructCfg() {
    if (st.reconstructRequested)
        return;
    st.reconstructRequested = true;
    const panel = $('panel-flow');
    panel.innerHTML = '<p class="loading">Running reconstruct-cfg…</p>';
    vscode.postMessage({ command: 'reconstruct_cfg' });
}
function ensureScanPanel() {
    const panel = $('panel-scan');
    if (st.scanRequested)
        return;
    panel.innerHTML = '';
    const toolbar = document.createElement('div');
    toolbar.className = 'analysis-toolbar';
    const meta = document.createElement('div');
    meta.className = 'analysis-toolbar-meta';
    meta.textContent = 'Scan a folder for risky images and fuzz entry candidates.';
    const runCurrent = document.createElement('button');
    runCurrent.className = 'btn-sm';
    runCurrent.textContent = 'Scan Current Folder';
    runCurrent.addEventListener('click', () => {
        st.scanRequested = true;
        panel.innerHTML = '<p class="loading">Scanning…</p>';
        vscode.postMessage({ command: 'scan_path' });
    });
    const browse = document.createElement('button');
    browse.className = 'btn-sm';
    browse.textContent = 'Browse…';
    browse.addEventListener('click', () => vscode.postMessage({ command: 'scan_browse_folder' }));
    toolbar.append(meta, runCurrent, browse);
    panel.appendChild(toolbar);
}
function getPayloadObject(data, key) {
    if (!data || typeof data !== 'object')
        return null;
    const record = data;
    if (record[key] && typeof record[key] === 'object')
        return record[key];
    return record;
}
function makeTag(text, extraClass = '') {
    const tag = document.createElement('span');
    tag.className = `tag ${extraClass}`.trim();
    tag.textContent = String(text || '');
    return tag;
}
function appendMiniStats(container, stats) {
    const grid = document.createElement('div');
    grid.className = 'mini-stats';
    Object.entries(stats).forEach(([label, value]) => {
        const item = document.createElement('div');
        item.className = 'mini-stat';
        item.innerHTML = `<span>${esc(value)}</span><small>${esc(label)}</small>`;
        grid.appendChild(item);
    });
    container.appendChild(grid);
}
function renderReconstructCfg(msg) {
    const panel = $('panel-flow');
    panel.innerHTML = '';
    const data = getPayloadObject(msg.data, 'reconstruct_cfg');
    if (msg.error || !data) {
        panel.appendChild(errBox(msg.error || 'reconstruct-cfg returned no data'));
        st.reconstructRequested = false;
        return;
    }
    const toolbar = document.createElement('div');
    toolbar.className = 'analysis-toolbar';
    const title = document.createElement('div');
    title.className = 'analysis-toolbar-meta';
    title.textContent = `${data.image || 'image'} ${data.arch ? `· ${data.arch}` : ''} · entry ${data.entry_point || 'unknown'}`;
    const rerun = document.createElement('button');
    rerun.className = 'btn-sm';
    rerun.textContent = 'Re-run';
    rerun.addEventListener('click', () => {
        panel.innerHTML = '<p class="loading">Running reconstruct-cfg…</p>';
        vscode.postMessage({ command: 'reconstruct_cfg' });
    });
    const raw = document.createElement('button');
    raw.className = 'btn-sm';
    raw.textContent = 'Open JSON';
    raw.addEventListener('click', () => vscode.postMessage({
        command: 'open_text_report',
        language: 'json',
        content: JSON.stringify(msg.data, null, 2),
    }));
    toolbar.append(title, rerun, raw);
    panel.appendChild(toolbar);
    appendMiniStats(panel, {
        roots: data.stats?.roots ?? (data.roots || []).length,
        functions: data.stats?.functions_expanded ?? 0,
        calls: data.stats?.call_edges ?? 0,
        imports: data.stats?.import_edges ?? 0,
        indirect: data.stats?.indirect_edges ?? 0,
        threads: data.stats?.thread_edges ?? 0,
        workpools: data.stats?.workpool_edges ?? 0,
        exceptions: data.stats?.exception_edges ?? 0,
    });
    if (data.pdb) {
        const pdb = _card('Function Discovery');
        pdb.body.appendChild(kvRow('PDB', data.pdb.status || (data.pdb.loaded ? 'loaded' : 'unavailable')));
        pdb.body.appendChild(kvRow('Symbols', data.pdb.symbol_count ?? 0));
        pdb.body.appendChild(kvRow('Functions', data.pdb.function_count ?? 0));
        pdb.body.appendChild(kvRow('Sized Functions', data.pdb.sized_function_count ?? 0));
        if (data.pdb.error)
            pdb.body.appendChild(kvRow('PDB Error', data.pdb.error));
        panel.appendChild(pdb.card);
    }
    const roots = Array.isArray(data.roots) ? data.roots : [];
    if (!roots.length) {
        panel.appendChild(document.createRange().createContextualFragment('<p class="no-data">No reconstructed roots.</p>'));
    }
    else {
        const tree = document.createElement('div');
        tree.className = 'flow-tree';
        roots.forEach(root => tree.appendChild(renderFlowFunction(root, 0)));
        panel.appendChild(tree);
    }
    if (Array.isArray(data.notes) && data.notes.length) {
        const notes = document.createElement('div');
        notes.className = 'analysis-notes';
        data.notes.forEach(note => notes.appendChild(makeTag(note)));
        panel.appendChild(notes);
    }
}
function renderFlowFunction(fn, depth) {
    const node = document.createElement('details');
    node.className = `flow-node depth-${Math.min(depth, 4)}`;
    node.open = depth < 2;
    const summary = document.createElement('summary');
    summary.className = 'flow-summary';
    const name = document.createElement('span');
    name.className = 'flow-name';
    name.textContent = fn.name || fn.rva || 'function';
    const rva = document.createElement('span');
    rva.className = 'rva flow-rva';
    rva.textContent = fn.rva || '';
    if (fn.rva) {
        rva.title = 'Open function disassembly';
        rva.addEventListener('click', evt => {
            evt.preventDefault();
            navigateRva(fn.rva, fn.name || fn.rva);
        });
    }
    summary.append(name, rva);
    ['kind', 'section', 'symbol_source', 'symbol_category', 'status'].forEach(key => {
        if (fn[key])
            summary.appendChild(makeTag(fn[key], `flow-tag-${key}`));
    });
    if (fn.thread_lane)
        summary.appendChild(makeTag(`lane ${fn.thread_lane}`, 'flow-tag-thread'));
    node.appendChild(summary);
    if (fn.prototype || fn.decode_bound || fn.note || fn.returns?.length) {
        const meta = document.createElement('div');
        meta.className = 'flow-meta';
        if (fn.prototype)
            meta.appendChild(kvRow('Prototype', fn.prototype));
        if (fn.decode_bound)
            meta.appendChild(kvRow('Decode Bound', fn.decode_bound));
        if (fn.note)
            meta.appendChild(kvRow('Note', fn.note));
        if (fn.returns?.length)
            meta.appendChild(kvRow('Returns', fn.returns.join(', ')));
        node.appendChild(meta);
    }
    const edges = Array.isArray(fn.edges) ? fn.edges : [];
    if (edges.length) {
        const list = document.createElement('div');
        list.className = 'flow-edge-list';
        edges.forEach(edge => {
            const row = document.createElement('div');
            row.className = 'flow-edge';
            const site = document.createElement('span');
            site.className = 'rva';
            site.textContent = edge.site_rva || '';
            if (edge.site_rva) {
                site.title = 'Open edge site';
                site.addEventListener('click', () => navigateRva(edge.site_rva, edge.target || edge.site_rva));
            }
            const target = document.createElement('span');
            target.className = 'flow-edge-target';
            target.textContent = edge.target || edge.target_rva || '';
            const detail = document.createElement('span');
            detail.className = 'flow-edge-detail';
            detail.textContent = [edge.kind, edge.relation, edge.detail].filter(Boolean).join(' · ');
            row.append(site, target, detail);
            (edge.tags || []).forEach(tag => row.appendChild(makeTag(tag, tag === 'indirect' ? 'tag-warn' : '')));
            list.appendChild(row);
            if (edge.child)
                list.appendChild(renderFlowFunction(edge.child, depth + 1));
        });
        node.appendChild(list);
    }
    return node;
}
function renderScan(msg) {
    const panel = $('panel-scan');
    panel.innerHTML = '';
    const data = getPayloadObject(msg.data, 'scan');
    if (msg.error || !data) {
        panel.appendChild(errBox(msg.error || 'scan returned no data'));
        st.scanRequested = false;
        const browse = document.createElement('button');
        browse.className = 'btn-sm';
        browse.textContent = 'Choose Folder';
        browse.addEventListener('click', () => vscode.postMessage({ command: 'scan_browse_folder' }));
        panel.appendChild(browse);
        return;
    }
    const results = Array.isArray(data.results) ? data.results : [];
    const toolbar = document.createElement('div');
    toolbar.className = 'analysis-toolbar';
    const meta = document.createElement('div');
    meta.className = 'analysis-toolbar-meta';
    meta.textContent = `${results.length} image${results.length === 1 ? '' : 's'} · root ${data.root || msg.root || ''}`;
    const rerun = document.createElement('button');
    rerun.className = 'btn-sm';
    rerun.textContent = 'Re-run';
    rerun.addEventListener('click', () => {
        panel.innerHTML = '<p class="loading">Scanning…</p>';
        vscode.postMessage({ command: 'scan_path', path: st.scanRoot || data.root || msg.root || '' });
    });
    const browse = document.createElement('button');
    browse.className = 'btn-sm';
    browse.textContent = 'Browse…';
    browse.addEventListener('click', () => vscode.postMessage({ command: 'scan_browse_folder' }));
    const raw = document.createElement('button');
    raw.className = 'btn-sm';
    raw.textContent = 'Open JSON';
    raw.addEventListener('click', () => vscode.postMessage({
        command: 'open_text_report',
        language: 'json',
        content: JSON.stringify(msg.data, null, 2),
    }));
    toolbar.append(meta, rerun, browse, raw);
    panel.appendChild(toolbar);
    appendMiniStats(panel, {
        seen: data.files_seen ?? results.length,
        reported: data.files_reported ?? results.length,
        candidates: results.reduce((n, item) => n + (Array.isArray(item.candidates) ? item.candidates.length : 0), 0),
        risk_imports: results.reduce((n, item) => n + (Array.isArray(item.risk_imports) ? item.risk_imports.length : 0), 0),
    });
    if (!results.length) {
        panel.appendChild(document.createRange().createContextualFragment('<p class="no-data">No matching PE images were reported.</p>'));
        return;
    }
    const { bar, lbl } = _searchBar(panel, 'Regex search scan results…');
    lbl.textContent = `${results.length} images`;
    const list = document.createElement('div');
    list.className = 'scan-results';
    panel.appendChild(list);
    const rows = [];
    results.forEach(item => {
        const details = document.createElement('details');
        details.className = 'scan-item';
        details.open = rows.length < 8;
        details.dataset.text = JSON.stringify(item).toLowerCase();
        const summary = document.createElement('summary');
        summary.className = 'scan-summary';
        summary.innerHTML = `<span class="scan-risk">${esc(item.risk_score ?? 0)}</span><span class="scan-name">${esc(item.name || item.path)}</span><span class="scan-meta">${esc([item.kind, item.arch, formatBytes(item.size_bytes), item.entry_point].filter(Boolean).join(' · '))}</span>`;
        details.appendChild(summary);
        const body = document.createElement('div');
        body.className = 'scan-body';
        body.appendChild(kvRow('Path', item.path || ''));
        body.appendChild(kvRow('Exports', item.exports ?? 0));
        body.appendChild(kvRow('Imports', item.imports ?? 0));
        body.appendChild(kvRow('Runtime Functions', item.runtime_functions ?? 0));
        if (item.pdb_name)
            body.appendChild(kvRow('PDB', item.pdb_name));
        appendScanCandidateSection(body, item.candidates || []);
        appendScanRiskImports(body, item.risk_imports || []);
        if (Array.isArray(item.anomalies) && item.anomalies.length) {
            const anom = document.createElement('div');
            anom.className = 'analysis-notes';
            item.anomalies.forEach(a => anom.appendChild(makeTag(a, 'tag-warn')));
            body.appendChild(anom);
        }
        details.appendChild(body);
        list.appendChild(details);
        rows.push(details);
    });
    const inp = bar.querySelector('input');
    inp.addEventListener('input', () => {
        const raw = inp.value.trim();
        let re = null;
        let errEl = bar.querySelector('.regex-err') || (() => { const e = document.createElement('span'); e.className = 'regex-err'; bar.appendChild(e); return e; })();
        if (raw) {
            try {
                re = new RegExp(raw, 'i');
                inp.classList.remove('invalid');
                errEl.textContent = '';
            }
            catch (ex) {
                inp.classList.add('invalid');
                errEl.textContent = ex.message;
                return;
            }
        }
        else {
            inp.classList.remove('invalid');
            errEl.textContent = '';
        }
        let visible = 0;
        rows.forEach(row => {
            const show = !re || re.test(row.dataset.text || '');
            row.style.display = show ? '' : 'none';
            if (show)
                visible++;
        });
        lbl.textContent = re ? `${visible} / ${results.length} images` : `${results.length} images`;
    });
}
function appendScanCandidateSection(container, candidates) {
    if (!candidates.length)
        return;
    const title = document.createElement('div');
    title.className = 'section-label';
    title.textContent = `Fuzz Candidates (${candidates.length})`;
    container.appendChild(title);
    candidates.slice(0, 12).forEach(candidate => {
        const row = document.createElement('div');
        row.className = 'scan-candidate';
        row.innerHTML = `<span class="scan-risk">${esc(candidate.score ?? 0)}</span><span class="rva">${esc(candidate.rva || '')}</span><span class="scan-candidate-name">${esc(candidate.name || '')}</span><span class="scan-meta">${esc(candidate.source || '')}</span>`;
        if (Array.isArray(candidate.reasons)) {
            candidate.reasons.forEach(reason => row.appendChild(makeTag(reason)));
        }
        container.appendChild(row);
    });
}
function appendScanRiskImports(container, imports) {
    if (!imports.length)
        return;
    const title = document.createElement('div');
    title.className = 'section-label';
    title.textContent = `Risk Imports (${imports.length})`;
    container.appendChild(title);
    const wrap = document.createElement('div');
    wrap.className = 'tag-wrap';
    imports.slice(0, 32).forEach(item => wrap.appendChild(makeTag(`${item.dll}!${item.name} · ${item.category}`, 'tag-warn')));
    container.appendChild(wrap);
}
function renderPeInfo(msg) {
    const d = unwrapObjectPayload(msg.data, 'peinfo');
    if (msg.error || !d) {
        $('panel-overview').appendChild(errBox(msg.error || 'peinfo returned no data'));
        $('panel-entry').appendChild(errBox(msg.error || 'peinfo returned no data'));
        $('panel-sections').appendChild(errBox(msg.error || 'no data'));
        return;
    }
    st.currentPeInfo = d;
    st.currentDumpDll = d.dll || basenamePath(d.dll_path || '') || '';
    st.currentDumpPath = d.dll_path || '';
    if (!st.rootDllPath) {
        st.rootDll = st.currentDumpDll;
        st.rootDllPath = st.currentDumpPath;
    }
    if (d.entry_point)
        st.entryPoint = d.entry_point;
    renderOverview(d);
    renderEntryPanel(d);
    renderSections(d.sections || []);
}
function renderOverview(d) {
    const panel = $('panel-overview');
    panel.innerHTML = '';
    const hdr = document.createElement('div');
    hdr.className = 'ov-file-header';
    hdr.innerHTML = `
            <span class="ov-file-name">${esc(d.file_name)}</span>
            <span class="ov-file-meta">${esc(d.image_kind)} &middot; ${esc(d.arch)} &middot; ${formatBytes(d.file_size)}</span>`;
    panel.appendChild(hdr);
    const grid = document.createElement('div');
    grid.className = 'ov-grid';
    panel.appendChild(grid);
    const id = _card('Identity');
    [['Architecture', `${d.arch} / ${d.machine}`], ['Subsystem', `${d.subsystem_name} (${d.subsystem})`],
        ['Linker', d.linker_version], ['Timestamp', d.timestamp], ['Checksum', d.checksum],
        ['DLL Chars', d.dll_characteristics]]
        .forEach(([k, v]) => id.body.appendChild(kvRow(k, v)));
    grid.appendChild(id.card);
    const addr = _card('Addresses');
    [['Image Base', d.image_base], ['Image Size', d.size_of_image], ['Sec Align', d.section_alignment],
        ['File Align', d.file_alignment], ['Checksum', d.checksum]]
        .forEach(([k, v]) => addr.body.appendChild(kvRow(k, v)));
    grid.appendChild(addr.card);
    const cnts = _card('Tables');
    [['Exports', d.export_count], ['Import DLLs', d.import_dll_count], ['Imports', d.import_count]]
        .forEach(([k, v]) => cnts.body.appendChild(kvRow(k, v)));
    grid.appendChild(cnts.card);
    const dataSummary = d.data || {};
    if (dataSummary.unwind_count || dataSummary.vtable_count || dataSummary.pointer_count || d.startup_routines?.length) {
        const funcs = _card('Function Discovery');
        funcs.body.appendChild(kvRow('Startup Routines', d.startup_routines?.length || 0));
        funcs.body.appendChild(kvRow('Runtime Functions', dataSummary.unwind_count || 0));
        funcs.body.appendChild(kvRow('VTables', dataSummary.vtable_count || 0));
        funcs.body.appendChild(kvRow('Pointers', dataSummary.pointer_count || 0));
        if (d.mitigations?.cfg_function_table != null)
            funcs.body.appendChild(kvRow('CFG Function Table', d.mitigations.cfg_function_table ? 'Present' : 'Absent'));
        grid.appendChild(funcs.card);
    }
    const n = d.names || {};
    if (n.product_name || n.file_description) {
        const ver = _card('Version Info');
        if (n.product_name)
            ver.body.appendChild(kvRow('Product', n.product_name));
        if (n.file_description)
            ver.body.appendChild(kvRow('Desc', n.file_description));
        if (n.company_name)
            ver.body.appendChild(kvRow('Company', n.company_name));
        if (n.file_version)
            ver.body.appendChild(kvRow('File Ver', n.file_version));
        if (n.original_filename)
            ver.body.appendChild(kvRow('Orig Name', n.original_filename));
        grid.appendChild(ver.card);
    }
    const a = d.analysis || {};
    if (a.platform || a.runtime) {
        const bld = _card('Build Analysis');
        bld.body.appendChild(kvRow('Platform', a.platform || '—'));
        bld.body.appendChild(kvRow('Runtime', a.runtime || '—'));
        if (a.likely_languages?.length)
            bld.body.appendChild(kvRow('Language', a.likely_languages.join(', ')));
        if (a.likely_toolchains?.length)
            bld.body.appendChild(kvRow('Toolchain', a.likely_toolchains.join(', ')));
        if (a.likely_components?.length)
            bld.body.appendChild(kvRow('Components', a.likely_components.join(', ')));
        if (a.packers?.length)
            bld.body.appendChild(kvRow('Packers', a.packers.join(', ')));
        if (a.clr_metadata_version)
            bld.body.appendChild(kvRow('CLR', a.clr_metadata_version));
        if (a.evidence?.length) {
            const tw = document.createElement('div');
            tw.className = 'tag-wrap';
            a.evidence.forEach(ev => {
                const t = document.createElement('span');
                t.className = 'tag';
                t.textContent = ev;
                tw.appendChild(t);
            });
            bld.body.appendChild(tw);
        }
        grid.appendChild(bld.card);
    }
    const dbg = d.debug || {};
    const dc = _card('Debug');
    dc.body.appendChild(kvRow('Has Debug Dir', dbg.has_debug_directory ? 'Yes' : 'No'));
    dc.body.appendChild(kvRow('Has CodeView', dbg.has_codeview ? 'Yes' : 'No'));
    dc.body.appendChild(kvRow('Stripped', dbg.debug_stripped ? 'Yes' : 'No'));
    if (dbg.pdb_name)
        dc.body.appendChild(kvRow('PDB Name', dbg.pdb_name));
    if (dbg.pdb_path)
        dc.body.appendChild(kvRow('PDB Path', dbg.pdb_path));
    if (dbg.pdb_guid_age)
        dc.body.appendChild(kvRow('PDB GUID/Age', dbg.pdb_guid_age));
    grid.appendChild(dc.card);
    const sig = d.signer || {};
    if (sig.status) {
        const sc = _card('Signature');
        const stEl = document.createElement('div');
        stEl.className = 'kv';
        const stKey = document.createElement('span');
        stKey.className = 'kv-k';
        stKey.textContent = 'Status';
        const stVal = document.createElement('span');
        const sl = sig.status.toLowerCase();
        stVal.className = `kv-v ${sl.includes('valid') && !sl.includes('invalid') ? 'sig-status-valid' : sl.includes('unsigned') ? 'sig-status-unsigned' : 'sig-status-invalid'}`;
        stVal.textContent = sig.status;
        stEl.append(stKey, stVal);
        sc.body.appendChild(stEl);
        if (sig.subject)
            sc.body.appendChild(kvRow('Subject', sig.subject));
        if (sig.issuer)
            sc.body.appendChild(kvRow('Issuer', sig.issuer));
        if (sig.thumbprint)
            sc.body.appendChild(kvRow('Thumbprint', sig.thumbprint));
        grid.appendChild(sc.card);
    }
    const mitCard = _card('Mitigations');
    mitCard.card.style.gridColumn = '1 / -1';
    const m = d.mitigations || {};
    const mitDefs = [
        ['ASLR', m.aslr, 'Address space layout randomisation'],
        ['High Entropy VA', m.high_entropy_va, '64-bit ASLR full VA range'],
        ['NX / DEP', m.nx_compat, 'Data Execution Prevention'],
        ['CFG', m.cfg, 'Control Flow Guard'],
        ['CFG Instrumented', m.cfg_instrumented, 'CFG instrumentation present'],
        ['XFG', m.xfg, 'Extended Flow Guard'],
        ['RETPOLINE', m.retpoline, 'Spectre v2 retpoline mitigation'],
        ['RF Instrumented', m.rf_instrumented, 'Return Flow instrumentation'],
        ['RF Enabled', m.rf_enabled, 'Return Flow guard enabled'],
        ['RF Strict', m.rf_strict, 'Return Flow strict mode'],
        ['CET EH', m.cet_eh_continuation, 'CET exception handler continuation'],
        ['CastGuard', m.cast_guard, 'Type-safety cast guard'],
        ['MemcpyGuard', m.memcpy_guard, 'Memcpy guard instrumentation'],
        ['Force Integrity', m.force_integrity, 'Code integrity enforcement'],
        ['AppContainer', m.appcontainer, 'AppContainer sandbox'],
        ['Security Cookie', m.security_cookie, '/GS stack cookie'],
        ['Safe SEH', m.safe_seh, 'SafeSEH table (x86)'],
        ['No SEH', m.no_seh, 'SEH disabled'],
        ['WDM Driver', m.wdm_driver, 'Windows Driver Model'],
        ['Delay IAT Prot.', m.delay_load_iat_protected, 'Delay-load IAT protected'],
        ['Reloc Stripped', m.reloc_stripped, 'Fixed base (no ASLR)'],
    ];
    const tbl = document.createElement('table');
    tbl.className = 'mit-table';
    const tbody = document.createElement('tbody');
    for (let i = 0; i < mitDefs.length; i += 2) {
        const tr = document.createElement('tr');
        for (let j = 0; j < 2; j++) {
            const def = mitDefs[i + j];
            if (!def) {
                for (let k = 0; k < 3; k++)
                    tr.appendChild(document.createElement('td'));
                continue;
            }
            const [label, on, desc] = def;
            const ti = document.createElement('td');
            ti.className = on ? 'mit-on' : 'mit-off';
            ti.textContent = on ? '✓' : '✗';
            const tn = document.createElement('td');
            tn.textContent = label;
            const td2 = document.createElement('td');
            td2.className = 'kv-k';
            td2.style.fontSize = '11px';
            td2.textContent = desc;
            tr.append(ti, tn, td2);
            if (j === 0 && mitDefs[i + 1]) {
                const sp = document.createElement('td');
                sp.style.width = '16px';
                tr.appendChild(sp);
            }
        }
        tbody.appendChild(tr);
    }
    tbl.appendChild(tbody);
    mitCard.body.appendChild(tbl);
    panel.appendChild(mitCard.card);
    if (d.anomalies?.length) {
        const al = document.createElement('div');
        al.className = 'section-label';
        al.textContent = `Anomalies (${d.anomalies.length})`;
        panel.appendChild(al);
        const aList = document.createElement('div');
        aList.className = 'anom-list';
        d.anomalies.forEach(a => {
            const row = document.createElement('div');
            row.className = `anom sev-${a.severity.toLowerCase()}`;
            row.innerHTML = `<span class="anom-sev">${esc(a.severity)}</span><span class="anom-kind">${esc(a.kind)}</span><span class="anom-detail">${esc(a.detail)}</span>`;
            aList.appendChild(row);
        });
        panel.appendChild(aList);
    }
}
function _card(title) {
    const card = document.createElement('div');
    card.className = 'ov-card';
    const t = document.createElement('div');
    t.className = 'ov-card-title';
    t.textContent = title;
    card.appendChild(t);
    return { card, body: card };
}
function renderSections(secs) {
    const panel = $('panel-sections');
    panel.innerHTML = '';
    if (!secs.length) {
        panel.innerHTML = '<p class="no-data">No sections.</p>';
        return;
    }
    const wrap = document.createElement('div');
    wrap.className = 'tbl-wrap';
    const tbl = document.createElement('table');
    const head = tbl.createTHead();
    const hrow = head.insertRow();
    ['Name', 'RVA', 'Virt Size', 'Raw Size', 'Protection', 'Expected', 'Entropy', 'Note'].forEach(label => {
        const th = document.createElement('th');
        th.textContent = label;
        th.addEventListener('click', () => sortTable(th, tbl));
        hrow.appendChild(th);
    });
    const body = tbl.createTBody();
    secs.forEach(s => {
        const tag = s.tag || s.protection || '';
        const hasW = tag.includes('W'), hasX = tag.includes('X') || tag.includes('E');
        const pc = hasW && hasX ? 'prot-rwx' : hasX ? 'prot-rx' : hasW ? 'prot-rw' : 'prot-r';
        const ec = s.entropy >= 7.8 ? 'entropy-xhi' : s.entropy >= 6.8 ? 'entropy-hi' : '';
        const tr = body.insertRow();
        tr.className = `${pc} section-row`;
        tr.title = `Browse ${s.name} at ${s.rva}`;
        tr.addEventListener('click', () => navigateRva(s.rva, `${s.name}@${s.rva}`));
        tr.addEventListener('dblclick', () => navigateRva(s.rva, `${s.name}@${s.rva}`));
        [s.name, s.rva, s.virtual_size, s.raw_size].forEach(v => { const td = tr.insertCell(); td.className = 'mono'; td.textContent = v; });
        const ptd = tr.insertCell();
        ptd.className = 'mono prot-cell';
        ptd.textContent = tag;
        const etd = tr.insertCell();
        etd.textContent = s.expected;
        const entd = tr.insertCell();
        entd.className = ec;
        entd.textContent = s.entropy.toFixed(3);
        const ntd = tr.insertCell();
        ntd.className = 'kv-k';
        ntd.style.fontSize = '11px';
        ntd.textContent = s.note || '';
    });
    wrap.appendChild(tbl);
    panel.appendChild(wrap);
}
function renderEat(msg) {
    const panel = $('panel-exports');
    panel.innerHTML = '';
    const exports = unwrapListPayload(msg.data, 'exports');
    if (msg.error || (!exports.length && !msg.data)) {
        setTabVisible('exports', false);
        panel.appendChild(errBox(msg.error || 'No export data'));
        return;
    }
    if (!exports.length) {
        setTabVisible('exports', false);
        panel.innerHTML = '<p class="no-data">No exports.</p>';
        return;
    }
    setTabVisible('exports', true);
    const { bar, lbl } = _searchBar(panel, 'Regex filter…');
    const wrap = document.createElement('div');
    wrap.className = 'tbl-wrap';
    const tbl = document.createElement('table');
    const head = tbl.createTHead();
    const hrow = head.insertRow();
    ['Name', 'Ordinal', 'RVA', 'Forward'].forEach(l => {
        const th = document.createElement('th');
        th.textContent = l;
        th.addEventListener('click', () => sortTable(th, tbl));
        hrow.appendChild(th);
    });
    const body = tbl.createTBody();
    exports.forEach(e => {
        const tr = body.insertRow();
        const ntd = tr.insertCell();
        if (e.name) {
            const link = document.createElement('span');
            link.className = 'fn-link';
            link.textContent = e.name;
            link.dataset.func = e.name;
            link.addEventListener('mouseenter', ev => startTooltip(e.name, ev));
            link.addEventListener('mousemove', ev => moveTooltip(ev));
            link.addEventListener('mouseleave', () => hideTooltip());
            link.addEventListener('contextmenu', ev => showCtxMenu(ev, e.name, null));
            link.addEventListener('click', () => navigateInRoot(e.name));
            link.addEventListener('dblclick', () => navigateInRoot(e.name));
            ntd.appendChild(link);
        }
        else
            ntd.innerHTML = '<span class="fwd-cell">(by ordinal)</span>';
        const otd = tr.insertCell();
        otd.className = 'mono';
        otd.textContent = e.ordinal;
        const rtd = tr.insertCell();
        rtd.className = 'rva';
        rtd.textContent = e.rva;
        const ftd = tr.insertCell();
        ftd.className = 'fwd-cell';
        ftd.textContent = e.forward_to || '';
    });
    wrap.appendChild(tbl);
    panel.appendChild(wrap);
    const rows = Array.from(body.rows);
    lbl.textContent = `${rows.length} exports`;
    _wireSearch(bar.querySelector('input'), rows, lbl, `${rows.length} exports`);
}
function renderIat(msg) {
    const panel = $('panel-imports');
    panel.innerHTML = '';
    const dlls = unwrapListPayload(msg.data, 'imports');
    if (msg.error || (!dlls.length && !msg.data)) {
        setTabVisible('imports', false);
        panel.appendChild(errBox(msg.error || 'No import data'));
        return;
    }
    if (!dlls.length) {
        setTabVisible('imports', false);
        panel.innerHTML = '<p class="no-data">No imports.</p>';
        return;
    }
    setTabVisible('imports', true);
    st.iatIndex.clear();
    let total = 0;
    dlls.forEach(d => {
        (d.imports || []).forEach(i => {
            if (i.name)
                st.iatIndex.set(i.name, d.dll);
        });
        total += (d.imports || []).length;
    });
    const { bar, lbl } = _searchBar(panel, 'Regex filter…');
    lbl.textContent = `${total} imports · ${dlls.length} DLLs`;
    const container = document.createElement('div');
    panel.appendChild(container);
    const groups = dlls.map(d => {
        const div = document.createElement('div');
        div.className = 'iat-dll';
        div.dataset.dll = d.dll.toLowerCase();
        const hdr = document.createElement('div');
        hdr.className = 'iat-dll-hdr';
        hdr.innerHTML = `<span>${esc(d.dll)}</span><span class="badge">${d.imports.length}</span>`;
        const body = document.createElement('div');
        body.className = 'iat-dll-body';
        hdr.addEventListener('click', () => body.classList.toggle('open'));
        const tbl = document.createElement('table');
        const th = tbl.createTHead();
        const hr = th.insertRow();
        ['Name', 'Ordinal', 'Hint'].forEach(l => { const cell = document.createElement('th'); cell.textContent = l; hr.appendChild(cell); });
        const tb = tbl.createTBody();
        (d.imports || []).forEach(imp => {
            const row = tb.insertRow();
            row.dataset.name = (imp.name || '').toLowerCase();
            const ntd = row.insertCell();
            if (imp.by_ord) {
                const link = document.createElement('span');
                link.className = 'fn-link';
                link.textContent = `(ordinal ${imp.ordinal})`;
                if (imp.slot_rva) {
                    link.title = `Open ${d.dll} ordinal import entry in the current image`;
                    link.addEventListener('click', () => navigateRootRva(imp.slot_rva, `${d.dll}!#${imp.ordinal}`));
                    link.addEventListener('dblclick', () => navigateRootRva(imp.slot_rva, `${d.dll}!#${imp.ordinal}`));
                }
                ntd.appendChild(link);
            }
            else if (imp.slot_rva) {
                const link = document.createElement('span');
                link.className = 'fn-link';
                link.textContent = imp.name;
                link.dataset.func = imp.name;
                link.title = `Open ${d.dll}!${imp.name} import entry in the current image`;
                link.addEventListener('mouseenter', ev => startTooltip(imp.name, ev));
                link.addEventListener('mousemove', ev => moveTooltip(ev));
                link.addEventListener('mouseleave', () => hideTooltip());
                link.addEventListener('contextmenu', ev => showCtxMenu(ev, imp.name, d.dll));
                link.addEventListener('click', () => navigateRootRva(imp.slot_rva, `${d.dll}!${imp.name}`));
                link.addEventListener('dblclick', () => navigateRootRva(imp.slot_rva, `${d.dll}!${imp.name}`));
                ntd.appendChild(link);
            }
            else {
                const link = fnLink(imp.name);
                link.title = `Open ${d.dll}!${imp.name} import entry in the current image`;
                ntd.appendChild(link);
            }
            const otd = row.insertCell();
            otd.className = 'mono';
            otd.textContent = imp.ordinal;
            const htd = row.insertCell();
            htd.className = 'mono';
            htd.textContent = imp.hint;
        });
        body.appendChild(tbl);
        div.append(hdr, body);
        return { div, body, tbl, dllName: d.dll.toLowerCase() };
    });
    groups.forEach(g => container.appendChild(g.div));
    const inp = bar.querySelector('input');
    inp.addEventListener('input', () => {
        const raw = inp.value.trim();
        let re = null, errEl = bar.querySelector('.regex-err') || (() => {
            const e = document.createElement('span');
            e.className = 'regex-err';
            bar.appendChild(e);
            return e;
        })();
        if (raw) {
            try {
                re = new RegExp(raw, 'i');
                inp.classList.remove('invalid');
                errEl.textContent = '';
            }
            catch (ex) {
                inp.classList.add('invalid');
                errEl.textContent = ex.message;
                return;
            }
        }
        else {
            inp.classList.remove('invalid');
            errEl.textContent = '';
        }
        let vi = 0, vd = 0;
        groups.forEach(({ div, body, tbl, dllName }) => {
            const dm = !re || re.test(dllName);
            let rc = 0;
            Array.from(tbl.tBodies[0].rows).forEach(row => {
                const show = !re || dm || re.test(row.dataset.name);
                row.style.display = show ? '' : 'none';
                if (show)
                    rc++;
            });
            const av = dm || rc > 0;
            div.style.display = av ? '' : 'none';
            if (av) {
                vd++;
                vi += rc;
                if (re)
                    body.classList.add('open');
            }
        });
        lbl.textContent = re ? `${vi} imports · ${vd} DLLs (filtered)` : `${total} imports · ${dlls.length} DLLs`;
    });
}
function renderSyms(msg) {
    const panel = $('panel-symbols');
    panel.innerHTML = '';
    const syms = unwrapListPayload(msg.data, 'symbols');
    if (msg.error || !syms.length) {
        panel.innerHTML = '<p class="no-data">No symbols. Use ⚙ Symbols to configure PDB paths and reload.</p>';
        if (msg.error)
            panel.insertAdjacentElement('afterbegin', errBox(msg.error));
        return;
    }
    const { bar, lbl } = _searchBar(panel, 'Regex filter…');
    lbl.textContent = `${syms.length} symbols`;
    const wrap = document.createElement('div');
    wrap.className = 'tbl-wrap';
    const tbl = document.createElement('table');
    const head = tbl.createTHead();
    const hrow = head.insertRow();
    ['Name', 'Kind', 'RVA', 'VA', 'Type', 'Size'].forEach(l => {
        const th = document.createElement('th');
        th.textContent = l;
        th.addEventListener('click', () => sortTable(th, tbl));
        hrow.appendChild(th);
    });
    const body = tbl.createTBody();
    syms.forEach(s => {
        const tr = body.insertRow();
        const ntd = tr.insertCell();
        const isCode = s.kind === 'function' || s.kind === 'public';
        if (isCode) {
            const link = document.createElement('span');
            link.className = 'fn-link';
            link.textContent = s.name;
            link.dataset.func = s.name;
            link.addEventListener('mouseenter', ev => startTooltip(s.name, ev));
            link.addEventListener('mousemove', ev => moveTooltip(ev));
            link.addEventListener('mouseleave', () => hideTooltip());
            link.addEventListener('contextmenu', ev => showCtxMenu(ev, s.name, null));
            link.addEventListener('click', () => navigateRootRva(s.rva, s.name));
            link.addEventListener('dblclick', () => navigateRootRva(s.rva, s.name));
            ntd.appendChild(link);
        }
        else {
            const typeName = (s.type_name || s.name).toLowerCase();
            const typeEntry = st.typesByName.get(typeName) || st.typesByName.get(s.name.toLowerCase());
            if (typeEntry) {
                const link = document.createElement('span');
                link.className = 'fn-link sym-data';
                link.textContent = s.name;
                link.title = `Data symbol · ${s.type_name || s.kind} · navigate to Types`;
                link.addEventListener('click', () => {
                    st._pendingTypeNav = typeName;
                    activateTab('types');
                });
                ntd.appendChild(link);
            }
            else {
                const span = document.createElement('span');
                span.className = 'sym-data';
                span.textContent = s.name;
                span.title = `Data symbol · ${s.type_name || s.kind}`;
                ntd.appendChild(span);
            }
        }
        const ktd = tr.insertCell();
        ktd.className = 'mono';
        ktd.textContent = s.kind;
        const rtd = tr.insertCell();
        rtd.className = 'rva';
        rtd.textContent = s.rva;
        const vtd = tr.insertCell();
        vtd.className = 'rva';
        vtd.textContent = s.va;
        const ttd = tr.insertCell();
        ttd.className = 'mono';
        ttd.textContent = s.type_name || '';
        const std = tr.insertCell();
        std.className = 'mono';
        std.textContent = s.size ? String(s.size) : '';
    });
    wrap.appendChild(tbl);
    panel.appendChild(wrap);
    _wireSearch(bar.querySelector('input'), Array.from(body.rows), lbl, `${syms.length} symbols`);
}
function renderTypes(msg) {
    const panel = $('panel-types');
    panel.innerHTML = '';
    const types = unwrapListPayload(msg.data, 'types');
    if (msg.error || !types.length) {
        panel.innerHTML = '<p class="no-data">No PDB-backed types found.</p>';
        if (msg.error)
            panel.insertAdjacentElement('afterbegin', errBox(msg.error));
        return;
    }
    const byId = new Map(types.map(entry => [entry.type_id, entry]));
    const byName = new Map();
    types.forEach(entry => {
        rememberTypeEntry(byName, String(entry.name || '').trim().toLowerCase(), entry);
        rememberTypeEntry(byName, canonicalTypeName(entry.name), entry);
    });
    st.typesByName = byName;
    const { bar, lbl } = _searchBar(panel, 'Search types or refs…');
    lbl.textContent = `${types.length} types`;
    const shell = document.createElement('div');
    shell.className = 'types-shell';
    const list = document.createElement('div');
    list.className = 'types-list';
    const detail = document.createElement('div');
    detail.className = 'types-detail';
    shell.append(list, detail);
    panel.appendChild(shell);
    let selected = null;
    let visible = types;
    const pickLinkedType = member => {
        if (member?.type_id && byId.has(member.type_id))
            return byId.get(member.type_id);
        const rawName = String(member?.type_name || '').trim();
        return byName.get(rawName.toLowerCase()) || byName.get(canonicalTypeName(rawName)) || null;
    };
    const renderDetail = entry => {
        if (!entry) {
            detail.innerHTML = '<p class="no-data">Select a type.</p>';
            return;
        }
        detail.innerHTML = '';
        const hdr = document.createElement('div');
        hdr.className = 'types-detail-title';
        hdr.textContent = entry.name;
        detail.appendChild(hdr);
        const meta = document.createElement('div');
        meta.className = 'types-detail-meta';
        meta.textContent = `${entry.kind || 'type'} · ${entry.size || 0} bytes · ${entry.members?.length || 0} member(s) · ${entry.symbol_count} symbol(s)`;
        detail.appendChild(meta);
        const membersWrap = document.createElement('div');
        membersWrap.className = 'types-members';
        const membersTitle = document.createElement('div');
        membersTitle.className = 'types-section-title';
        membersTitle.textContent = 'Members';
        membersWrap.appendChild(membersTitle);
        if (entry.members?.length) {
            entry.members.forEach(member => {
                const row = document.createElement('div');
                row.className = 'types-member-row';
                const off = document.createElement('span');
                off.className = 'types-member-offset';
                off.textContent = member.offset || '0x0';
                const type = document.createElement(pickLinkedType(member) ? 'button' : 'span');
                type.className = pickLinkedType(member) ? 'types-member-type linkish-btn' : 'types-member-type';
                type.textContent = member.type_name || member.kind || 'member';
                if (type.tagName === 'BUTTON') {
                    type.addEventListener('click', () => {
                        selected = pickLinkedType(member);
                        renderList(visible);
                        renderDetail(selected);
                    });
                }
                const name = document.createElement('span');
                name.className = 'types-member-name';
                name.textContent = member.name || '<anon>';
                row.append(off, type, name);
                membersWrap.appendChild(row);
            });
        }
        else {
            const none = document.createElement('p');
            none.className = 'no-data';
            none.textContent = 'No member layout available.';
            membersWrap.appendChild(none);
        }
        detail.appendChild(membersWrap);
        const refsTitle = document.createElement('div');
        refsTitle.className = 'types-section-title';
        refsTitle.textContent = 'Typed References';
        detail.appendChild(refsTitle);
        const refs = document.createElement('div');
        refs.className = 'types-refs';
        entry.refs.forEach(ref => {
            const row = document.createElement('div');
            row.className = 'types-ref-row';
            const name = document.createElement('span');
            name.className = 'types-ref-name';
            name.appendChild(fnLink(ref.name, ref.rva ? { rva: ref.rva } : {}));
            const kind = document.createElement('span');
            kind.className = 'types-ref-kind';
            kind.textContent = ref.kind;
            const rva = document.createElement('span');
            rva.className = 'types-ref-rva';
            rva.textContent = ref.rva;
            row.append(kind, name, rva);
            refs.appendChild(row);
        });
        detail.appendChild(refs);
    };
    const renderList = filtered => {
        visible = filtered;
        list.innerHTML = '';
        filtered.forEach(entry => {
            const item = document.createElement('button');
            item.className = `types-item${selected?.type_id === entry.type_id ? ' active' : ''}`;
            item.innerHTML = `<span class="types-item-name">${esc(entry.name)}</span><span class="types-item-count">${entry.members?.length || 0}m</span>`;
            item.addEventListener('click', () => {
                selected = entry;
                renderList(filtered);
                renderDetail(entry);
            });
            list.appendChild(item);
        });
        if (!selected && filtered.length) {
            selected = filtered[0];
            renderList(filtered);
            renderDetail(filtered[0]);
        }
        else if (!filtered.length) {
            selected = null;
            renderDetail(null);
        }
    };
    const inp = bar.querySelector('input');
    inp.addEventListener('input', () => {
        const raw = inp.value.trim().toLowerCase();
        const filtered = !raw ? types : types.filter(entry => entry.name.toLowerCase().includes(raw)
            || String(entry.kind || '').toLowerCase().includes(raw)
            || (entry.members || []).some(member => String(member.name || '').toLowerCase().includes(raw)
                || String(member.type_name || '').toLowerCase().includes(raw))
            || entry.refs.some(ref => ref.name.toLowerCase().includes(raw)));
        lbl.textContent = !raw ? `${types.length} types` : `${filtered.length} / ${types.length} types`;
        if (selected && !filtered.some(entry => entry.type_id === selected.type_id)) {
            selected = null;
        }
        renderList(filtered);
    });
    if (st._pendingTypeNav) {
        const pending = st._pendingTypeNav;
        st._pendingTypeNav = null;
        const target = byName.get(pending) || byName.get(canonicalTypeName(pending));
        if (target) {
            selected = target;
            renderList(types);
            renderDetail(target);
        }
        else {
            renderList(types);
        }
    }
    else {
        renderList(types);
    }
}
function renderTriage(msg) {
    const panel = $('panel-triage');
    panel.innerHTML = '';
    const data = unwrapObjectPayload(msg.data, 'dump');
    if (msg.error || !data) {
        panel.appendChild(errBox(msg.error || 'No triage data'));
        return;
    }
    const findings = data.intelli_findings || [];
    const startupRoutines = Array.isArray(st.currentPeInfo?.startup_routines) ? st.currentPeInfo.startup_routines : [];
    if (!findings.length && !startupRoutines.length) {
        panel.innerHTML = '<p class="no-data">No triage findings.</p>';
        return;
    }
    const grouped = {};
    if (startupRoutines.length) {
        grouped['Startup Execution'] = startupRoutines.map(entry => ({
            category: 'Startup Execution',
            rule: entry.kind,
            source: entry.source,
            value: `${entry.section || 'section'} ${entry.rva}${entry.note ? ` · ${entry.note}` : ''}`,
            rva: entry.rva,
        }));
    }
    findings.forEach(f => { (grouped[f.category] = grouped[f.category] || []).push(f); });
    const { bar, lbl } = _searchBar(panel, 'Regex search findings…');
    const totalFindings = findings.length + startupRoutines.length;
    lbl.textContent = `${totalFindings} findings`;
    const container = document.createElement('div');
    panel.appendChild(container);
    const allRows = [];
    for (const [cat, items] of Object.entries(grouped)) {
        const grp = document.createElement('details');
        grp.className = 'finding-group';
        const title = document.createElement('summary');
        title.className = 'finding-group-title';
        title.innerHTML = `${esc(cat)} <span class="tag">${items.length}</span>`;
        grp.appendChild(title);
        items.forEach(f => {
            const row = document.createElement('div');
            row.className = 'finding-row';
            row.dataset.text = `${f.category} ${f.rule} ${f.source} ${f.value}`.toLowerCase();
            row.innerHTML = `<span class="finding-rule">${esc(f.rule)}</span><span class="finding-source">${esc(f.source)}</span><span class="finding-val">${esc(f.value)}</span>`;
            if (f.rva) {
                row.title = `Disassemble ${f.rva}`;
                row.addEventListener('click', () => navigateRva(f.rva, `${f.rule}@${f.rva}`));
            }
            grp.appendChild(row);
            allRows.push({ row, grp });
        });
        container.appendChild(grp);
    }
    const inp = bar.querySelector('input');
    inp.addEventListener('input', () => {
        const raw = inp.value.trim();
        let re = null;
        let errEl = bar.querySelector('.regex-err') || (() => { const e = document.createElement('span'); e.className = 'regex-err'; bar.appendChild(e); return e; })();
        if (raw) {
            try {
                re = new RegExp(raw, 'i');
                inp.classList.remove('invalid');
                errEl.textContent = '';
            }
            catch (ex) {
                inp.classList.add('invalid');
                errEl.textContent = ex.message;
                return;
            }
        }
        else {
            inp.classList.remove('invalid');
            errEl.textContent = '';
        }
        let visible = 0;
        const vis = new Set();
        allRows.forEach(({ row, grp }) => {
            const show = !re || re.test(row.dataset.text);
            row.style.display = show ? '' : 'none';
            if (show) {
                visible++;
                vis.add(grp);
            }
        });
        container.querySelectorAll('.finding-group').forEach(g => g.style.display = vis.has(g) ? '' : 'none');
        lbl.textContent = re ? `${visible} / ${totalFindings} findings` : `${totalFindings} findings`;
    });
}
function renderDevLogs() {
    const panel = $('panel-dev');
    if (!panel)
        return;
    panel.innerHTML = '';
    const logs = Array.isArray(st.devLogs) ? st.devLogs.slice().sort((a, b) => (b.id || 0) - (a.id || 0)) : [];
    const toolbar = document.createElement('div');
    toolbar.className = 'dev-toolbar';
    const meta = document.createElement('div');
    meta.className = 'dev-toolbar-meta';
    meta.textContent = logs.length ? `${logs.length} RESX invocation${logs.length === 1 ? '' : 's'}` : 'No RESX invocations yet';
    const copyBtn = document.createElement('button');
    copyBtn.className = 'btn-sm';
    copyBtn.textContent = 'Copy Log';
    copyBtn.disabled = !logs.length;
    copyBtn.addEventListener('click', () => {
        const text = logs.map(entry => {
            const parts = [
                `[${fmtDevTime(entry.startedAt)}]`,
                String(entry.status || 'running').toUpperCase(),
                entry.exe || 'resx',
                ...(entry.args || []),
            ];
            if (entry.durationMs != null)
                parts.push(`(${entry.durationMs} ms)`);
            if (entry.error)
                parts.push(`ERROR: ${entry.error}`);
            if (entry.stderr)
                parts.push(`STDERR: ${entry.stderr}`);
            return parts.join(' ');
        }).join('\n');
        copyText(text);
    });
    toolbar.append(meta, copyBtn);
    panel.appendChild(toolbar);
    if (!logs.length) {
        panel.appendChild(document.createRange().createContextualFragment('<p class="no-data">No RESX processes have been spawned in this viewer yet.</p>'));
        return;
    }
    const list = document.createElement('div');
    list.className = 'dev-log-list';
    logs.forEach(entry => {
        const item = document.createElement('div');
        item.className = `dev-log-item dev-log-${esc(String(entry.status || 'running'))}`;
        const header = document.createElement('div');
        header.className = 'dev-log-header';
        const status = document.createElement('span');
        status.className = `dev-log-status dev-log-status-${esc(String(entry.status || 'running'))}`;
        status.textContent = String(entry.status || 'running').toUpperCase();
        const started = document.createElement('span');
        started.className = 'dev-log-time';
        started.textContent = fmtDevTime(entry.startedAt);
        const dur = document.createElement('span');
        dur.className = 'dev-log-duration';
        dur.textContent = entry.durationMs != null ? `${entry.durationMs} ms` : 'running';
        header.append(status, started, dur);
        const cmd = document.createElement('pre');
        cmd.className = 'dev-log-cmd';
        cmd.textContent = [entry.exe || 'resx', ...(entry.args || [])].join(' ');
        item.appendChild(header);
        item.appendChild(cmd);
        if (entry.error) {
            const err = document.createElement('pre');
            err.className = 'dev-log-detail dev-log-error';
            err.textContent = entry.error;
            item.appendChild(err);
        }
        if (entry.stderr) {
            const stderr = document.createElement('pre');
            stderr.className = 'dev-log-detail';
            stderr.textContent = entry.stderr;
            item.appendChild(stderr);
        }
        list.appendChild(item);
    });
    panel.appendChild(list);
}
function renderDump(msg) {
    hideTooltip();
    if (msg.cacheKey && !msg.error)
        st.dumpCache.set(msg.cacheKey, msg);
    if (msg.prefetch)
        return;
    if (st.activeDumpRequestId && msg.requestId && msg.requestId !== st.activeDumpRequestId)
        return;
    initDumpShell();
    _updateNavUI();
    const label = msg.sourceLabel || msg.func || '?';
    const d = unwrapObjectPayload(msg.data, 'dump');
    if (msg.error || !d) {
        $('dump-header').innerHTML = `<span class="dump-fn">${esc(label)}</span>`;
        $('stab-disasm').innerHTML = '';
        $('stab-disasm').appendChild(errBox(msg.error || 'no data'));
        return;
    }
    st.currentDumpDll = d.dll || basenamePath(d.dll_path || '') || st.currentDumpDll || '';
    st.currentDumpPath = d.dll_path || st.currentDumpPath || '';
    setCurrentDepth(currentNavEntry()?.funcsDepth || st.apiDepth || 1);
    const currentSyscall = d.current_syscall || detectCurrentSyscallInfo(d, label);
    const isImportSlot = !!d.is_import_slot;
    const slotSection = isImportSlot ? findSectionForRva(d.sections || [], d.rva) : null;
    let hHtml = `<span class="dump-fn">${esc(label)}</span>`;
    if (d.rva)
        hHtml += `<span class="dump-meta">RVA ${esc(d.rva)}</span>`;
    if (slotSection?.name)
        hHtml += `<span class="dump-meta">${esc(slotSection.name)}</span>`;
    if (d.arch)
        hHtml += `<span class="dump-meta">${esc(d.arch)}</span>`;
    if (d.pdb_loaded)
        hHtml += `<span class="dump-meta">PDB ✓</span>`;
    if (currentSyscall?.service_number)
        hHtml += `<span class="dump-meta">SSN ${esc(currentSyscall.service_number)}</span>`;
    if (currentSyscall?.kernel_module && currentSyscall?.kernel_symbol)
        hHtml += `<span class="dump-meta">Kernel ${esc(currentSyscall.kernel_module)}!${esc(currentSyscall.kernel_symbol)}</span>`;
    const hdrMeta = estimateHeaderMeta(d.instructions || [], d.xrefs || []);
    if (!isImportSlot && hdrMeta.stackSize)
        hHtml += `<span class="dump-meta">Stack ${esc(hdrMeta.stackSize)}</span>`;
    hHtml += `<span class="dump-meta">Xrefs ${hdrMeta.xrefCount}</span>`;
    if (d.hook_indicators?.length)
        hHtml += `<span class="dump-hook">⚠ HOOKED: ${d.hook_indicators.map(esc).join(', ')}</span>`;
    $('dump-header').innerHTML = hHtml;
    const hasInsns = !isImportSlot && d.instructions?.length > 0;
    const hasCalls = !isImportSlot && ((d.api_calls?.length > 0) || !!currentSyscall);
    const hasXrefs = true;
    const hasStrings = !isImportSlot && d.strings?.length > 0;
    const hasCfg = !isImportSlot && d.cfg?.trim();
    const hasRecomp = !isImportSlot && d.recomp?.trim();
    const hasHex = !isImportSlot && hasInsns;
    const callArgumentNotes = buildCallArgumentNotes(d.instructions || [], d.api_calls || [], d.arch || '', d.sections || [], d.image_base || '', d.strings || []);
    const callCommentMap = buildCallCommentMap(callArgumentNotes);
    document.querySelectorAll('.stab').forEach(btn => {
        const s = btn.dataset.stab;
        const show = s === 'disasm' || (s === 'calls' && hasCalls) ||
            (s === 'xrefs' && hasXrefs) || (s === 'strings' && hasStrings) || (s === 'cfg' && hasCfg) ||
            (s === 'recomp' && hasRecomp) || (s === 'hex' && hasHex);
        btn.classList.toggle('hidden', !show);
    });
    if (hasRecomp) {
        const openBtn = document.createElement('button');
        openBtn.className = 'btn-sm';
        openBtn.textContent = 'Open Recomp';
        openBtn.title = 'Open reconstructed C in a native VS Code editor';
        openBtn.addEventListener('click', () => {
            vscode.postMessage({
                command: 'open_recomp',
                content: d.recomp,
                label,
            });
        });
        $('dump-header').appendChild(openBtn);
    }
    if (d.is_import_slot && d.import_target_name && d.import_target_dll) {
        const followBtn = document.createElement('button');
        followBtn.className = 'btn-sm';
        followBtn.textContent = `Follow ${d.import_target_dll}!${d.import_target_name}`;
        followBtn.title = 'Follow this import to the real exported function in the target module';
        followBtn.addEventListener('click', () => {
            navigate(d.import_target_name, d.import_target_dll);
        });
        $('dump-header').appendChild(followBtn);
    }
    if (currentSyscall?.kernel_module && currentSyscall?.kernel_symbol) {
        const kernelBtn = document.createElement('button');
        kernelBtn.className = 'btn-sm';
        kernelBtn.textContent = `Follow ${currentSyscall.kernel_module}!${currentSyscall.kernel_symbol}`;
        kernelBtn.title = 'Follow this syscall into the kernel implementation';
        kernelBtn.addEventListener('click', () => {
            navigate(currentSyscall.kernel_symbol, currentSyscall.kernel_module);
        });
        $('dump-header').appendChild(kernelBtn);
    }
    $('stab-disasm').innerHTML = '';
    if (isImportSlot)
        $('stab-disasm').appendChild(renderImportSlotView(d, slotSection));
    else if (hasInsns) {
        const semanticNotes = buildHeuristicInsnNotes(d.instructions || []);
        $('stab-disasm').appendChild(renderDisasmView(d.instructions, d.api_calls || [], d.dll || '', currentSyscall, d.sections || [], d.image_base || '', semanticNotes, callCommentMap, formatDisasmHeaderText(label, d, hdrMeta, currentSyscall, slotSection)));
    }
    else
        $('stab-disasm').innerHTML = '<p class="no-data">No disassembly.</p>';
    if (hasCalls) {
        const cp = $('stab-calls');
        cp.innerHTML = '';
        const toolbar = document.createElement('div');
        toolbar.className = 'calls-toolbar';
        const depthLabel = document.createElement('label');
        depthLabel.className = 'calls-depth-label';
        depthLabel.textContent = 'Depth';
        const depthSelect = document.createElement('select');
        depthSelect.className = 'calls-depth-select';
        for (let i = 1; i <= 5; i++) {
            const opt = document.createElement('option');
            opt.value = String(i);
            opt.textContent = String(i);
            opt.selected = i === st.apiDepth;
            depthSelect.appendChild(opt);
        }
        depthSelect.addEventListener('change', () => {
            const nextDepth = Math.max(1, Math.min(5, Number(depthSelect.value) || 1));
            if (nextDepth === st.apiDepth)
                return;
            setCurrentDepth(nextDepth);
            const entry = currentNavEntry();
            if (entry) {
                _showDumpLoading(entry.label);
                _requestDump(entry);
            }
        });
        depthLabel.appendChild(depthSelect);
        toolbar.appendChild(depthLabel);
        const hostileLabel = document.createElement('label');
        hostileLabel.className = 'calls-hostile-label';
        hostileLabel.title = 'Enable aggressive tracing: recursive register backward-slice, decoder-driven cross-reference scan, indirect-JMP emission, suspicion annotations';
        const hostileCheck = document.createElement('input');
        hostileCheck.type = 'checkbox';
        hostileCheck.className = 'calls-hostile-check';
        hostileCheck.checked = st.hostile;
        hostileCheck.addEventListener('change', () => {
            st.hostile = hostileCheck.checked;
            const entry = currentNavEntry();
            if (entry) {
                st.dumpCache.clear();
                _showDumpLoading(entry.label);
                _requestDump(entry);
            }
        });
        hostileLabel.appendChild(hostileCheck);
        hostileLabel.appendChild(document.createTextNode(' Hostile'));
        toolbar.appendChild(hostileLabel);
        cp.appendChild(toolbar);
        const wrap = document.createElement('div');
        wrap.className = 'tbl-wrap';
        const tbl = document.createElement('table');
        const head = tbl.createTHead();
        const hrow = head.insertRow();
        ['RVA', 'Kind', 'Label', 'DLL', 'Indirect'].forEach(l => {
            const th = document.createElement('th');
            th.textContent = l;
            th.addEventListener('click', () => sortTable(th, tbl));
            hrow.appendChild(th);
        });
        const body = tbl.createTBody();
        const treeRows = st.apiDepth > 1 && d.api_call_tree ? parseApiCallTree(d.api_call_tree) : [];
        const baseCalls = d.api_calls.map(c => ({
            depth: 0,
            rva: c.rva,
            kind: c.kind,
            label: c.label,
            dll: c.dll || '',
            indirect: [c.is_indirect ? (c.indirect_method || 'indirect') : '', c.switch_cases?.length ? `${c.switch_cases.length} cases` : '']
                .filter(Boolean)
                .join(' · '),
            notes: callArgumentNotes.get(normalizeRva(c.rva)) || [],
            target_rva: c.target_rva || '',
            syscall: c.syscall || null,
        }));
        if (currentSyscall) {
            baseCalls.unshift({
                depth: 0,
                rva: d.rva || '',
                kind: 'syscall',
                label: d.function || label,
                dll: 'ntdll.dll',
                indirect: '',
                notes: [],
                target_rva: '',
                syscall: currentSyscall,
            });
        }
        const rows = treeRows.length ? treeRows : baseCalls;
        const items = rows.map((row, index) => ({
            ...row,
            index,
            hasChildren: (rows[index + 1]?.depth || 0) > (row.depth || 0),
            collapsed: false,
        }));
        const elementGroups = new Map();
        function setGroupVisible(group, visible) {
            (group || []).forEach(el => {
                el.style.display = visible ? '' : 'none';
            });
        }
        function refreshTreeVisibility() {
            const collapsedAtDepth = [];
            items.forEach(item => {
                collapsedAtDepth.length = item.depth + 1;
                const hidden = collapsedAtDepth.slice(0, item.depth).some(Boolean);
                setGroupVisible(elementGroups.get(item.index), !hidden);
                collapsedAtDepth[item.depth] = item.collapsed;
            });
        }
        function bindToggleRow(target, item) {
            if (!item.hasChildren)
                return;
            target.classList.add('api-collapsible');
            const sync = () => {
                target.classList.toggle('api-collapsed', item.collapsed);
                target.title = item.collapsed ? 'Click to expand child calls' : 'Click to collapse child calls';
            };
            target.addEventListener('click', e => {
                if (e.target.closest('.fn-link, .api-subrow-site, .api-kernel-link .fn-link, .rva')) {
                    return;
                }
                item.collapsed = !item.collapsed;
                sync();
                refreshTreeVisibility();
            });
            sync();
        }
        items.forEach(item => {
            const c = item;
            const details = [];
            if (c.indirect) {
                details.push(c.indirect);
            }
            if (c.syscall?.service_number) {
                details.push(`SSN ${c.syscall.service_number}`);
            }
            if (!c.depth) {
                const tr = body.insertRow();
                const group = [tr];
                bindToggleRow(tr, item);
                const rtd = tr.insertCell();
                rtd.className = 'rva';
                rtd.textContent = c.rva;
                rtd.title = 'Jump to callsite RVA';
                rtd.addEventListener('click', () => navigateRva(c.rva, `callsite@${c.rva}`));
                const ktd = tr.insertCell();
                ktd.className = 'mono';
                ktd.textContent = c.kind;
                const ltd = tr.insertCell();
                ltd.className = 'api-label-cell';
                if (c.label)
                    ltd.appendChild(fnLink(c.label, c.target_rva && !c.dll ? { rva: c.target_rva } : { dll: c.dll || null }));
                if (c.syscall?.kernel_symbol && c.syscall?.kernel_module) {
                    const kernelMeta = document.createElement('div');
                    kernelMeta.className = 'api-kernel-link';
                    const kernelLink = fnLink(c.syscall.kernel_symbol, { dll: c.syscall.kernel_module });
                    kernelLink.title = `Follow into ${c.syscall.kernel_module}!${c.syscall.kernel_symbol}`;
                    kernelMeta.append('kernel ', kernelLink, ` @ ${c.syscall.kernel_rva || ''}`);
                    ltd.appendChild(kernelMeta);
                }
                const dtd = tr.insertCell();
                dtd.className = 'mono';
                dtd.textContent = c.syscall?.kernel_module || c.dll || '';
                const itd = tr.insertCell();
                if (details.length) {
                    itd.style.color = 'var(--warn)';
                    itd.textContent = details.join(' · ');
                }
                elementGroups.set(item.index, group);
            }
            else {
                const subRow = body.insertRow();
                subRow.className = 'api-subrow-outer';
                const group = [subRow];
                const subCell = subRow.insertCell();
                subCell.colSpan = 5;
                const sub = document.createElement('div');
                sub.className = 'api-subrow';
                sub.style.setProperty('--api-depth', String(c.depth));
                bindToggleRow(sub, item);
                const grid = document.createElement('div');
                grid.className = 'api-subrow-grid';
                const site = document.createElement('button');
                site.className = 'api-subrow-cell api-subrow-site';
                site.textContent = c.rva;
                site.title = 'Jump to callsite RVA';
                site.addEventListener('click', () => navigateRva(c.rva, `callsite@${c.rva}`));
                const kind = document.createElement('div');
                kind.className = 'api-subrow-cell mono';
                kind.textContent = c.kind;
                const label = document.createElement('div');
                label.className = 'api-subrow-cell api-subrow-label';
                if (c.label)
                    label.appendChild(fnLink(c.label, c.target_rva && !c.dll ? { rva: c.target_rva } : { dll: c.dll || null }));
                if (c.syscall?.kernel_symbol && c.syscall?.kernel_module) {
                    const kernelMeta = document.createElement('div');
                    kernelMeta.className = 'api-kernel-link';
                    const kernelLink = fnLink(c.syscall.kernel_symbol, { dll: c.syscall.kernel_module });
                    kernelLink.title = `Follow into ${c.syscall.kernel_module}!${c.syscall.kernel_symbol}`;
                    kernelMeta.append('kernel ', kernelLink, ` @ ${c.syscall.kernel_rva || ''}`);
                    label.appendChild(kernelMeta);
                }
                const dll = document.createElement('div');
                dll.className = 'api-subrow-cell mono';
                dll.textContent = c.syscall?.kernel_module || c.dll || '';
                const extra = document.createElement('div');
                extra.className = 'api-subrow-cell';
                if (details.length) {
                    extra.style.color = 'var(--warn)';
                    extra.textContent = details.join(' · ');
                }
                grid.append(site, kind, label, dll, extra);
                sub.append(grid);
                if (Array.isArray(c.notes) && c.notes.length) {
                    const note = document.createElement('div');
                    note.className = 'api-subrow-note';
                    note.textContent = c.notes.join(' | ');
                    sub.appendChild(note);
                }
                subCell.appendChild(sub);
                elementGroups.set(item.index, group);
            }
            if (Array.isArray(c.notes) && c.notes.length && !c.depth) {
                const noteRow = body.insertRow();
                noteRow.className = 'api-note-row';
                const noteCell = noteRow.insertCell();
                noteCell.colSpan = 5;
                noteCell.innerHTML = `<span class="api-note-indent"></span>${esc(c.notes.join(' | '))}`;
                elementGroups.get(item.index)?.push(noteRow);
            }
        });
        refreshTreeVisibility();
        wrap.appendChild(tbl);
        cp.appendChild(wrap);
    }
    if (hasXrefs) {
        const xp = $('stab-xrefs');
        xp.innerHTML = '';
        if (d.xrefs?.length) {
            const wrap = document.createElement('div');
            wrap.className = 'tbl-wrap';
            const tbl = document.createElement('table');
            const head = tbl.createTHead();
            const hrow = head.insertRow();
            ['Site', 'Kind', 'Owner', 'Target'].forEach(l => {
                const th = document.createElement('th');
                th.textContent = l;
                th.addEventListener('click', () => sortTable(th, tbl));
                hrow.appendChild(th);
            });
            const body = tbl.createTBody();
            d.xrefs.forEach(xref => {
                const parsed = parseXrefEntry(xref);
                const row = body.insertRow();
                const siteTd = row.insertCell();
                siteTd.className = 'rva';
                siteTd.textContent = parsed?.siteRva || '';
                if (parsed?.siteRva) {
                    siteTd.title = 'Open callsite in disassembly';
                    siteTd.addEventListener('click', () => {
                        st.activeDumpSubTab = 'disasm';
                        navigateRva(parsed.siteRva, parsed.owner || parsed.siteRva);
                    });
                }
                const kindTd = row.insertCell();
                kindTd.className = 'mono';
                kindTd.textContent = parsed?.kind || '';
                const ownerTd = row.insertCell();
                ownerTd.className = 'mono xref-jump';
                ownerTd.textContent = parsed?.owner || '';
                if (parsed?.siteRva) {
                    ownerTd.title = 'Open callsite in disassembly';
                    ownerTd.addEventListener('click', () => {
                        st.activeDumpSubTab = 'disasm';
                        navigateRva(parsed.siteRva, parsed.owner || parsed.siteRva);
                    });
                }
                const targetTd = row.insertCell();
                targetTd.className = 'mono';
                targetTd.textContent = parsed?.target || xref;
            });
            wrap.appendChild(tbl);
            xp.appendChild(wrap);
        }
        else {
            xp.innerHTML = '<p class="no-data">No xrefs found for this target.</p>';
        }
    }
    if (hasStrings) {
        const sp = $('stab-strings');
        sp.innerHTML = '';
        const list = document.createElement('div');
        list.className = 'str-list';
        d.strings.forEach(s => {
            const el = document.createElement('div');
            el.className = 'str-item';
            el.textContent = s;
            el.title = s;
            list.appendChild(el);
        });
        sp.appendChild(list);
    }
    if (hasCfg)
        renderCfgVisual(d.cfg, $('stab-cfg'), { cfgMnemonicClass, navigateRva, normalizeRva });
    if (hasRecomp) {
        const rp = $('stab-recomp');
        rp.innerHTML = '';
        const pre = document.createElement('pre');
        pre.className = 'pre-block';
        pre.textContent = annotateRecompText(d.recomp, d.api_calls || [], callCommentMap);
        rp.appendChild(pre);
    }
    if (hasHex) {
        const hp = $('stab-hex');
        hp.innerHTML = '';
        hp.appendChild(renderHexView(d.instructions));
    }
    restoreDumpViewState(currentNavEntry());
    if (!isImportSlot)
        prefetchCallTargets(d.api_calls || []);
}
function renderImportSlotView(d, slotSection) {
    const wrap = document.createElement('div');
    wrap.className = 'overview-grid';
    const left = document.createElement('div');
    left.className = 'kv-card';
    const title = document.createElement('div');
    title.className = 'types-section-title';
    title.textContent = 'Import Entry';
    left.appendChild(title);
    left.appendChild(kvRow('Kind', 'IAT slot'));
    if (slotSection?.name)
        left.appendChild(kvRow('Section', slotSection.name));
    if (d.rva)
        left.appendChild(kvRow('Slot RVA', d.rva));
    if (d.import_target_dll)
        left.appendChild(kvRow('Module', d.import_target_dll));
    if (d.import_target_name)
        left.appendChild(kvRow('Symbol', d.import_target_name));
    const right = document.createElement('div');
    right.className = 'kv-card';
    const noteTitle = document.createElement('div');
    noteTitle.className = 'types-section-title';
    noteTitle.textContent = '.idata View';
    right.appendChild(noteTitle);
    const note = document.createElement('div');
    note.className = 'no-data';
    note.textContent = 'This target is an import table entry in the current image. Use Xrefs to find callers, or use the Follow button above to jump to the real exported function.';
    right.appendChild(note);
    wrap.append(left, right);
    return wrap;
}
function prefetchCallTargets(apiCalls) {
    const targets = [];
    const seen = new Set();
    for (const call of apiCalls) {
        if (call.dll || !call.target_rva)
            continue;
        const rva = normalizeRva(call.target_rva);
        if (!rva || seen.has(rva))
            continue;
        seen.add(rva);
        targets.push({ rva, label: call.label || `@${rva}` });
        if (targets.length >= 24)
            break;
    }
    for (const target of targets) {
        _requestDump({ label: target.label, fn: null, dll: null, rva: target.rva }, true);
    }
}
function renderDisasmView(insns, apiCalls, imageName, currentSyscall = null, sections = [], imageBase = '', semanticNotes = new Map(), callCommentMap = new Map(), copyHeaderText = '') {
    const view = document.createElement('div');
    view.className = 'asm-view';
    view.style.setProperty('--asm-meta-width', `${st.asmMetaWidth}px`);
    const shell = document.createElement('div');
    shell.className = 'asm-shell';
    const insnPane = document.createElement('div');
    insnPane.className = 'asm-pane asm-pane-insn';
    const metaPane = document.createElement('div');
    metaPane.className = 'asm-pane asm-pane-meta';
    const insnBody = document.createElement('div');
    insnBody.className = 'asm-body';
    const flowSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    flowSvg.classList.add('asm-flow');
    const insnRows = document.createElement('div');
    insnRows.className = 'asm-rows asm-rows-insn';
    const metaRows = document.createElement('div');
    metaRows.className = 'asm-rows asm-rows-meta';
    const insnBar = document.createElement('div');
    insnBar.className = 'asm-pane-bar';
    const searchWrap = document.createElement('div');
    searchWrap.className = 'searchbar asm-searchbar';
    const searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.placeholder = 'Search disasm…';
    searchInput.autocomplete = 'off';
    searchInput.spellcheck = false;
    const searchLabel = document.createElement('span');
    searchLabel.className = 'count-lbl';
    searchWrap.append(searchInput, searchLabel);
    insnBar.appendChild(searchWrap);
    const insnCopy = document.createElement('button');
    insnCopy.className = 'asm-copy-btn';
    insnCopy.title = 'Copy function details, addresses, bytes, instructions, and comments';
    insnCopy.textContent = 'Copy';
    insnCopy.addEventListener('click', () => copyText(formatDisasmCopyText(insnRows, metaRows, copyHeaderText)));
    insnBar.appendChild(insnCopy);
    const splitter = document.createElement('div');
    splitter.className = 'asm-splitter';
    splitter.title = 'Drag to resize columns';
    const callIndex = new Map();
    apiCalls.forEach(call => {
        if (call?.rva)
            callIndex.set(normalizeRva(call.rva), call);
    });
    const insnRowByRva = new Map();
    insns.forEach(insn => {
        const leftRow = document.createElement('div');
        leftRow.className = 'asm-row asm-row-insn';
        insnRowByRva.set(normalizeRva(insn.rva), leftRow);
        const rightRow = document.createElement('div');
        rightRow.className = 'asm-row asm-row-meta';
        const metaCall = callIndex.get(normalizeRva(insn.rva));
        const lineTone = classifyAsmRow(insn, metaCall);
        if (lineTone)
            leftRow.classList.add(lineTone);
        const text = insn.text || '';
        const si = text.search(/[\s,]/);
        const mnem = si === -1 ? text : text.slice(0, si).trimEnd();
        const ops = si === -1 ? '' : text.slice(si).trimStart();
        const mnemEl = document.createElement('span');
        mnemEl.className = `asm-mnem ${mnemonicClass(mnem)}`;
        mnemEl.textContent = mnem.padEnd(10, ' ');
        const opsEl = document.createElement('span');
        opsEl.className = 'asm-ops';
        opsEl.innerHTML = highlightOperands(ops, sections, imageBase);
        wireShortAddressSpans(opsEl);
        const codeEl = document.createElement('div');
        codeEl.className = 'asm-code';
        codeEl.append(mnemEl, opsEl);
        leftRow.appendChild(codeEl);
        const isSyscallInsn = /^syscall$/i.test(String(insn.text || '').trim())
            || /^sysenter$/i.test(String(insn.text || '').trim())
            || /^int\s+2Eh$/i.test(String(insn.text || '').trim());
        const semantic = semanticNotes.get(normalizeRva(insn.rva));
        const callSummary = callCommentMap.get(normalizeRva(insn.rva));
        if (insn.comment || metaCall?.target_rva || metaCall?.dll || semantic || (isSyscallInsn && currentSyscall?.kernel_symbol)) {
            const cmtEl = document.createElement('span');
            cmtEl.className = 'asm-cmt';
            if (isSyscallInsn && currentSyscall?.kernel_symbol && currentSyscall?.kernel_module) {
                cmtEl.innerHTML = '; ';
                if (currentSyscall.service_number) {
                    const ssn = document.createElement('span');
                    ssn.className = 'asm-syscall-inline';
                    ssn.textContent = `SSN ${currentSyscall.service_number}`;
                    cmtEl.appendChild(ssn);
                    cmtEl.append(' -> ');
                }
                const kernelLink = document.createElement('span');
                kernelLink.className = 'cmt-link cmt-link-import';
                kernelLink.textContent = `${currentSyscall.kernel_module}!${currentSyscall.kernel_symbol}`;
                kernelLink.title = `Follow into ${currentSyscall.kernel_module}!${currentSyscall.kernel_symbol}`;
                kernelLink.addEventListener('click', () => navigate(currentSyscall.kernel_symbol, currentSyscall.kernel_module));
                cmtEl.appendChild(kernelLink);
                if (currentSyscall.kernel_rva) {
                    const rva = document.createElement('span');
                    rva.className = 'asm-syscall-inline';
                    rva.textContent = ` @ ${currentSyscall.kernel_rva}`;
                    cmtEl.appendChild(rva);
                }
                codeEl.appendChild(cmtEl);
            }
            else {
                const target = metaCall?.target_rva
                    ? {
                        func: stripScopedName(metaCall.label || insn.comment),
                        dll: sameImageModule(metaCall.dll, imageName) ? null : (metaCall.dll || null),
                        rva: metaCall.target_rva,
                    }
                    : parseCommentTarget(insn.comment, imageName);
                const resolvedLabel = metaCall?.dll
                    ? `${metaCall.dll}!${normalizeImportName(metaCall.label || insn.comment || '')}`
                    : (metaCall?.label && metaCall?.target_rva && !metaCall?.dll)
                        ? `${imageName || 'current'}!${stripScopedName(metaCall.label)}`
                        : (insn.comment || '');
                if (target) {
                    cmtEl.innerHTML = '; ';
                    const link = document.createElement('span');
                    link.className = `cmt-link ${metaCall?.dll ? 'cmt-link-import' : (metaCall?.target_rva ? 'cmt-link-internal' : '')}`.trim();
                    link.textContent = resolvedLabel || String(target.rva || target.func || '');
                    link.title = target.dll
                        ? `Imported call: ${target.dll}!${target.func}`
                        : metaCall?.target_rva
                            ? `Internal call: ${(imageName || 'current')}!${target.func}`
                            : `Navigate to ${target.rva || target.func}`;
                    link.addEventListener('click', () => {
                        if (target.rva && !target.dll)
                            navigateRva(target.rva, target.func || target.rva);
                        else
                            navigate(target.func, target.dll);
                    });
                    cmtEl.appendChild(link);
                    if (callSummary) {
                        cmtEl.append(` ; ${callSummary}`);
                    }
                    if (semantic && !String(cmtEl.textContent || '').includes(semantic)) {
                        cmtEl.append(` ; ${semantic}`);
                    }
                }
                else {
                    const rawComment = resolvedLabel || insn.comment || '';
                    const typeRefMatch = rawComment.match(/^(.*)\(([A-Za-z_][A-Za-z0-9_*[\] :<>]*)\)\s*$/);
                    const candidateType = typeRefMatch ? typeRefMatch[2].trim().replace(/\s*[*[\]]+\s*$/, '').trim() : null;
                    const typeEntry = candidateType && st.typesByName.size > 0
                        ? (st.typesByName.get(candidateType.toLowerCase()) || st.typesByName.get(canonicalTypeName(candidateType)))
                        : null;
                    if (typeEntry) {
                        cmtEl.innerHTML = `; ${shortenAddressMarkup(typeRefMatch[1].trim(), sections, imageBase)} `;
                        wireShortAddressSpans(cmtEl);
                        const typeLink = document.createElement('span');
                        typeLink.className = 'cmt-link cmt-link-type';
                        typeLink.textContent = `(${candidateType})`;
                        typeLink.title = `${typeEntry.kind} · ${typeEntry.size}B · ${typeEntry.members?.length || 0} member(s) — navigate to Types`;
                        typeLink.addEventListener('click', () => {
                            st._pendingTypeNav = candidateType.toLowerCase();
                            activateTab('types');
                        });
                        cmtEl.appendChild(typeLink);
                    }
                    else {
                        cmtEl.innerHTML = `; ${shortenAddressMarkup(rawComment, sections, imageBase)}`;
                        wireShortAddressSpans(cmtEl);
                    }
                    if (callSummary && !String(cmtEl.textContent || '').includes(callSummary)) {
                        cmtEl.append(` ; ${callSummary}`);
                    }
                    if (semantic) {
                        const merged = composeSemanticComment(cmtEl.textContent || '', semantic);
                        cmtEl.textContent = merged ? `; ${merged}` : '';
                    }
                }
                codeEl.appendChild(cmtEl);
            }
        }
        const rvaEl = document.createElement('span');
        rvaEl.className = 'asm-rva';
        rvaEl.textContent = insn.rva;
        const bytesEl = document.createElement('span');
        bytesEl.className = 'asm-bytes';
        bytesEl.textContent = insn.bytes;
        rightRow.append(rvaEl, bytesEl);
        insnRows.appendChild(leftRow);
        metaRows.appendChild(rightRow);
    });
    const main = document.createElement('div');
    main.className = 'asm-main';
    insnBody.append(flowSvg, insnRows);
    insnPane.append(insnBar, insnBody);
    metaPane.append(metaRows);
    shell.append(insnPane, splitter, metaPane);
    main.append(shell);
    view.appendChild(main);
    wireDisasmSearch(searchInput, searchLabel, insnRows, metaRows);
    wireAsmPaneSync(insnPane, metaPane);
    wireAsmSplitter(view, splitter);
    wireAsmFlow(view, insnPane, insnBody, flowSvg, insns, apiCalls, imageName, insnRowByRva);
    return view;
}
function collectAsmFlowEdges(insns, apiCalls, imageName, rowByRva) {
    const callIndex = new Map();
    const rowList = insns.map(insn => normalizeRva(insn?.rva)).filter(Boolean);
    const rowIndex = new Map(rowList.map((rva, idx) => [rva, idx]));
    (apiCalls || []).forEach(call => {
        if (call?.rva)
            callIndex.set(normalizeRva(call.rva), call);
    });
    const edges = [];
    for (const insn of insns || []) {
        const srcRva = normalizeRva(insn?.rva);
        if (!srcRva || !rowByRva.has(srcRva))
            continue;
        const text = String(insn?.text || '').trim().toLowerCase();
        const mnemonic = text.split(/\s+/, 1)[0] || '';
        const metaCall = callIndex.get(srcRva);
        let targetRva = '';
        let kind = '';
        if (metaCall?.target_rva && !metaCall?.dll) {
            targetRva = normalizeRva(metaCall.target_rva);
            kind = text.startsWith('call ') ? 'call' : (JCC_MNEMS.has(mnemonic) ? 'jcc' : 'jump');
        }
        else {
            const parsed = parseCommentTarget(insn?.comment, imageName);
            if (parsed?.rva) {
                targetRva = normalizeRva(parsed.rva);
                if (text.startsWith('call '))
                    kind = 'call';
                else if (text.startsWith('jmp '))
                    kind = 'jump';
                else if (JCC_MNEMS.has(mnemonic))
                    kind = 'jcc';
            }
        }
        if (!targetRva || !rowByRva.has(targetRva) || targetRva === srcRva || !kind)
            continue;
        const srcIdx = rowIndex.get(srcRva);
        const dstIdx = rowIndex.get(targetRva);
        if (srcIdx == null || dstIdx == null)
            continue;
        edges.push({
            srcRva,
            targetRva,
            kind,
            srcIdx,
            dstIdx,
            start: Math.min(srcIdx, dstIdx),
            end: Math.max(srcIdx, dstIdx),
            span: Math.abs(dstIdx - srcIdx),
            dir: dstIdx > srcIdx ? 'down' : 'up',
        });
    }
    return edges;
}
function assignAsmFlowLanes(edges) {
    const sorted = [...edges].sort((a, b) => a.span - b.span
        || (a.kind === 'jcc' ? -1 : 0) - (b.kind === 'jcc' ? -1 : 0)
        || a.start - b.start
        || a.srcIdx - b.srcIdx);
    const lanes = [];
    for (const edge of sorted) {
        let lane = 0;
        for (; lane < lanes.length; lane++) {
            const conflict = lanes[lane].some(other => !(edge.end < other.start || edge.start > other.end));
            if (!conflict)
                break;
        }
        if (!lanes[lane])
            lanes[lane] = [];
        lanes[lane].push(edge);
        edge.lane = lane;
    }
    return { edges: sorted, laneCount: lanes.length };
}
function wireAsmFlow(view, insnPane, insnBody, flowSvg, insns, apiCalls, imageName, rowByRva) {
    const render = () => {
        const rawEdges = collectAsmFlowEdges(insns, apiCalls, imageName, rowByRva);
        const { edges, laneCount } = assignAsmFlowLanes(rawEdges);
        const width = Math.max(56, 28 + laneCount * 12);
        const height = Math.max(insnRowsHeight(insnRowsFromBody(insnBody)), insnBody.scrollHeight || 0);
        flowSvg.setAttribute('width', String(width));
        flowSvg.setAttribute('height', String(height));
        flowSvg.setAttribute('viewBox', `0 0 ${width} ${height}`);
        flowSvg.innerHTML = '';
        flowSvg.style.width = `${width}px`;
        insnBody.style.setProperty('--asm-flow-width', `${width}px`);
        for (const edge of edges) {
            const src = rowByRva.get(edge.srcRva);
            const dst = rowByRva.get(edge.targetRva);
            if (!src || !dst)
                continue;
            const y1 = src.offsetTop + Math.max(8, Math.floor(src.offsetHeight / 2));
            const y2 = dst.offsetTop + Math.max(8, Math.floor(dst.offsetHeight / 2));
            const rightX = width - 8;
            const laneX = rightX - 10 - edge.lane * 12;
            const color = edge.kind === 'call'
                ? 'rgba(78,201,176,.95)'
                : edge.kind === 'jcc'
                    ? 'rgba(220,220,170,.98)'
                    : 'rgba(86,156,214,.95)';
            const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            path.setAttribute('d', `M ${rightX} ${y1} H ${laneX} V ${y2} H ${rightX - 2}`);
            path.setAttribute('fill', 'none');
            path.setAttribute('stroke', color);
            path.setAttribute('stroke-width', edge.kind === 'call' ? '1.8' : edge.kind === 'jcc' ? '1.6' : '1.4');
            path.setAttribute('stroke-linecap', 'round');
            path.setAttribute('stroke-linejoin', 'round');
            path.setAttribute('opacity', edge.kind === 'call' ? '0.78' : '0.96');
            flowSvg.appendChild(path);
            const arrow = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            arrow.setAttribute('d', `M ${rightX - 2} ${y2} l -6 -4 v 8 z`);
            arrow.setAttribute('fill', color);
            flowSvg.appendChild(arrow);
        }
    };
    const schedule = () => requestAnimationFrame(render);
    schedule();
    insnPane.addEventListener('scroll', schedule);
    const resizeObs = new ResizeObserver(schedule);
    resizeObs.observe(insnPane);
    resizeObs.observe(insnBody);
}
function insnRowsFromBody(insnBody) {
    return insnBody.querySelector('.asm-rows-insn');
}
function insnRowsHeight(rows) {
    return rows instanceof HTMLElement ? rows.scrollHeight : 0;
}
function wireAsmPaneSync(leftPane, rightPane) {
    let syncing = false;
    const sync = (src, dst) => {
        if (syncing)
            return;
        syncing = true;
        dst.scrollTop = src.scrollTop;
        syncing = false;
    };
    leftPane.addEventListener('scroll', () => sync(leftPane, rightPane));
    rightPane.addEventListener('scroll', () => sync(rightPane, leftPane));
}
function extractPaneText(node) {
    return Array.from(node.querySelectorAll('.asm-row'))
        .map(row => row.textContent || '')
        .join('\n')
        .trim();
}
function extractPanelText(node) {
    if (!(node instanceof HTMLElement))
        return '';
    return String(node.textContent || '')
        .replace(/\r/g, '')
        .replace(/[ \t]+\n/g, '\n')
        .replace(/\n{3,}/g, '\n\n')
        .trim();
}
function extractDisasmText(insnRows, metaRows) {
    const leftRows = Array.from(insnRows.querySelectorAll('.asm-row'));
    const rightRows = Array.from(metaRows.querySelectorAll('.asm-row'));
    return leftRows.map((row, idx) => {
        const metaRow = rightRows[idx];
        const rva = metaRow?.querySelector('.asm-rva')?.textContent?.trim() || '';
        const bytes = metaRow?.querySelector('.asm-bytes')?.textContent?.trim() || '';
        const code = row.textContent?.trim() || '';
        return [rva, bytes, code].filter(Boolean).join('  ');
    }).join('\n').trim();
}
function formatDisasmCopyText(insnRows, metaRows, headerText = '') {
    const body = extractDisasmText(insnRows, metaRows);
    return [String(headerText || '').trim(), body].filter(Boolean).join('\n\n').trim();
}
function collectDumpExportText() {
    const title = currentNavEntry()?.label || 'dump';
    const header = extractPanelText($('dump-header'));
    if (st.activeDumpSubTab === 'disasm') {
        const panel = $('stab-disasm');
        const insnRows = panel?.querySelector('.asm-rows-insn');
        const metaRows = panel?.querySelector('.asm-rows-meta');
        if (insnRows instanceof HTMLElement && metaRows instanceof HTMLElement) {
            return {
                title: `${title}-disasm`,
                content: formatDisasmCopyText(insnRows, metaRows, header),
            };
        }
    }
    const activePanel = $(`stab-${st.activeDumpSubTab}`);
    return {
        title: `${title}-${st.activeDumpSubTab}`,
        content: [header, extractPanelText(activePanel)].filter(Boolean).join('\n\n').trim(),
    };
}
function exportCurrentView() {
    let title = st.activeTopTab || 'overview';
    let content = '';
    if (st.activeTopTab === 'dump') {
        const dumpExport = collectDumpExportText();
        title = dumpExport.title;
        content = dumpExport.content;
    }
    else {
        const panel = $(`panel-${st.activeTopTab}`);
        content = extractPanelText(panel);
    }
    if (!content)
        return;
    vscode.postMessage({
        command: 'open_text_report',
        title,
        content,
        language: 'text',
    });
}
function formatDisasmHeaderText(label, d, hdrMeta, currentSyscall = null, slotSection = null) {
    const insns = Array.isArray(d?.instructions) ? d.instructions : [];
    const stack = summarizeStack(insns);
    const regs = summarizeRegisters(insns);
    const lines = [`Function: ${label}`];
    if (d?.dll)
        lines.push(`Module: ${d.dll}`);
    if (d?.rva)
        lines.push(`RVA: ${d.rva}`);
    if (slotSection?.name)
        lines.push(`Section: ${slotSection.name}`);
    if (d?.arch)
        lines.push(`Arch: ${d.arch}`);
    if (d?.pdb_loaded)
        lines.push('Symbols: PDB loaded');
    if (hdrMeta?.stackSize)
        lines.push(`Stack: ${hdrMeta.stackSize}`);
    if (stack.shadowSpace)
        lines.push('Shadow Space: present');
    if (regs.length)
        lines.push(`Registers: ${regs.map(reg => `${reg.reg}=${reg.summary}`).join(' | ')}`);
    if (stack.items.length)
        lines.push(`Stack Slots: ${stack.items.map(item => `${item.slot}=${item.value}`).join(' | ')}`);
    if (hdrMeta?.xrefCount != null)
        lines.push(`Xrefs: ${hdrMeta.xrefCount}`);
    if (currentSyscall?.service_number != null)
        lines.push(`SSN: ${currentSyscall.service_number}`);
    if (currentSyscall?.kernel_module && currentSyscall?.kernel_symbol) {
        const kernelTarget = `${currentSyscall.kernel_module}!${currentSyscall.kernel_symbol}${currentSyscall.kernel_rva ? ` @ ${currentSyscall.kernel_rva}` : ''}`;
        lines.push(`Kernel: ${kernelTarget}`);
    }
    if (Array.isArray(d?.hook_indicators) && d.hook_indicators.length)
        lines.push(`Hooks: ${d.hook_indicators.join(', ')}`);
    return lines.join('\n').trim();
}
function wireDisasmSearch(input, label, insnRows, metaRows) {
    const leftRows = Array.from(insnRows.querySelectorAll('.asm-row'));
    const rightRows = Array.from(metaRows.querySelectorAll('.asm-row'));
    const update = () => {
        const raw = input.value.trim();
        let re = null;
        let errEl = input.parentElement?.querySelector('.regex-err');
        if (!errEl) {
            errEl = document.createElement('span');
            errEl.className = 'regex-err';
            input.parentElement?.appendChild(errEl);
        }
        if (raw) {
            try {
                re = new RegExp(raw, 'i');
                input.classList.remove('invalid');
                errEl.textContent = '';
            }
            catch (ex) {
                input.classList.add('invalid');
                errEl.textContent = ex instanceof Error ? ex.message : String(ex);
                return;
            }
        }
        else {
            input.classList.remove('invalid');
            errEl.textContent = '';
        }
        let matches = 0;
        leftRows.forEach((row, idx) => {
            const metaRow = rightRows[idx];
            const hit = !!re && re.test(`${row.textContent || ''} ${metaRow?.textContent || ''}`);
            row.classList.toggle('asm-search-hit', hit);
            metaRow?.classList.toggle('asm-search-hit', hit);
            if (hit)
                matches++;
        });
        label.textContent = re ? `${matches} hit${matches === 1 ? '' : 's'}` : '';
    };
    input.addEventListener('input', update);
    input.addEventListener('keydown', evt => {
        if (evt.key !== 'Enter')
            return;
        const hit = insnRows.querySelector('.asm-row.asm-search-hit');
        if (hit instanceof HTMLElement)
            hit.scrollIntoView({ block: 'center' });
    });
    update();
}
function classifyAsmRow(insn, metaCall) {
    const text = String(insn.text || '').toLowerCase();
    const isCall = text.startsWith('call ');
    const isJump = text.startsWith('jmp ') || JCC_MNEMS.has(text.split(/\s+/, 1)[0] || '');
    const rawText = String(insn.text || '');
    const isLeaSymbolic = /^lea\s+\w+,\s*\[[^\]]*[A-Za-z_][A-Za-z0-9_]*[^\]]*\]$/i.test(rawText);
    const isMovSymbolicLoad = /^mov\s+\w+,\s*(?:qword|dword|word|byte)?\s*ptr\s*\[[^\]]*(?:rip|[A-Za-z_][A-Za-z0-9_]*)[^\]]*\]$/i.test(rawText);
    const isAbsoluteImmediateLoad = /^mov\s+\w+,\s*0x[0-9a-f]+$/i.test(rawText);
    const hasAddressishComment = /(0x[0-9a-f]{4,}|[A-Za-z0-9_.]+![A-Za-z0-9_@$]+|[A-Za-z0-9_.]+\.[A-Za-z0-9_@$]+|\([^)]+\)|\bdata\b)/i.test(String(insn.comment || ''));
    const loadsAddress = isLeaSymbolic || isMovSymbolicLoad || isAbsoluteImmediateLoad;
    if (metaCall?.dll)
        return 'asm-row-call-import';
    if (metaCall?.target_rva)
        return 'asm-row-call-internal';
    if (isCall || metaCall)
        return 'asm-row-call';
    if (isJump)
        return 'asm-row-jump';
    if (loadsAddress || hasAddressishComment)
        return 'asm-row-address';
    return '';
}
function wireAsmSplitter(view, splitter) {
    let dragging = false;
    const minMeta = 160;
    const maxMeta = 520;
    const setWidthFromClientX = clientX => {
        const rect = view.getBoundingClientRect();
        const next = Math.max(minMeta, Math.min(maxMeta, rect.right - clientX));
        st.asmMetaWidth = Math.round(next);
        view.style.setProperty('--asm-meta-width', `${st.asmMetaWidth}px`);
        persistUiState();
    };
    splitter.addEventListener('mousedown', e => {
        e.preventDefault();
        dragging = true;
        document.body.classList.add('asm-resizing');
    });
    window.addEventListener('mousemove', e => {
        if (!dragging)
            return;
        setWidthFromClientX(e.clientX);
    });
    window.addEventListener('mouseup', () => {
        if (!dragging)
            return;
        dragging = false;
        document.body.classList.remove('asm-resizing');
    });
}
function highlightOperands(raw, sections = [], imageBase = '') {
    if (!raw)
        return '';
    let ops = raw.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    ops = ops.replace(/\b(BYTE|WORD|DWORD|QWORD|XMMWORD|YMMWORD|ZMMWORD|TWORD|OWORD)\s+PTR\b/g, '<span class="asm-size">$1 PTR</span>');
    ops = ops.replace(/\b(__?imp_\w+)\b/g, '<span class="asm-imp">$1</span>');
    ops = ops.replace(/\b(0[xX][0-9A-Fa-f]+|[0-9A-Fa-f]+h)\b/g, '<span class="asm-imm">$1</span>');
    ops = ops.replace(/<span class="asm-imm">(0[xX][0-9A-Fa-f]+|[0-9A-Fa-f]+h)<\/span>/g, (_, rawHex) => {
        const shortened = shortenAddressForImage(rawHex, sections, imageBase);
        if (!shortened)
            return `<span class="asm-imm">${rawHex}</span>`;
        return `<span class="asm-imm asm-addr-short" data-raw="${esc(shortened.raw)}" data-short="${esc(shortened.short)}">${esc(shortened.short)}</span>`;
    });
    ops = ops.replace(/\b([re]?(?:ax|bx|cx|dx|si|di|bp|sp)|r(?:[8-9]|1[0-5])(?:d|w|b)?|[abcd][lh]|rip|eip|xmm\d+|ymm\d+|zmm\d+)\b/gi, '<span class="asm-reg">$1</span>');
    ops = ops.replace(/\b([A-Z][A-Za-z0-9_]{3,})\b/g, (m) => REGS.has(m.toLowerCase()) ? m : `<span class="asm-sym">${m}</span>`);
    return ops;
}
function parseCommentTarget(comment, imageName = '') {
    comment = String(comment || '').trim();
    const bang = comment.match(/^([A-Za-z0-9_.]+)!([A-Za-z0-9_@$]+)/);
    if (bang) {
        const target = resolveNavigationTarget(bang[2], bang[1]);
        return {
            dll: sameImageModule(target.dll, imageName) ? null : target.dll,
            func: target.func,
            rva: null,
        };
    }
    const fwd = comment.match(/^([A-Za-z0-9_.]+)\.([A-Za-z0-9_@$]+)/);
    if (fwd) {
        const target = resolveNavigationTarget(fwd[2], fwd[1]);
        return {
            dll: sameImageModule(target.dll, imageName) ? null : target.dll,
            func: target.func,
            rva: null,
        };
    }
    const sym = comment.match(/^([A-Za-z_][A-Za-z0-9_@$]{2,})$/);
    if (sym) {
        const target = resolveNavigationTarget(sym[1], null);
        return { func: target.func, dll: target.dll, rva: null };
    }
    return null;
}
function renderHexView(insns) {
    const view = document.createElement('div');
    view.className = 'hex-view';
    const allBytes = [];
    const startRva = normalizeRva(insns?.[0]?.rva || '0x0');
    const startOffset = parseHexValue(startRva) || 0;
    insns.forEach(insn => insn.bytes.split(' ').forEach(b => {
        const v = parseInt(b, 16);
        if (!isNaN(v))
            allBytes.push(v);
    }));
    const W = 16;
    for (let off = 0; off < allBytes.length; off += W) {
        const chunk = allBytes.slice(off, off + W);
        const row = document.createElement('div');
        row.className = 'hex-row';
        const offEl = document.createElement('span');
        offEl.className = 'hex-off';
        offEl.textContent = `0x${(startOffset + off).toString(16).padStart(8, '0').toUpperCase()}:  `;
        const hexParts = chunk.map(b => b.toString(16).padStart(2, '0').toUpperCase());
        while (hexParts.length < W)
            hexParts.push('  ');
        const hexEl = document.createElement('span');
        hexEl.className = 'hex-hex';
        hexEl.textContent = hexParts.slice(0, 8).join(' ') + '  ' + hexParts.slice(8).join(' ') + '  ';
        const ascEl = document.createElement('span');
        ascEl.className = 'hex-asc';
        ascEl.textContent = chunk.map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('');
        row.append(offEl, hexEl, ascEl);
        view.appendChild(row);
    }
    return view;
}
