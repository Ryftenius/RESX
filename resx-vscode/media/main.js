import { renderCfgVisual } from './cfg.js';
import { createSearchBar as _searchBar, wireSearch as _wireSearch, sortTable } from './tables.js';
'use strict';
const vscode = acquireVsCodeApi();
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
const st = {
    navHistory: [],
    navPos: -1,
    dumpCache: new Map(),
    activeDumpRequestId: null,
    activeTopTab: 'overview',
    activeDumpSubTab: 'disasm',
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
    currentDumpDll: '',
    currentDumpPath: '',
    apiDepth: 1,
    devLogs: [],
    _lastHovered: null,
};
const $ = id => document.getElementById(id);
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
    if (entry?.rva)
        return `rva:${scope}:${normalizeRva(entry.rva)}:depth:${depth}`;
    const dll = entry?.dll ? String(entry.dll).toLowerCase() : '';
    const fn = entry?.fn ? String(entry.fn).toLowerCase() : '';
    return `fn:${scope}:${dll}!${fn}:depth:${depth}`;
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
    const target = parseHexValue(rva);
    if (!Number.isFinite(target))
        return null;
    for (const sec of sections || []) {
        const start = parseHexValue(sec.rva);
        const size = Math.max(parseHexValue(sec.virtual_size), parseHexValue(sec.raw_size));
        if (!Number.isFinite(start) || !Number.isFinite(size))
            continue;
        if (target >= start && target < start + size)
            return sec;
    }
    return null;
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
    });
});
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
function _navPush(entry) {
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
    st.navPos--;
    _replayNav(st.navHistory[st.navPos]);
}
function navFwd() {
    if (st.navPos >= st.navHistory.length - 1)
        return;
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
    const kind = raw.match(/^(CALL|JMP)\b/);
    const owner = raw.match(/^(?:CALL|JMP)\s+(.+?)\s+\[site\b/);
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
}
function renderPeInfo(msg) {
    if (msg.error || !msg.data) {
        $('panel-overview').appendChild(errBox(msg.error || 'peinfo returned no data'));
        $('panel-sections').appendChild(errBox(msg.error || 'no data'));
        return;
    }
    const d = msg.data;
    st.currentDumpDll = d.dll || basenamePath(d.dll_path || '') || '';
    st.currentDumpPath = d.dll_path || '';
    if (d.entry_point)
        st.entryPoint = d.entry_point;
    renderOverview(d);
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
    if (d.entry_point) {
        const epBtn = document.createElement('button');
        epBtn.className = 'btn-sm';
        epBtn.textContent = `EP ${d.entry_point}`;
        epBtn.title = 'Disassemble entry point';
        epBtn.style.marginLeft = 'auto';
        epBtn.addEventListener('click', () => navigateRva(d.entry_point, `entry_point@${d.entry_point}`));
        hdr.appendChild(epBtn);
    }
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
    [['Image Base', d.image_base], ['Entry Point', d.entry_point],
        ['Image Size', d.size_of_image], ['Sec Align', d.section_alignment],
        ['File Align', d.file_alignment], ['Checksum', d.checksum]]
        .forEach(([k, v]) => addr.body.appendChild(kvRow(k, v)));
    grid.appendChild(addr.card);
    const cnts = _card('Tables');
    [['Exports', d.export_count], ['Import DLLs', d.import_dll_count], ['Imports', d.import_count]]
        .forEach(([k, v]) => cnts.body.appendChild(kvRow(k, v)));
    grid.appendChild(cnts.card);
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
    if (msg.error || !msg.data) {
        panel.appendChild(errBox(msg.error || 'No export data'));
        return;
    }
    const exports = msg.data;
    if (!exports.length) {
        panel.innerHTML = '<p class="no-data">No exports.</p>';
        return;
    }
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
        if (e.name)
            ntd.appendChild(fnLink(e.name));
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
    if (msg.error || !msg.data) {
        panel.appendChild(errBox(msg.error || 'No import data'));
        return;
    }
    const dlls = msg.data;
    if (!dlls.length) {
        panel.innerHTML = '<p class="no-data">No imports.</p>';
        return;
    }
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
                    link.addEventListener('click', () => navigateRva(imp.slot_rva, `${d.dll}!#${imp.ordinal}`));
                    link.addEventListener('dblclick', () => navigateRva(imp.slot_rva, `${d.dll}!#${imp.ordinal}`));
                }
                ntd.appendChild(link);
            }
            else if (imp.slot_rva) {
                const link = fnLink(imp.name, { rva: imp.slot_rva });
                link.title = `Open ${d.dll}!${imp.name} import entry in the current image`;
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
    if (msg.error || !msg.data?.length) {
        panel.innerHTML = '<p class="no-data">No symbols. Use ⚙ Symbols to configure PDB paths and reload.</p>';
        if (msg.error)
            panel.insertAdjacentElement('afterbegin', errBox(msg.error));
        return;
    }
    const syms = msg.data;
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
        ntd.appendChild(fnLink(s.name, { rva: s.rva }));
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
    if (msg.error || !msg.data?.length) {
        panel.innerHTML = '<p class="no-data">No PDB-backed types found.</p>';
        if (msg.error)
            panel.insertAdjacentElement('afterbegin', errBox(msg.error));
        return;
    }
    const types = msg.data;
    const byId = new Map(types.map(entry => [entry.type_id, entry]));
    const byName = new Map();
    types.forEach(entry => {
        rememberTypeEntry(byName, String(entry.name || '').trim().toLowerCase(), entry);
        rememberTypeEntry(byName, canonicalTypeName(entry.name), entry);
    });
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
    renderList(types);
}
function renderTriage(msg) {
    const panel = $('panel-triage');
    panel.innerHTML = '';
    if (msg.error || !msg.data) {
        panel.appendChild(errBox(msg.error || 'No triage data'));
        return;
    }
    const findings = msg.data.intelli_findings || [];
    if (!findings.length) {
        panel.innerHTML = '<p class="no-data">No triage findings.</p>';
        return;
    }
    const grouped = {};
    findings.forEach(f => { (grouped[f.category] = grouped[f.category] || []).push(f); });
    const { bar, lbl } = _searchBar(panel, 'Regex search findings…');
    lbl.textContent = `${findings.length} findings`;
    const container = document.createElement('div');
    panel.appendChild(container);
    const allRows = [];
    for (const [cat, items] of Object.entries(grouped)) {
        const grp = document.createElement('div');
        grp.className = 'finding-group';
        const title = document.createElement('div');
        title.className = 'finding-group-title';
        title.innerHTML = `${esc(cat)} <span class="tag">${items.length}</span>`;
        grp.appendChild(title);
        items.forEach(f => {
            const row = document.createElement('div');
            row.className = 'finding-row';
            row.dataset.text = `${f.category} ${f.rule} ${f.source} ${f.value}`.toLowerCase();
            row.innerHTML = `<span class="finding-rule">${esc(f.rule)}</span><span class="finding-source">${esc(f.source)}</span><span class="finding-val">${esc(f.value)}</span>`;
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
        lbl.textContent = re ? `${visible} / ${findings.length} findings` : `${findings.length} findings`;
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
    if (msg.error || !msg.data) {
        $('dump-header').innerHTML = `<span class="dump-fn">${esc(label)}</span>`;
        $('stab-disasm').innerHTML = '';
        $('stab-disasm').appendChild(errBox(msg.error || 'no data'));
        return;
    }
    const d = msg.data;
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
    else if (hasInsns)
        $('stab-disasm').appendChild(renderDisasmView(d.instructions, d.api_calls || [], d.dll || '', currentSyscall));
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
            notes: [],
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
        pre.textContent = d.recomp;
        rp.appendChild(pre);
    }
    if (hasHex) {
        const hp = $('stab-hex');
        hp.innerHTML = '';
        hp.appendChild(renderHexView(d.instructions));
    }
    activateDumpSubTab(st.activeDumpSubTab);
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
function renderDisasmView(insns, apiCalls, imageName, currentSyscall = null) {
    const view = document.createElement('div');
    view.className = 'asm-view';
    view.style.setProperty('--asm-meta-width', '280px');
    const shell = document.createElement('div');
    shell.className = 'asm-shell';
    const insnPane = document.createElement('div');
    insnPane.className = 'asm-pane asm-pane-insn';
    const metaPane = document.createElement('div');
    metaPane.className = 'asm-pane asm-pane-meta';
    const insnRows = document.createElement('div');
    insnRows.className = 'asm-rows asm-rows-insn';
    const metaRows = document.createElement('div');
    metaRows.className = 'asm-rows asm-rows-meta';
    const insnBar = document.createElement('div');
    insnBar.className = 'asm-pane-bar';
    const insnCopy = document.createElement('button');
    insnCopy.className = 'asm-copy-btn';
    insnCopy.title = 'Copy instructions and comments';
    insnCopy.textContent = 'Copy';
    insnCopy.addEventListener('click', () => copyText(extractPaneText(insnRows)));
    insnBar.appendChild(insnCopy);
    const splitter = document.createElement('div');
    splitter.className = 'asm-splitter';
    splitter.title = 'Drag to resize columns';
    const callIndex = new Map();
    apiCalls.forEach(call => {
        if (call?.rva)
            callIndex.set(normalizeRva(call.rva), call);
    });
    insns.forEach(insn => {
        const leftRow = document.createElement('div');
        leftRow.className = 'asm-row asm-row-insn';
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
        opsEl.innerHTML = highlightOperands(ops);
        const codeEl = document.createElement('div');
        codeEl.className = 'asm-code';
        codeEl.append(mnemEl, opsEl);
        leftRow.appendChild(codeEl);
        const isSyscallInsn = /^syscall$/i.test(String(insn.text || '').trim())
            || /^sysenter$/i.test(String(insn.text || '').trim())
            || /^int\s+2Eh$/i.test(String(insn.text || '').trim());
        if (insn.comment || metaCall?.target_rva || metaCall?.dll || (isSyscallInsn && currentSyscall?.kernel_symbol)) {
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
                }
                else {
                    cmtEl.textContent = `; ${resolvedLabel || insn.comment}`;
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
    insnPane.append(insnBar, insnRows);
    metaPane.append(metaRows);
    shell.append(insnPane, splitter, metaPane);
    main.append(shell);
    view.appendChild(main);
    wireAsmPaneSync(insnPane, metaPane);
    wireAsmSplitter(view, splitter);
    return view;
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
        view.style.setProperty('--asm-meta-width', `${Math.round(next)}px`);
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
function highlightOperands(raw) {
    if (!raw)
        return '';
    let ops = raw.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    ops = ops.replace(/\b(BYTE|WORD|DWORD|QWORD|XMMWORD|YMMWORD|ZMMWORD|TWORD|OWORD)\s+PTR\b/g, '<span class="asm-size">$1 PTR</span>');
    ops = ops.replace(/\b(__?imp_\w+)\b/g, '<span class="asm-imp">$1</span>');
    ops = ops.replace(/\b(0[xX][0-9A-Fa-f]+)\b/g, '<span class="asm-imm">$1</span>');
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
