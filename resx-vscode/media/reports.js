export function h(tag, props = null, ...children) {
    const el = document.createElement(tag);
    if (props) {
        for (const [key, value] of Object.entries(props)) {
            if (value === undefined || value === null || value === false)
                continue;
            if (key === 'class')
                el.className = String(value);
            else if (key === 'text')
                el.textContent = String(value);
            else if (key === 'title')
                el.title = String(value);
            else if (key.startsWith('on') && typeof value === 'function')
                el.addEventListener(key.slice(2), value);
            else if (key === 'style' && typeof value === 'object')
                Object.assign(el.style, value);
            else
                el.setAttribute(key, String(value));
        }
    }
    for (const child of children) {
        if (child === null || child === undefined || child === false)
            continue;
        el.append(child instanceof Node ? child : String(child));
    }
    return el;
}
export function hex(value, width = 8) {
    if (value === null || value === undefined || value === '')
        return '';
    if (typeof value === 'number' && Number.isFinite(value)) {
        return `0x${value.toString(16).toUpperCase().padStart(width, '0')}`;
    }
    const text = String(value).trim();
    if (/^0x[0-9a-f]+$/i.test(text))
        return `0x${text.slice(2).toUpperCase().padStart(width, '0')}`;
    if (/^\d+$/.test(text))
        return hex(Number(text), width);
    return text;
}
function arr(value) {
    return Array.isArray(value) ? value : [];
}
function str(value) {
    if (value === null || value === undefined)
        return '';
    if (typeof value === 'object')
        return JSON.stringify(value);
    return String(value);
}
export function errorBox(message) {
    return h('div', { class: 'err-box', text: message });
}
export function noData(message) {
    return h('p', { class: 'no-data', text: message });
}
export function loading(message) {
    return h('p', { class: 'loading', text: message });
}
export function tag(text, cls = '') {
    return h('span', { class: `tag ${cls}`.trim(), text });
}
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export function severityTag(severity) {
    const sev = String(severity || 'info').toLowerCase();
    return tag(sev, `sev sev-${sev}`);
}
export function stats(values) {
    const grid = h('div', { class: 'mini-stats' });
    for (const [label, value] of Object.entries(values)) {
        if (value === undefined)
            continue;
        grid.append(h('div', { class: 'mini-stat' }, h('span', { text: str(value) }), h('small', { text: label })));
    }
    return grid;
}
export function kv(key, value) {
    return h('div', { class: 'kv' }, h('span', { class: 'kv-k', text: key }), h('span', { class: 'kv-v', text: str(value) }));
}
export function card(title, ...children) {
    return h('div', { class: 'ov-card' }, h('div', { class: 'ov-card-title', text: title }), ...children);
}
export function section(title, count) {
    return h('div', { class: 'section-label', text: count === undefined ? title : `${title} (${count})` });
}
export function notes(items, cls = '') {
    const list = arr(items).filter(Boolean);
    if (!list.length)
        return null;
    return h('ul', { class: `report-notes ${cls}`.trim() }, ...list.map(note => h('li', { text: str(note) })));
}
export function addrLink(ctx, value, label) {
    const text = hex(value);
    if (!text)
        return h('span', { class: 'dim', text: '-' });
    if (!ctx.navigateRva || !/^0x[0-9A-F]+$/i.test(text))
        return h('span', { class: 'rva', text });
    return h('span', {
        class: 'rva rva-link',
        text,
        title: 'Open disassembly here',
        onclick: (e) => { e.stopPropagation(); ctx.navigateRva(text, label || text); },
    });
}
export function toolbar(meta, ...buttons) {
    return h('div', { class: 'analysis-toolbar' }, h('div', { class: 'analysis-toolbar-meta', text: meta }), ...buttons);
}
export function button(label, onclick, title, cls = 'btn-sm') {
    return h('button', { class: cls, text: label, title, onclick });
}
export function jsonButton(ctx, data, title) {
    return button('Open JSON', () => ctx.openJson(data, title), 'Open the full RESX JSON document in an editor');
}
export function dataTable(rows, columns, opts = {}) {
    const pageSize = opts.pageSize ?? 400;
    const wrapper = h('div', { class: 'report-table' });
    if (!rows.length) {
        wrapper.append(noData(opts.emptyText || 'No entries.'));
        return wrapper;
    }
    const input = h('input', { type: 'text', placeholder: opts.placeholder || 'Regex filter…', spellcheck: 'false', autocomplete: 'off' });
    const count = h('span', { class: 'count-lbl' });
    const err = h('span', { class: 'regex-err' });
    wrapper.append(h('div', { class: 'searchbar' }, input, count, err));
    const texts = rows.map(row => columns.map(col => str(col.value(row))).join('\u0001').toLowerCase());
    let order = rows.map((_, i) => i);
    let filtered = order;
    let shown = 0;
    let sortCol = -1;
    let sortAsc = true;
    const table = h('table');
    const head = h('tr');
    columns.forEach((col, index) => {
        const th = h('th', { text: col.label, class: col.numeric ? 'num' : undefined });
        th.addEventListener('click', () => {
            sortAsc = sortCol === index ? !sortAsc : true;
            sortCol = index;
            head.querySelectorAll('th').forEach(t => t.classList.remove('sort-asc', 'sort-desc'));
            th.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
            order = order.slice().sort((a, b) => {
                const c = compareValues(col.value(rows[a]), col.value(rows[b]));
                return sortAsc ? c : -c;
            });
            apply();
        });
        head.append(th);
    });
    table.append(h('thead', null, head));
    const body = h('tbody');
    table.append(body);
    wrapper.append(h('div', { class: 'tbl-wrap' }, table));
    const more = button('', () => renderPage(), 'Render more rows');
    more.classList.add('report-more');
    wrapper.append(more);
    function renderPage() {
        const end = Math.min(filtered.length, shown + pageSize);
        const frag = document.createDocumentFragment();
        for (let i = shown; i < end; i++) {
            const row = rows[filtered[i]];
            const tr = h('tr');
            if (opts.onRow) {
                tr.classList.add('clickable');
                if (opts.rowTitle)
                    tr.title = opts.rowTitle;
                tr.addEventListener('click', () => opts.onRow(row));
            }
            for (const col of columns) {
                const content = col.render ? col.render(row) : str(col.value(row));
                tr.append(h('td', { class: col.cls }, content));
            }
            frag.append(tr);
        }
        body.append(frag);
        shown = end;
        const rest = filtered.length - shown;
        more.style.display = rest > 0 ? '' : 'none';
        more.textContent = `Show ${Math.min(rest, pageSize)} more (${rest} hidden)`;
    }
    function apply() {
        const raw = input.value.trim();
        let re = null;
        if (raw) {
            try {
                re = new RegExp(raw, 'i');
                input.classList.remove('invalid');
                err.textContent = '';
            }
            catch (ex) {
                input.classList.add('invalid');
                err.textContent = ex instanceof Error ? ex.message : String(ex);
                return;
            }
        }
        else {
            input.classList.remove('invalid');
            err.textContent = '';
        }
        filtered = re ? order.filter(i => re.test(texts[i])) : order;
        count.textContent = re ? `${filtered.length} / ${rows.length}` : `${rows.length}`;
        body.innerHTML = '';
        shown = 0;
        renderPage();
    }
    input.addEventListener('input', apply);
    apply();
    return wrapper;
}
function compareValues(a, b) {
    if (typeof a === 'number' && typeof b === 'number')
        return a - b;
    const as = str(a).trim();
    const bs = str(b).trim();
    const hexOrInt = /^(?:0x[0-9a-f]+|\d+)$/i;
    if (hexOrInt.test(as) && hexOrInt.test(bs)) {
        try {
            const x = BigInt(as);
            const y = BigInt(bs);
            return x < y ? -1 : x > y ? 1 : 0;
        }
        catch { }
    }
    const na = Number(as);
    const nb = Number(bs);
    if (as && bs && !Number.isNaN(na) && !Number.isNaN(nb))
        return na - nb;
    return as.localeCompare(bs);
}
export function jsonTree(value, label = 'root', depth = 0) {
    if (value === null || typeof value !== 'object') {
        return h('div', { class: 'jt-leaf' }, h('span', { class: 'jt-key', text: `${label}: ` }), h('span', { class: `jt-val jt-${value === null ? 'null' : typeof value}`, text: JSON.stringify(value) }));
    }
    const entries = Array.isArray(value) ? value.map((v, i) => [String(i), v]) : Object.entries(value);
    const summaryText = Array.isArray(value) ? `${label} [${entries.length}]` : `${label} {${entries.length}}`;
    const details = h('details', { class: 'jt-node' }, h('summary', { class: 'jt-key', text: summaryText }));
    details.open = depth < 1;
    let rendered = false;
    const fill = () => {
        if (rendered)
            return;
        rendered = true;
        const limit = 1000;
        entries.slice(0, limit).forEach(([k, v]) => details.append(jsonTree(v, k, depth + 1)));
        if (entries.length > limit)
            details.append(noData(`${entries.length - limit} more entries; open the JSON document for all of them.`));
    };
    if (details.open)
        fill();
    details.addEventListener('toggle', fill);
    return details;
}
export function renderBehavior(container, d, ctx) {
    const findings = arr(d.findings);
    const bySeverity = {};
    findings.forEach(f => { const s = String(f.severity || 'info').toLowerCase(); bySeverity[s] = (bySeverity[s] || 0) + 1; });
    container.append(stats({
        findings: d.finding_count ?? findings.length,
        high: bySeverity.high || 0,
        medium: bySeverity.medium || 0,
        low: bySeverity.low || 0,
        'resolved APIs': arr(d.resolved_apis).length,
    }));
    for (const limit of arr(d.analysis_limits))
        container.append(h('div', { class: 'report-banner warn', text: `Partial analysis: ${limit}` }));
    if (d.api_resolution) {
        container.append(h('div', { class: 'report-banner' }, h('strong', { text: 'Dynamic API resolution: ' }), String(d.api_resolution)));
    }
    if (!findings.length)
        container.append(noData('No static behavior signals found.'));
    const groups = new Map();
    for (const f of findings) {
        const key = [f.category, f.rule, f.severity, f.confidence, f.detail, f.source].join('\u0001');
        (groups.get(key) || groups.set(key, []).get(key)).push(f);
    }
    const byCategory = new Map();
    for (const group of groups.values()) {
        const cat = String(group[0].category || 'other');
        (byCategory.get(cat) || byCategory.set(cat, []).get(cat)).push(group);
    }
    const categories = [...byCategory.entries()].sort((a, b) => worst(a[1]) - worst(b[1]) || a[0].localeCompare(b[0]));
    if (categories.length) {
        const filterInput = h('input', { type: 'text', placeholder: 'Regex filter findings…', spellcheck: 'false' });
        const sevSelect = h('select', { class: 'report-select' }, h('option', { value: '', text: 'All severities' }), ...['high', 'medium', 'low', 'info'].map(s => h('option', { value: s, text: `${s} and above` })));
        container.append(h('div', { class: 'searchbar' }, filterInput, sevSelect));
        const list = h('div', { class: 'behavior-list' });
        container.append(list);
        const rows = [];
        for (const [category, catGroups] of categories) {
            const count = catGroups.reduce((n, g) => n + g.length, 0);
            const catEl = h('details', { class: 'finding-group' }, h('summary', { class: 'finding-group-title' }, category, ' ', tag(String(count))));
            catEl.open = worst(catGroups) <= 1 || categories.length <= 4;
            catGroups.sort((a, b) => sevRank(a[0].severity) - sevRank(b[0].severity));
            for (const group of catGroups) {
                const f = group[0];
                const item = h('details', { class: 'behavior-item' });
                const summary = h('summary', { class: 'behavior-summary' }, severityTag(f.severity), h('span', { class: 'finding-rule', text: f.rule || '' }), h('span', { class: 'behavior-detail', text: f.detail || '' }), h('span', { class: 'dim', text: `${f.confidence || ''} confidence${group.length > 1 ? ` · ${group.length} occurrences` : ''}` }));
                item.append(summary);
                const body = h('div', { class: 'behavior-body' });
                const sites = h('div', { class: 'tag-wrap' });
                group.slice(0, 200).forEach(g => { if (g.rva)
                    sites.append(addrLink(ctx, g.rva, `${f.rule}@${g.rva}`)); });
                if (group.length > 200)
                    sites.append(tag(`+${group.length - 200} more`));
                if (sites.childNodes.length)
                    body.append(sites);
                const evidence = arr(f.evidence);
                if (evidence.length)
                    body.append(h('pre', { class: 'behavior-evidence', text: evidence.join('\n') }));
                if (f.source)
                    body.append(h('div', { class: 'dim', text: `source: ${f.source}` }));
                item.append(body);
                catEl.append(item);
                rows.push({
                    el: item,
                    text: [category, f.rule, f.detail, f.source, ...evidence, ...group.map(g => g.rva)].join(' ').toLowerCase(),
                    sev: sevRank(f.severity),
                    cat: catEl,
                });
            }
            list.append(catEl);
        }
        const apply = () => {
            let re = null;
            try {
                re = filterInput.value.trim() ? new RegExp(filterInput.value.trim(), 'i') : null;
                filterInput.classList.remove('invalid');
            }
            catch {
                filterInput.classList.add('invalid');
                return;
            }
            const maxSev = sevSelect.value ? sevRank(sevSelect.value) : 99;
            const visibleCats = new Set();
            for (const row of rows) {
                const show = row.sev <= maxSev && (!re || re.test(row.text));
                row.el.style.display = show ? '' : 'none';
                if (show)
                    visibleCats.add(row.cat);
            }
            list.querySelectorAll(':scope > .finding-group').forEach(c => { c.style.display = visibleCats.has(c) ? '' : 'none'; });
        };
        filterInput.addEventListener('input', apply);
        sevSelect.addEventListener('change', apply);
    }
    const resolved = arr(d.resolved_apis);
    if (resolved.length) {
        container.append(section('Dynamically resolved APIs', resolved.length));
        container.append(dataTable(resolved, [
            { label: 'Site', value: r => hex(r.site), render: r => addrLink(ctx, r.site, `resolve ${r.api}`) },
            { label: 'API', value: r => r.api, cls: 'mono' },
            { label: 'Module', value: r => r.module || '', cls: 'mono' },
            { label: 'Method', value: r => r.method },
            { label: 'Name source', value: r => r.api_source },
            { label: 'Resolver', value: r => hex(r.function), render: r => addrLink(ctx, r.function) },
            { label: 'Call sites', value: r => arr(r.call_sites).length, render: r => siteList(ctx, r.call_sites, r.api), numeric: true },
        ], { placeholder: 'Regex filter resolved APIs…' }));
    }
    const signatures = d.api_signatures && typeof d.api_signatures === 'object' ? Object.entries(d.api_signatures) : [];
    if (signatures.length) {
        container.append(section('Recovered API arguments', signatures.length));
        container.append(dataTable(signatures, [
            { label: 'Site', value: ([rva]) => hex(Number(rva)), render: ([rva]) => addrLink(ctx, Number(rva)) },
            { label: 'Call', value: ([, sig]) => sig?.call || '', cls: 'mono wrap' },
        ]));
    }
}
function siteList(ctx, sites, label) {
    const list = arr(sites);
    if (!list.length)
        return document.createTextNode('0');
    const wrap = h('span', { class: 'tag-wrap inline' });
    list.slice(0, 6).forEach(site => wrap.append(addrLink(ctx, typeof site === 'object' ? site.rva ?? site.site : site, label)));
    if (list.length > 6)
        wrap.append(tag(`+${list.length - 6}`));
    return wrap;
}
function sevRank(severity) {
    return SEVERITY_ORDER[String(severity || 'info').toLowerCase()] ?? 5;
}
function worst(groups) {
    return Math.min(...groups.map(g => sevRank(g[0]?.severity)));
}
export function renderEvidence(container, d, ctx, argsEnabled) {
    const calls = arr(d.calls);
    const coverage = d.coverage || {};
    container.append(stats({
        calls: calls.length,
        'decoded insns': d.decoded_instructions,
        'IPC channels': arr(d.flows?.ipc_channels).length,
        'network requests': arr(d.flows?.network_requests).length,
        'crypto configs': arr(d.flows?.crypto_configurations).length,
        indicators: d.indicators ? arr(d.indicators).length : undefined,
    }));
    if (coverage.instruction_limit_reached)
        container.append(h('div', { class: 'report-banner warn', text: `Instruction limit (${coverage.instruction_limit}) reached; later code was not analyzed.` }));
    if (coverage.call_limit_reached)
        container.append(h('div', { class: 'report-banner warn', text: `Call limit (${coverage.call_limit}) reached.` }));
    if (coverage.architecture_supported === false)
        container.append(h('div', { class: 'report-banner warn', text: 'Argument recovery is not supported for this architecture.' }));
    if (!argsEnabled && calls.length) {
        container.append(h('div', { class: 'report-banner', text: 'Call arguments are omitted. Enable "Recover arguments" to include them.' }));
    }
    const flows = d.flows || {};
    for (const [key, title] of [['ipc_channels', 'IPC channels'], ['network_requests', 'Network requests'], ['crypto_configurations', 'Crypto configurations']]) {
        const items = arr(flows[key]);
        if (!items.length)
            continue;
        container.append(section(title, items.length));
        container.append(objectTable(items, ctx));
    }
    if (calls.length) {
        container.append(section('API calls', calls.length));
        container.append(dataTable(calls, [
            { label: 'Site', value: c => hex(c.site_rva), render: c => addrLink(ctx, c.site_rva, `${c.api}@${hex(c.site_rva)}`) },
            { label: 'Category', value: c => c.category },
            { label: 'API', value: c => `${c.dll ? `${c.dll}!` : ''}${c.api || ''}`, cls: 'mono' },
            { label: 'Owner', value: c => c.owner_name || hex(c.owner_rva), render: c => c.owner_rva != null ? addrLink(ctx, c.owner_rva, c.owner_name) : (c.owner_name || '') },
            { label: 'Call', value: c => c.reconstructed_call || '', render: c => h('pre', { class: 'inline-pre', text: c.reconstructed_call || '' }) },
            { label: 'Status', value: c => c.status || '', cls: 'dim small' },
        ], { placeholder: 'Regex filter calls…' }));
    }
    const indicators = arr(d.indicators);
    if (indicators.length) {
        container.append(section('String indicators', indicators.length));
        container.append(dataTable(indicators, [
            { label: 'Offset', value: i => hex(i.file_offset), cls: 'rva' },
            { label: 'Rule', value: i => i.rule },
            { label: 'Encoding', value: i => i.encoding },
            { label: 'Value', value: i => i.value, cls: 'mono wrap' },
        ], { placeholder: 'Regex filter indicators…' }));
    }
    const lim = notes(d.limitations);
    if (lim) {
        container.append(section('Limitations'));
        container.append(lim);
    }
}
export function objectTable(items, ctx) {
    const keys = [];
    for (const item of items.slice(0, 50)) {
        if (item && typeof item === 'object')
            for (const k of Object.keys(item))
                if (!keys.includes(k))
                    keys.push(k);
    }
    const addressKey = (k) => /(^|_)(rva|site|va)$|_rva$/.test(k);
    return dataTable(items, keys.slice(0, 10).map(k => ({
        label: k.replace(/_/g, ' '),
        value: (row) => addressKey(k) ? hex(row?.[k]) : str(row?.[k]),
        render: addressKey(k) ? (row) => addrLink(ctx, row?.[k]) : undefined,
        cls: 'mono wrap',
    })));
}
export function renderStrings(container, d, ctx) {
    const list = arr(d.strings);
    container.append(stats({
        returned: list.length,
        matched: d.total,
        filtered: d.filtered_out,
        'scanned bytes': d.scanned_bytes,
    }));
    if (d.truncated)
        container.append(h('div', { class: 'report-banner warn', text: 'Result limit reached; raise the limit or narrow the filter.' }));
    container.append(dataTable(list, [
        { label: 'RVA', value: s => s.rva ? hex(s.rva) : '', render: s => s.rva ? h('span', { class: 'rva', text: hex(s.rva) }) : h('span', { class: 'dim', text: '-' }) },
        { label: 'File', value: s => hex(s.file_offset), cls: 'rva' },
        { label: 'Section', value: s => s.section || '' },
        { label: 'Enc', value: s => s.encoding },
        { label: 'Tags', value: s => arr(s.tags).join(', '), render: s => { const w = h('span', { class: 'tag-wrap inline' }); arr(s.tags).forEach(t => w.append(tag(t))); return w; } },
        { label: 'Value', value: s => s.value, render: s => h('span', { class: 'str-val', text: s.value + (s.truncated ? '…' : ''), title: 'Click to copy' }), cls: 'wrap' },
    ], { placeholder: 'Regex filter strings…', onRow: s => ctx.copy(String(s.value || '')), rowTitle: 'Click to copy the string' }));
}
export function renderEntropy(container, d, ctx) {
    const windows = arr(d.windows);
    const s = d.summary || {};
    container.append(stats({
        windows: s.window_count ?? windows.length,
        avg: s.avg_entropy,
        max: s.max_entropy,
        min: s.min_entropy,
        high: s.high_entropy_windows,
        low: s.low_entropy_windows,
        'zero-heavy': s.zero_heavy_windows,
        'ascii-heavy': s.ascii_heavy_windows,
    }));
    if (!windows.length) {
        container.append(noData('No entropy windows. Include non-executable sections or reduce the window size.'));
        return;
    }
    container.append(entropyChart(windows, ctx));
    const flagged = windows.filter(w => arr(w.flags).length);
    container.append(section(flagged.length ? 'Flagged windows' : 'Windows', flagged.length || windows.length));
    container.append(dataTable(flagged.length ? flagged : windows, [
        { label: 'RVA', value: w => hex(w.rva), render: w => addrLink(ctx, w.rva) },
        { label: 'Section', value: w => w.section },
        { label: 'Entropy', value: w => Number(w.entropy), numeric: true },
        { label: 'Zero %', value: w => pct(w.zero_ratio), numeric: true },
        { label: 'ASCII %', value: w => pct(w.ascii_ratio), numeric: true },
        { label: 'Unique %', value: w => pct(w.unique_ratio), numeric: true },
        { label: 'Flags', value: w => arr(w.flags).join(', ') },
    ]));
}
function pct(value) {
    const n = Number(value);
    return Number.isFinite(n) ? `${Math.round(n * 1000) / 10}` : '';
}
function entropyChart(windows, ctx) {
    const ns = 'http://www.w3.org/2000/svg';
    const width = 1000;
    const height = 180;
    const pad = 24;
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', `0 0 ${width} ${height + pad}`);
    svg.setAttribute('class', 'entropy-chart');
    svg.setAttribute('preserveAspectRatio', 'none');
    const n = windows.length;
    const x = (i) => (n <= 1 ? 0 : (i / (n - 1)) * width);
    const y = (e) => height - (Math.max(0, Math.min(8, e)) / 8) * height;
    let start = 0;
    for (let i = 1; i <= n; i++) {
        if (i === n || windows[i].section !== windows[start].section) {
            const band = document.createElementNS(ns, 'rect');
            band.setAttribute('x', String(x(start)));
            band.setAttribute('y', '0');
            band.setAttribute('width', String(Math.max(1, x(i - 1) - x(start))));
            band.setAttribute('height', String(height));
            band.setAttribute('class', `entropy-band band-${(start === 0 ? 0 : 1) + (Math.floor(i) % 2)}`);
            svg.append(band);
            const label = document.createElementNS(ns, 'text');
            label.setAttribute('x', String(x(start) + 4));
            label.setAttribute('y', String(height + 16));
            label.setAttribute('class', 'entropy-label');
            label.textContent = String(windows[start].section || '');
            svg.append(label);
            start = i;
        }
    }
    for (const level of [7.2]) {
        const line = document.createElementNS(ns, 'line');
        line.setAttribute('x1', '0');
        line.setAttribute('x2', String(width));
        line.setAttribute('y1', String(y(level)));
        line.setAttribute('y2', String(y(level)));
        line.setAttribute('class', 'entropy-threshold');
        svg.append(line);
    }
    const path = document.createElementNS(ns, 'polyline');
    path.setAttribute('points', windows.map((w, i) => `${x(i).toFixed(1)},${y(Number(w.entropy) || 0).toFixed(1)}`).join(' '));
    path.setAttribute('class', 'entropy-line');
    svg.append(path);
    const tip = h('div', { class: 'entropy-tip' });
    const wrap = h('div', { class: 'entropy-wrap' }, svg, tip);
    const indexAt = (evt) => {
        const rect = svg.getBoundingClientRect();
        const ratio = (evt.clientX - rect.left) / Math.max(1, rect.width);
        return Math.max(0, Math.min(n - 1, Math.round(ratio * (n - 1))));
    };
    svg.addEventListener('mousemove', evt => {
        const w = windows[indexAt(evt)];
        tip.textContent = `${w.section} ${hex(w.rva)}  entropy ${w.entropy}  zero ${pct(w.zero_ratio)}%  ascii ${pct(w.ascii_ratio)}%${arr(w.flags).length ? `  [${arr(w.flags).join(', ')}]` : ''}`;
    });
    svg.addEventListener('click', evt => {
        const w = windows[indexAt(evt)];
        if (w?.rva && ctx.navigateRva)
            ctx.navigateRva(hex(w.rva), `${w.section}@${hex(w.rva)}`);
    });
    tip.textContent = 'Hover for window details; click to disassemble at the window start. Dashed line: 7.2 bits/byte.';
    return wrap;
}
export function renderDriver(container, d, ctx) {
    const ioctl = d.ioctl || {};
    const codes = arr(ioctl.codes);
    container.append(stats({
        classification: d.classification,
        confidence: d.confidence,
        'major functions': arr(d.major_functions).length,
        'IOCTL codes': codes.length,
        capabilities: arr(d.capabilities).length,
        devices: arr(ioctl.devices?.endpoints).length,
    }));
    if (ioctl.summary)
        container.append(h('div', { class: 'report-banner', text: ioctl.summary }));
    const indicators = arr(d.framework_indicators);
    if (indicators.length) {
        const w = h('div', { class: 'tag-wrap' });
        indicators.forEach(i => w.append(tag(i)));
        container.append(w);
    }
    const majors = arr(d.major_functions);
    if (majors.length) {
        container.append(section('Dispatch routines', majors.length));
        container.append(dataTable(majors, [
            { label: 'Major', value: m => m.major_name || m.major_index },
            { label: 'Handler', value: m => hex(m.target_rva), render: m => addrLink(ctx, m.target_rva, m.major_name) },
            { label: 'Assigned at', value: m => hex(m.site_rva), render: m => addrLink(ctx, m.site_rva) },
            { label: 'Instruction', value: m => m.instruction, cls: 'mono' },
            { label: 'Confidence', value: m => m.confidence, cls: 'dim small' },
        ]));
    }
    renderIoctl(container, ioctl, ctx, false);
    const caps = arr(d.capabilities);
    if (caps.length) {
        container.append(section('Capabilities', caps.length));
        container.append(dataTable(caps, [
            { label: 'Capability', value: c => c.capability },
            { label: 'APIs', value: c => arr(c.apis).join(', '), cls: 'mono wrap' },
            { label: 'Confidence', value: c => c.confidence },
        ]));
    }
    for (const [key, title] of [['device_apis', 'Device APIs'], ['symbolic_link_apis', 'Symbolic link APIs'], ['registry_apis', 'Registry APIs'], ['callback_apis', 'Callbacks and notifications']]) {
        const items = arr(d[key]);
        if (!items.length)
            continue;
        container.append(section(title, items.length));
        container.append(dataTable(items, [
            { label: 'API', value: a => `${a.dll ? `${a.dll}!` : ''}${a.name}`, cls: 'mono' },
            { label: 'Kind', value: a => a.kind },
            { label: 'IAT slot', value: a => hex(a.slot_rva), cls: 'rva' },
        ]));
    }
    const hv = d.hypervisor;
    if (hv && (arr(hv.capabilities).length || arr(hv.instruction_evidence).length || arr(hv.vendors).length)) {
        container.append(section('Virtualization'));
        container.append(card(hv.classification || 'Hypervisor evidence', kv('Confidence', hv.confidence), kv('Vendors', arr(hv.vendors).join(', ') || '-'), kv('Capabilities', arr(hv.capabilities).map(str).join(', ') || '-')));
        if (arr(hv.instruction_evidence).length)
            container.append(objectTable(arr(hv.instruction_evidence), ctx));
    }
    const strs = arr(d.interesting_strings);
    if (strs.length) {
        container.append(section('Interesting strings', strs.length));
        container.append(dataTable(strs, [
            { label: 'RVA', value: s => hex(s.rva), cls: 'rva' },
            { label: 'Section', value: s => s.section },
            { label: 'Value', value: s => s.value, cls: 'mono wrap' },
        ]));
    }
    const n = notes(d.notes);
    if (n) {
        container.append(section('Notes'));
        container.append(n);
    }
}
export function renderIoctl(container, ioctl, ctx, withSummary = true) {
    const codes = arr(ioctl.codes);
    if (withSummary) {
        container.append(stats({ 'IOCTL codes': codes.length, 'dispatch roots': ioctl.coverage?.dispatch_roots, 'call sites': arr(ioctl.call_sites).length }));
        if (ioctl.summary)
            container.append(h('div', { class: 'report-banner', text: ioctl.summary }));
    }
    const cov = ioctl.coverage || {};
    const truncated = ['dispatch_analysis_truncated', 'dispatch_discovery_truncated', 'length_analysis_truncated', 'linear_instruction_limit_reached', 'call_limit_reached'].filter(k => cov[k]);
    if (truncated.length)
        container.append(h('div', { class: 'report-banner warn', text: `Bounded analysis: ${truncated.map(k => k.replace(/_/g, ' ')).join(', ')}.` }));
    if (codes.length) {
        container.append(section('IOCTL codes', codes.length));
        container.append(dataTable(codes, [
            { label: 'Code', value: c => c.code, cls: 'mono' },
            { label: 'Device type', value: c => c.device_type_name || c.device_type },
            { label: 'Function', value: c => c.function, cls: 'mono' },
            { label: 'Method', value: c => c.method },
            { label: 'Access', value: c => c.access },
            { label: 'Handler', value: c => hex(c.handler_rva), render: c => addrLink(ctx, c.handler_rva, `IOCTL ${c.code}`) },
            { label: 'Compared at', value: c => hex(c.site_rva), render: c => addrLink(ctx, c.site_rva) },
            { label: 'Length checks', value: c => arr(c.length_checks).map(str).join('; '), cls: 'small wrap' },
        ], { placeholder: 'Regex filter IOCTL codes…' }));
    }
    const candidates = arr(ioctl.dispatch_candidates);
    if (candidates.length) {
        container.append(section('Dispatch candidates', candidates.length));
        container.append(dataTable(candidates, [
            { label: 'Owner', value: c => c.owner_name || hex(c.owner_rva), render: c => addrLink(ctx, c.owner_rva, c.owner_name) },
            { label: 'Codes', value: c => c.code_count ?? arr(c.codes).length, numeric: true },
            { label: 'Reason', value: c => c.reason, cls: 'small wrap' },
        ]));
    }
    const sites = arr(ioctl.call_sites);
    if (sites.length) {
        container.append(section('Request call sites', sites.length));
        container.append(objectTable(sites, ctx));
    }
    const devices = ioctl.devices || {};
    if (arr(devices.endpoints).length || arr(devices.symbolic_links).length) {
        container.append(section('Devices'));
        if (arr(devices.endpoints).length)
            container.append(objectTable(arr(devices.endpoints), ctx));
        if (arr(devices.symbolic_links).length)
            container.append(objectTable(arr(devices.symbolic_links), ctx));
    }
    const lim = notes([...arr(ioctl.limitations), ...arr(devices.limitations)]);
    if (lim) {
        container.append(section('Limitations'));
        container.append(lim);
    }
}
export function renderPechk(container, d) {
    const findings = arr(d.findings);
    container.append(stats({
        findings: d.finding_count ?? findings.length,
        architecture: d.architecture,
        'file bytes': d.file_bytes,
        'header corrupt': d.header_corrupt ? 'yes' : 'no',
    }));
    if (d.report_truncated)
        container.append(h('div', { class: 'report-banner warn', text: `Only the first ${d.report_limit} findings are reported.` }));
    if (!findings.length) {
        container.append(noData('No structural or loader anomalies found.'));
        return;
    }
    container.append(dataTable(findings, [
        { label: 'Severity', value: f => sevRank(f.severity), render: f => severityTag(f.severity) },
        { label: 'Kind', value: f => f.kind || f.rule || '', cls: 'mono' },
        { label: 'Detail', value: f => f.detail || f.message || str(f), cls: 'wrap' },
    ], { placeholder: 'Regex filter findings…' }));
}
export function renderFind(container, d, ctx) {
    const matches = arr(d.matches);
    container.append(stats({ matches: matches.length, mode: d.mode, 'decoded insns': d.decoded_instructions }));
    if (d.truncated)
        container.append(h('div', { class: 'report-banner warn', text: 'The search budget was reached; later bytes were not searched.' }));
    container.append(dataTable(matches, [
        { label: 'RVA', value: m => hex(m.rva), render: m => addrLink(ctx, m.rva, `find@${hex(m.rva)}`) },
        { label: 'File', value: m => hex(m.file_offset), cls: 'rva' },
        { label: 'Section', value: m => m.section || '' },
        { label: 'Mode', value: m => m.mode },
        { label: 'Match', value: m => m.text, cls: 'mono wrap' },
        { label: 'Transform', value: m => m.transform ? str(m.transform) : '' },
    ], { emptyText: `No matches for ${JSON.stringify(d.query || '')}.` }));
}
export function renderYara(container, d, ctx) {
    const matches = arr(d.matches);
    container.append(stats({ 'matched rules': d.match_count ?? matches.length, 'rule inputs': arr(d.rule_inputs).length }));
    if (!matches.length) {
        container.append(noData('No rules matched.'));
        return;
    }
    for (const m of matches) {
        const strings = arr(m.strings);
        const item = h('details', { class: 'behavior-item' }, h('summary', { class: 'behavior-summary' }, h('span', { class: 'finding-rule', text: `${m.namespace && m.namespace !== 'default' ? `${m.namespace}:` : ''}${m.rule}` }), ...arr(m.tags).map(t => tag(t)), h('span', { class: 'dim', text: `${strings.length} string match${strings.length === 1 ? '' : 'es'}` })));
        item.open = matches.length <= 5;
        if (arr(m.metadata).length)
            item.append(objectTable(arr(m.metadata), ctx));
        item.append(dataTable(strings, [
            { label: 'Id', value: s => s.identifier, cls: 'mono' },
            { label: 'Offset', value: s => hex(s.offset), cls: 'rva' },
            { label: 'RVA', value: s => s.rva != null ? hex(s.rva) : '', render: s => s.rva != null ? addrLink(ctx, s.rva) : h('span', { class: 'dim', text: '-' }) },
            { label: 'Section', value: s => s.section || '' },
            { label: 'Data', value: s => s.data, cls: 'mono wrap' },
        ]));
        container.append(item);
    }
}
export function renderCallers(container, d, ctx) {
    const nodes = arr(d.callers);
    const meta = `${d.dll || ''}!${d.function || ''} ${d.rva ? `@ ${d.rva}` : ''}`;
    container.append(h('div', { class: 'dim', text: meta }));
    if (d.truncated)
        container.append(h('div', { class: 'report-banner warn', text: 'Caller list truncated; raise the max-callers or depth budget.' }));
    if (!nodes.length) {
        container.append(noData('No callers found in the searched images.'));
        return;
    }
    const tree = h('div', { class: 'callers-tree' });
    const walk = (list, depth) => {
        for (const node of list) {
            const sameImage = !node.dll || !d.dll || String(node.dll).toLowerCase() === String(d.dll).toLowerCase();
            const name = h('span', { class: 'fn-link', text: `${sameImage ? '' : `${node.dll}!`}${node.function || hex(node.rva)}` });
            name.addEventListener('click', () => {
                if (sameImage && node.rva && ctx.navigateRva)
                    ctx.navigateRva(node.rva, node.function);
                else if (ctx.navigate && node.function)
                    ctx.navigate(node.function, node.dll);
            });
            const row = h('div', { class: 'callers-row', style: { paddingLeft: `${depth * 16}px` } }, h('span', { class: 'dim', text: depth ? '└ ' : '' }), name, node.rva ? h('span', { class: 'rva dim', text: ` ${node.rva}` }) : null);
            const sites = arr(node.call_sites);
            if (sites.length && sameImage) {
                const wrap = h('span', { class: 'tag-wrap inline' });
                sites.slice(0, 4).forEach(s => wrap.append(addrLink(ctx, s.rva, `${node.function} call site`), tag(s.pattern || 'call')));
                row.append(wrap);
            }
            else if (sites.length) {
                row.append(h('span', { class: 'dim', text: ` · ${sites.length} site${sites.length === 1 ? '' : 's'}` }));
            }
            tree.append(row);
            if (arr(node.callers).length)
                walk(arr(node.callers), depth + 1);
        }
    };
    walk(nodes, 0);
    container.append(tree);
}
export function renderDiff(container, d, ctx) {
    const s = d.summary || {};
    const left = d.left || {};
    const right = d.right || {};
    container.append(h('div', { class: 'diff-sides' }, imageCard('Left', left), imageCard('Right', right)));
    container.append(stats({
        similarity: s.similarity_score,
        'unique similarity': s.unique_similarity_score,
        matched: s.matched_functions,
        exact: s.exact_matches,
        strong: s.strong_matches,
        changed: s.changed_matches,
        weak: s.weak_matches,
        'left only': s.left_only_functions,
        'right only': s.right_only_functions,
    }));
    const n = notes(d.notes);
    if (n)
        container.append(n);
    const matches = arr(d.matches);
    container.append(section('Function matches', matches.length));
    container.append(dataTable(matches, [
        { label: 'Score', value: m => Number(m.score ?? 0), numeric: true },
        { label: 'Tier', value: m => m.tier || m.kind || '' },
        { label: 'Left', value: m => `${m.left?.name || ''} ${m.left?.rva || ''}`, render: m => sideLink(ctx, left.path, m.left) },
        { label: 'Right', value: m => `${m.right?.name || ''} ${m.right?.rva || ''}`, render: m => sideLink(ctx, right.path, m.right) },
        { label: 'Signals', value: m => signalText(m.evidence || m.signals), cls: 'small' },
    ], { placeholder: 'Regex filter matches…', emptyText: 'No functions matched above the threshold.' }));
    const clusters = arr(d.changed_clusters);
    if (clusters.length) {
        container.append(section('Changed regions', clusters.length));
        container.append(dataTable(clusters, [
            { label: 'Kind', value: c => c.kind },
            { label: 'Side', value: c => c.side },
            { label: 'Section', value: c => c.section },
            { label: 'Range', value: c => `${c.start_rva}..${c.end_rva}`, cls: 'rva' },
            { label: 'Functions', value: c => c.functions, numeric: true },
            { label: 'Examples', value: c => arr(c.examples).join(', '), cls: 'mono small wrap' },
        ]));
    }
    const hot = arr(d.heatmap?.hotspots);
    if (hot.length) {
        container.append(section('Hotspots', hot.length));
        container.append(dataTable(hot, [
            { label: 'Heat', value: x => Number(x.heat ?? 0), numeric: true },
            { label: 'Kind', value: x => x.kind },
            { label: 'Left', value: x => `${x.left_name} ${x.left_rva}`, render: x => sideLink(ctx, left.path, { name: x.left_name, rva: x.left_rva }) },
            { label: 'Right', value: x => `${x.right_name} ${x.right_rva}`, render: x => sideLink(ctx, right.path, { name: x.right_name, rva: x.right_rva }) },
            { label: 'Notes', value: x => arr(x.notes).join('; '), cls: 'small wrap' },
        ]));
    }
    const sec = arr(d.heatmap?.section_entropy);
    if (sec.length) {
        container.append(section('Section entropy', sec.length));
        container.append(dataTable(sec, [
            { label: 'Section', value: x => x.section, cls: 'mono' },
            { label: 'Left', value: x => x.left_entropy ?? '-', numeric: true },
            { label: 'Right', value: x => x.right_entropy ?? '-', numeric: true },
            { label: 'Δ', value: x => x.entropy_delta ?? '-', numeric: true },
            { label: 'Note', value: x => x.note || '', cls: 'small' },
        ]));
    }
    const meta = d.metadata || {};
    const metaLists = [
        ['Imports only in left', meta.left_only_imports], ['Imports only in right', meta.right_only_imports],
        ['Exports only in left', meta.left_only_exports], ['Exports only in right', meta.right_only_exports],
        ['Strings only in left', meta.left_only_strings], ['Strings only in right', meta.right_only_strings],
    ].filter(([, v]) => arr(v).length);
    if (metaLists.length) {
        container.append(section('Metadata differences'));
        container.append(stats({ 'common imports': meta.common_imports, 'common exports': meta.common_exports, 'common strings': meta.common_strings }));
        for (const [title, list] of metaLists) {
            const w = h('div', { class: 'tag-wrap' });
            arr(list).slice(0, 200).forEach(x => w.append(tag(str(x))));
            container.append(h('details', { class: 'finding-group' }, h('summary', { class: 'finding-group-title' }, title, ' ', tag(String(arr(list).length))), w));
        }
    }
    for (const [key, title, path] of [['left_only', 'Functions only in left', left.path], ['right_only', 'Functions only in right', right.path]]) {
        const fns = arr(d[key]).filter(f => !f.noise);
        if (!fns.length)
            continue;
        container.append(section(`${title} (excluding noise)`, fns.length));
        container.append(dataTable(fns, [
            { label: 'Function', value: f => `${f.name} ${f.rva}`, render: f => sideLink(ctx, path, f) },
            { label: 'Section', value: f => f.section },
            { label: 'Size', value: f => f.size_bytes, numeric: true },
            { label: 'Blocks', value: f => f.block_count, numeric: true },
            { label: 'Traits', value: f => arr(f.trait_tags).join(', '), cls: 'small' },
        ]));
    }
}
function imageCard(title, img) {
    return card(`${title}: ${img.name || ''}`, kv('Path', img.path || ''), kv('Arch', img.arch || ''), kv('Size', img.size_bytes ?? ''), kv('Entry', img.entry_point || ''), kv('Functions', `${img.profiled_functions ?? '?'} profiled / ${img.discovered_functions ?? '?'} discovered`), kv('Imports / exports', `${img.imports ?? 0} / ${img.exports ?? 0}`));
}
function sideLink(ctx, path, fn) {
    if (!fn || (!fn.name && !fn.rva))
        return h('span', { class: 'dim', text: '-' });
    const label = `${fn.name || ''}${fn.rva ? ` ${fn.rva}` : ''}`.trim();
    if (!path || !fn.rva || !ctx.openImage)
        return h('span', { class: 'mono', text: label });
    return h('span', {
        class: 'fn-link',
        text: label,
        title: `Open ${path} at ${fn.rva}`,
        onclick: (e) => { e.stopPropagation(); ctx.openImage(cleanPath(path), fn.rva, fn.name); },
    });
}
function signalText(evidence) {
    if (!evidence || typeof evidence !== 'object')
        return '';
    return Object.entries(evidence)
        .filter(([k, v]) => /_score$/.test(k) && typeof v === 'number')
        .map(([k, v]) => `${k.replace(/_score$/, '')} ${v}`)
        .join(' · ');
}
export function cleanPath(path) {
    return String(path || '').replace(/^\\\\\?\\/, '');
}
export function renderHunt(container, d, ctx) {
    const candidates = arr(d.candidates);
    container.append(stats({ 'indexed images': d.indexed_images, candidates: candidates.length, sample: d.sample?.name }));
    if (d.index_root)
        container.append(h('div', { class: 'dim', text: `Corpus root: ${d.index_root}` }));
    const n = notes(d.notes);
    if (n)
        container.append(n);
    container.append(dataTable(candidates, [
        { label: 'Rank', value: c => c.rank, numeric: true },
        { label: 'Score', value: c => c.score, numeric: true },
        { label: 'Unique', value: c => c.unique_score, numeric: true },
        { label: 'Image', value: c => c.name, render: c => ctx.openImage ? h('span', { class: 'fn-link', text: c.name, title: c.path, onclick: () => ctx.openImage(cleanPath(c.path)) }) : c.name },
        { label: 'Matched', value: c => c.matched_functions, numeric: true },
        { label: 'Exact', value: c => c.exact_matches, numeric: true },
        { label: 'Coverage L/R', value: c => `${c.left_coverage}/${c.right_coverage}` },
        { label: 'Tags', value: c => arr(c.family_tags).join(', ') },
    ], { emptyText: 'No indexed image ranked above the threshold.' }));
}
export function renderIndex(container, d, ctx) {
    const images = arr(d.images);
    container.append(stats({ images: images.length, skipped: arr(d.skipped).length, 'created by': d.created_by }));
    if (d.root)
        container.append(h('div', { class: 'dim', text: `Root: ${d.root}` }));
    container.append(dataTable(images, [
        { label: 'Image', value: i => i.summary?.name, render: i => ctx.openImage ? h('span', { class: 'fn-link', text: i.summary?.name || '', title: i.summary?.path, onclick: () => ctx.openImage(cleanPath(i.summary?.path)) }) : (i.summary?.name || '') },
        { label: 'Arch', value: i => i.summary?.arch },
        { label: 'Functions', value: i => arr(i.functions).length, numeric: true },
        { label: 'Imports', value: i => arr(i.imports).length, numeric: true },
        { label: 'Exports', value: i => arr(i.exports).length, numeric: true },
        { label: 'Strings', value: i => arr(i.strings).length, numeric: true },
    ]));
    if (arr(d.skipped).length) {
        container.append(section('Skipped', arr(d.skipped).length));
        container.append(objectTable(arr(d.skipped), ctx));
    }
}
export function renderPayload(container, d, ctx) {
    const layers = arr(d.layers);
    container.append(stats({
        layers: layers.length,
        'decoded bytes': d.decoded_bytes,
        decompressed: d.decompression_performed ? 'yes' : 'no',
        'PE rebuilt': d.executable_reconstructed ? 'yes' : 'no',
    }));
    if (d.layer_limit_reached)
        container.append(h('div', { class: 'report-banner warn', text: 'Layer limit reached; decoding stopped.' }));
    container.append(card('Hashes', kv('Source SHA-256', d.source_sha256 || ''), kv('Final SHA-256', d.final_sha256 || ''), kv('Source range', d.source_range ? `offset ${d.source_range.offset}, ${d.source_range.size} bytes` : '')));
    container.append(section('Layers', layers.length));
    container.append(dataTable(layers, [
        { label: '#', value: l => l.depth, numeric: true },
        { label: 'Codec', value: l => l.codec },
        { label: 'In', value: l => l.input_size, numeric: true },
        { label: 'Out', value: l => l.output_size, numeric: true },
        { label: 'File', value: l => l.file, cls: 'mono small' },
        { label: 'Validation', value: l => l.validation, cls: 'small wrap' },
    ]));
    if (d.pe) {
        container.append(section('Reconstructed PE'));
        container.append(jsonTree(d.pe, 'pe'));
    }
    if (d.structural_fingerprint)
        container.append(kv('Structural fingerprint', `${d.structural_fingerprint.status}${d.structural_fingerprint.reason ? ` · ${d.structural_fingerprint.reason}` : ''}`));
    const strs = arr(d.strings?.strings);
    if (strs.length) {
        container.append(section('Strings in final layer', strs.length));
        container.append(dataTable(strs, [
            { label: 'Offset', value: s => hex(s.offset), cls: 'rva' },
            { label: 'Enc', value: s => s.encoding },
            { label: 'Value', value: s => s.value, cls: 'mono wrap' },
        ], { onRow: s => ctx.copy(String(s.value || '')), rowTitle: 'Click to copy' }));
    }
    const lim = notes(d.limitations);
    if (lim) {
        container.append(section('Limitations'));
        container.append(lim);
    }
}
export function renderPatch(container, d) {
    const a = d.address || {};
    const b = d.bytes || {};
    const performed = d.write?.performed;
    container.append(h('div', { class: `report-banner ${performed ? '' : 'warn'}`, text: performed
            ? `Patched image written to ${cleanPath(d.output_path)}.`
            : d.dry_run ? 'Dry run: nothing was written.' : 'No bytes were written.' }));
    container.append(card('Address', kv('Input', a.input || ''), kv('RVA', a.rva || ''), kv('VA', a.va || ''), kv('File offset', a.file_offset || ''), kv('Section', a.section || '')));
    container.append(card('Bytes', kv('Original', b.original || ''), kv('Replacement', b.replacement || ''), kv('Expected', b.expected ?? '-'), kv('Length', b.length ?? ''), kv('Changes bytes', b.changed ? 'yes' : 'no')));
    container.append(card('Output', kv('Source', cleanPath(d.source_path)), kv('Output', cleanPath(d.output_path)), kv('In place', d.in_place ? 'yes' : 'no'), kv('Checksum', d.checksum?.updated ? `${d.checksum.old} → ${d.checksum.new}` : `${d.checksum?.old ?? '-'} (unchanged)`)));
    const n = notes(d.notes);
    if (n)
        container.append(n);
}
export function renderApi(container, d) {
    const p = d.prototype || {};
    container.append(h('pre', { class: 'pre-block api-decl', text: d.declaration || '' }));
    container.append(card('Prototype', kv('Name', p.name || ''), kv('Returns', p.returns || ''), kv('Header', p.header || ''), kv('SDK', cleanPath(d.headers || ''))));
    const params = arr(p.params);
    if (params.length) {
        container.append(section('Parameters', params.length));
        container.append(dataTable(params, [
            { label: 'Name', value: x => x.name, cls: 'mono' },
            { label: 'Type', value: x => x.type, cls: 'mono' },
            { label: 'Direction', value: x => x.direction },
            { label: 'Optional', value: x => x.optional ? 'yes' : '' },
        ]));
    }
    for (const [key, title] of [['constants', 'Constants'], ['typedefs', 'Typedefs']]) {
        if (d[key] && (Array.isArray(d[key]) ? d[key].length : Object.keys(d[key]).length)) {
            container.append(section(title));
            container.append(jsonTree(d[key], key));
        }
    }
}
export function renderScanSummary(container, d, ctx) {
    const results = arr(d.results);
    container.append(stats({ seen: d.files_seen, reported: d.files_reported ?? results.length }));
    container.append(dataTable(results, [
        { label: 'Risk', value: r => Number(r.risk_score ?? 0), numeric: true },
        { label: 'Image', value: r => r.name, render: r => ctx.openImage ? h('span', { class: 'fn-link', text: r.name, title: r.path, onclick: () => ctx.openImage(r.path) }) : r.name },
        { label: 'Kind', value: r => r.kind },
        { label: 'Arch', value: r => r.arch },
        { label: 'Candidates', value: r => arr(r.candidates).length, numeric: true },
        { label: 'Risk imports', value: r => arr(r.risk_imports).map(i => i.name).join(', '), cls: 'small wrap' },
        { label: 'Surfaces', value: r => arr(r.input_surfaces).join(', '), cls: 'small' },
    ], { placeholder: 'Regex filter images…' }));
}
export function renderKnownReport(kind, container, payload, ctx, extra = {}) {
    switch (kind) {
        case 'behavior': return renderBehavior(container, payload, ctx);
        case 'contracts':
        case 'ipc':
        case 'network':
        case 'crypto': return renderEvidence(container, payload, ctx, !!extra.argsEnabled);
        case 'strings': return renderStrings(container, payload, ctx);
        case 'entropy': return renderEntropy(container, payload, ctx);
        case 'driver': return renderDriver(container, payload, ctx);
        case 'ioctl': return renderIoctl(container, payload, ctx);
        case 'pechk': return renderPechk(container, payload);
        case 'find': return renderFind(container, payload, ctx);
        case 'yara': return renderYara(container, payload, ctx);
        case 'callers': return renderCallers(container, payload, ctx);
        case 'diff': return renderDiff(container, payload, ctx);
        case 'hunt': return renderHunt(container, payload, ctx);
        case 'index': return renderIndex(container, payload, ctx);
        case 'payload': return renderPayload(container, payload, ctx);
        case 'patch': return renderPatch(container, payload);
        case 'api': return renderApi(container, payload);
        case 'scan': return renderScanSummary(container, payload, ctx);
        default: container.append(jsonTree(payload, kind || 'report'));
    }
}
