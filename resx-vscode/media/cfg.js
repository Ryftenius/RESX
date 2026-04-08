export function renderCfgVisual(cfgText, panel, deps) {
    const { blocks, entryId } = parseCfgText(cfgText, deps);
    panel.innerHTML = '';
    if (!blocks.size) {
        panel.className = 'pre-block';
        panel.textContent = cfgText || 'No CFG data.';
        return;
    }
    panel.className = '';
    const HEADER_H = 24;
    const INSN_H = 16;
    const BW = blocks.size > 80 ? 260 : blocks.size > 32 ? 300 : 340;
    const H_GAP = blocks.size > 80 ? 48 : 64;
    const V_GAP = blocks.size > 80 ? 70 : 92;
    const PAD_Y = 18;
    const blockIds = [...blocks.keys()];
    const indeg = new Map();
    blockIds.forEach(id => indeg.set(id, 0));
    blocks.forEach(blk => blk.edges.forEach(e => {
        if (e.target && blocks.has(e.target))
            indeg.set(e.target, (indeg.get(e.target) || 0) + 1);
    }));
    const start = entryId && blocks.has(entryId)
        ? entryId
        : blockIds.find(id => (indeg.get(id) || 0) === 0) || blockIds[0];
    const layerOf = new Map();
    const q = [start];
    layerOf.set(start, 0);
    while (q.length) {
        const cur = q.shift();
        if (!cur)
            continue;
        const ly = layerOf.get(cur) || 0;
        const blk = blocks.get(cur);
        if (!blk)
            continue;
        for (const edge of blk.edges) {
            if (!edge.target || !blocks.has(edge.target))
                continue;
            const prev = layerOf.get(edge.target);
            if (prev == null || ly + 1 < prev) {
                layerOf.set(edge.target, ly + 1);
                q.push(edge.target);
            }
        }
    }
    blockIds.forEach(id => {
        if (!layerOf.has(id))
            layerOf.set(id, (layerOf.get(start) || 0) + 1);
    });
    const layers = new Map();
    blockIds.forEach(id => {
        const ly = layerOf.get(id) || 0;
        if (!layers.has(ly))
            layers.set(ly, []);
        layers.get(ly)?.push(id);
    });
    const sortedLayers = [...layers.entries()].sort((a, b) => a[0] - b[0]);
    const blockH = (id) => {
        const blk = blocks.get(id);
        return HEADER_H + 10 + Math.min((blk?.insns.length || 0), 22) * INSN_H + 8;
    };
    const layerY = new Map();
    let totalH = PAD_Y;
    let totalW = 0;
    sortedLayers.forEach(([ly, ids]) => {
        const maxH = Math.max(...ids.map(blockH));
        layerY.set(ly, totalH);
        totalH += maxH + V_GAP;
        const layW = ids.length * BW + (ids.length - 1) * H_GAP;
        totalW = Math.max(totalW, layW);
    });
    totalW += 40;
    totalH += 20;
    sortedLayers.forEach(([ly, ids]) => {
        const layW = ids.length * BW + (ids.length - 1) * H_GAP;
        const startX = (totalW - layW) / 2;
        ids.forEach((id, i) => {
            const blk = blocks.get(id);
            if (!blk)
                return;
            blk.layer = ly;
            blk.x = startX + i * (BW + H_GAP);
            blk.y = layerY.get(ly);
            blk.w = BW;
            blk.h = blockH(id);
        });
    });
    const blockCount = blocks.size;
    const legend = document.createElement('div');
    legend.className = 'cfg-legend';
    legend.innerHTML = `
        <span class="cfg-legend-item"><span class="cfg-legend-swatch cfg-swatch-entry"></span>Entry</span>
        <span class="cfg-legend-item"><span class="cfg-legend-swatch cfg-swatch-branch"></span>Branch</span>
        <span class="cfg-legend-item"><span class="cfg-legend-swatch cfg-swatch-jump"></span>Jump</span>
        <span class="cfg-legend-item"><span class="cfg-legend-swatch cfg-swatch-exit"></span>Exit</span>
        <span class="cfg-legend-item"><span class="cfg-legend-line cfg-line-taken"></span>Taken</span>
        <span class="cfg-legend-item"><span class="cfg-legend-line cfg-line-fall"></span>Fallthrough</span>
        <span class="cfg-legend-item"><span class="cfg-legend-line cfg-line-switch"></span>Switch</span>
        <span class="cfg-legend-note">${blockCount} block${blockCount === 1 ? '' : 's'} · click a block to disassemble its first instruction</span>`;
    panel.appendChild(legend);
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    svg.id = 'cfg-svg';
    svg.setAttribute('width', '100%');
    svg.setAttribute('height', '100%');
    const defs = document.createElementNS(NS, 'defs');
    const arrows = [
        ['arr-taken', '#4ec9b0'], ['arr-fall', '#569cd6'],
        ['arr-jump', '#dcdcaa'], ['arr-exit', '#f44747'],
        ['arr-switch', '#c586c0'], ['arr-default', 'rgba(128,128,128,.7)'],
    ];
    arrows.forEach(([id, color]) => {
        const marker = document.createElementNS(NS, 'marker');
        marker.setAttribute('id', id);
        marker.setAttribute('markerWidth', '10');
        marker.setAttribute('markerHeight', '8');
        marker.setAttribute('refX', '8');
        marker.setAttribute('refY', '4');
        marker.setAttribute('markerUnits', 'strokeWidth');
        marker.setAttribute('orient', 'auto');
        const poly = document.createElementNS(NS, 'polygon');
        poly.setAttribute('points', '0 0, 10 4, 0 8');
        poly.setAttribute('fill', color);
        marker.appendChild(poly);
        defs.appendChild(marker);
    });
    svg.appendChild(defs);
    const gViewport = document.createElementNS(NS, 'g');
    const gEdges = document.createElementNS(NS, 'g');
    const gBlocks = document.createElementNS(NS, 'g');
    const outerLeftX = 18;
    const outerRightX = totalW - 18;
    const incomingLanes = new Map();
    for (const [id, blk] of blocks) {
        blk.edges.forEach((edge, edgeIdx) => {
            if (!edge.target)
                return;
            const tgt = blocks.get(edge.target);
            if (!tgt || blk.x == null || blk.w == null || blk.y == null || blk.h == null || tgt.x == null || tgt.w == null || tgt.y == null || tgt.h == null) {
                return;
            }
            const sourceCx = blk.x + blk.w / 2;
            const targetCx = tgt.x + tgt.w / 2;
            const isForward = (tgt.layer || 0) > (blk.layer || 0);
            const laneKey = `${edge.target}:${blk.layer || 0}`;
            const laneIndex = incomingLanes.get(laneKey) || 0;
            incomingLanes.set(laneKey, laneIndex + 1);
            let points;
            if (isForward) {
                const sx = sourceCx + ((edgeIdx % 3) - 1) * 18;
                const sy = blk.y + blk.h;
                const ex = targetCx + (laneIndex % 5 - 2) * 14;
                const ey = tgt.y;
                const midY = sy + Math.max(28, (ey - sy) / 2);
                points = [`${sx},${sy}`, `${sx},${midY}`, `${ex},${midY}`, `${ex},${ey - 10}`].join(' ');
            }
            else {
                const goLeft = targetCx <= sourceCx;
                const laneX = goLeft
                    ? Math.max(outerLeftX, Math.min(blk.x, tgt.x) - 34 - edgeIdx * 12)
                    : Math.min(outerRightX, Math.max(blk.x + blk.w, tgt.x + tgt.w) + 34 + edgeIdx * 12);
                const sx = goLeft ? blk.x : blk.x + blk.w;
                const sy = blk.y + HEADER_H + 14 + Math.min(edgeIdx * 8, Math.max(0, blk.h - HEADER_H - 24));
                const ex = goLeft ? tgt.x + tgt.w : tgt.x;
                const ey = tgt.y + HEADER_H + 12 + Math.min(laneIndex * 8, Math.max(0, tgt.h - HEADER_H - 24));
                points = [`${sx},${sy}`, `${laneX},${sy}`, `${laneX},${ey}`, `${ex + (goLeft ? 10 : -10)},${ey}`].join(' ');
            }
            const cls = {
                taken: 'cfg-edge-taken',
                fallthrough: 'cfg-edge-fallthrough',
                jump: 'cfg-edge-jump',
                exit: 'cfg-edge-exit',
                switch: 'cfg-edge-switch',
            }[edge.kind] || 'cfg-edge';
            const line = document.createElementNS(NS, 'polyline');
            line.setAttribute('points', points);
            line.setAttribute('class', `cfg-edge ${cls}`);
            gEdges.appendChild(line);
        });
    }
    const kindOf = (id, idx) => {
        if (idx === 0 || id === entryId)
            return 'entry';
        const blk = blocks.get(id);
        if (!blk)
            return 'normal';
        if (blk.edges.some(e => e.kind === 'exit'))
            return 'exit';
        if (blk.edges.some(e => e.kind === 'taken') && blk.edges.some(e => e.kind === 'fallthrough'))
            return 'branch';
        if (blk.edges.some(e => e.kind === 'jump'))
            return 'jump';
        return 'normal';
    };
    let idx = 0;
    for (const [id, blk] of blocks) {
        if (blk.x == null || blk.y == null || blk.w == null || blk.h == null)
            continue;
        const kind = kindOf(id, idx++);
        const g = document.createElementNS(NS, 'g');
        g.setAttribute('transform', `translate(${blk.x},${blk.y})`);
        const rect = document.createElementNS(NS, 'rect');
        rect.setAttribute('width', String(blk.w));
        rect.setAttribute('height', String(blk.h));
        rect.setAttribute('rx', '4');
        rect.setAttribute('class', `cfg-block-${kind}`);
        g.appendChild(rect);
        const hdr = document.createElementNS(NS, 'rect');
        hdr.setAttribute('width', String(blk.w));
        hdr.setAttribute('height', String(HEADER_H));
        hdr.setAttribute('rx', '4');
        hdr.setAttribute('class', `cfg-hdr-${kind}`);
        g.appendChild(hdr);
        const title = document.createElementNS(NS, 'text');
        title.setAttribute('x', '8');
        title.setAttribute('y', '17');
        title.setAttribute('class', 'cfg-title');
        title.textContent = `block_${id}`;
        g.appendChild(title);
        const count = document.createElementNS(NS, 'text');
        count.setAttribute('x', String(blk.w - 8));
        count.setAttribute('y', '17');
        count.setAttribute('text-anchor', 'end');
        count.setAttribute('class', 'cfg-count');
        count.textContent = `${blk.insns.length} insn`;
        g.appendChild(count);
        for (let i = 0; i < blk.insns.length; i++) {
            const insn = blk.insns[i];
            const y = HEADER_H + 5 + i * INSN_H + 13;
            const mnemSp = insn.text.search(/[\s,]/);
            const mnem = mnemSp === -1 ? insn.text : insn.text.slice(0, mnemSp);
            const ops = mnemSp === -1 ? '' : insn.text.slice(mnemSp).trim();
            const mc = deps.cfgMnemonicClass(mnem);
            const mt = document.createElementNS(NS, 'text');
            mt.setAttribute('x', '8');
            mt.setAttribute('y', String(y));
            mt.setAttribute('class', `cfg-insn${mc ? ` ${mc}` : ''}`);
            mt.textContent = mnem.padEnd(9, ' ');
            g.appendChild(mt);
            const ot = document.createElementNS(NS, 'text');
            ot.setAttribute('x', '80');
            ot.setAttribute('y', String(y));
            ot.setAttribute('class', 'cfg-insn');
            const maxOps = blockCount > 80 ? 24 : blockCount > 32 ? 34 : 48;
            ot.textContent = ops.length > maxOps ? `${ops.slice(0, maxOps)}...` : ops;
            const otTitle = document.createElementNS(NS, 'title');
            otTitle.textContent = insn.text + (insn.comment ? ` ; ${insn.comment}` : '');
            ot.appendChild(otTitle);
            g.appendChild(ot);
        }
        g.style.cursor = 'pointer';
        g.addEventListener('click', () => deps.navigateRva(blk.startRva || `0x${id}`, `block_${id}`));
        gBlocks.appendChild(g);
    }
    gViewport.appendChild(gEdges);
    gViewport.appendChild(gBlocks);
    svg.appendChild(gViewport);
    const container = document.createElement('div');
    container.id = 'cfg-svg-container';
    container.className = blockCount > 80 ? 'cfg-large' : '';
    const toolbar = document.createElement('div');
    toolbar.className = 'cfg-toolbar';
    const zoomOutBtn = document.createElement('button');
    zoomOutBtn.className = 'cfg-tool-btn';
    zoomOutBtn.textContent = '-';
    const fitBtn = document.createElement('button');
    fitBtn.className = 'cfg-tool-btn';
    fitBtn.textContent = 'Fit';
    const resetBtn = document.createElement('button');
    resetBtn.className = 'cfg-tool-btn';
    resetBtn.textContent = '1:1';
    const zoomInBtn = document.createElement('button');
    zoomInBtn.className = 'cfg-tool-btn';
    zoomInBtn.textContent = '+';
    toolbar.append(zoomOutBtn, fitBtn, resetBtn, zoomInBtn);
    container.appendChild(svg);
    container.appendChild(toolbar);
    panel.appendChild(container);
    let scale = 1;
    let tx = 0;
    let ty = 0;
    let panning = false;
    let moved = false;
    let lastX = 0;
    let lastY = 0;
    function viewportSize() {
        return {
            w: Math.max(320, container.clientWidth || 900),
            h: Math.max(240, container.clientHeight || 640),
        };
    }
    function applyTransform() {
        const { w, h } = viewportSize();
        svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
        gViewport.setAttribute('transform', `translate(${tx} ${ty}) scale(${scale})`);
    }
    function fitToView() {
        const { w, h } = viewportSize();
        scale = Math.min((w - 40) / totalW, (h - 40) / totalH, 1);
        tx = Math.round((w - totalW * scale) / 2);
        ty = Math.round((h - totalH * scale) / 2);
        applyTransform();
    }
    function focusEntryBlock() {
        const entry = blocks.get(entryId);
        if (!entry || entry.x == null || entry.y == null || entry.w == null || entry.h == null) {
            fitToView();
            return;
        }
        const { w, h } = viewportSize();
        const targetScale = Math.min(Math.max(0.55, Math.min((w - 80) / (entry.w + 140), (h - 80) / (Math.min(totalH, entry.h + 240)))), 1);
        scale = targetScale;
        tx = Math.round(w * 0.5 - (entry.x + entry.w / 2) * scale);
        ty = Math.round(Math.max(24, h * 0.18 - entry.y * scale));
        applyTransform();
    }
    function zoomAt(clientX, clientY, factor) {
        const rect = svg.getBoundingClientRect();
        const x = clientX - rect.left;
        const y = clientY - rect.top;
        const nextScale = Math.max(0.2, Math.min(3.5, scale * factor));
        const wx = (x - tx) / scale;
        const wy = (y - ty) / scale;
        scale = nextScale;
        tx = x - wx * scale;
        ty = y - wy * scale;
        applyTransform();
    }
    container.addEventListener('wheel', e => {
        e.preventDefault();
        zoomAt(e.clientX, e.clientY, e.deltaY < 0 ? 1.12 : 0.88);
    }, { passive: false });
    svg.addEventListener('mousedown', e => {
        if (e.button !== 0 && e.button !== 1)
            return;
        panning = true;
        moved = false;
        lastX = e.clientX;
        lastY = e.clientY;
        container.classList.add('panning');
    });
    window.addEventListener('mousemove', e => {
        if (!panning)
            return;
        const dx = e.clientX - lastX;
        const dy = e.clientY - lastY;
        if (Math.abs(dx) > 1 || Math.abs(dy) > 1)
            moved = true;
        tx += dx;
        ty += dy;
        lastX = e.clientX;
        lastY = e.clientY;
        applyTransform();
    });
    window.addEventListener('mouseup', () => {
        panning = false;
        container.classList.remove('panning');
        requestAnimationFrame(() => { moved = false; });
    });
    zoomOutBtn.addEventListener('click', () => {
        const rect = svg.getBoundingClientRect();
        zoomAt(rect.left + rect.width / 2, rect.top + rect.height / 2, 0.88);
    });
    zoomInBtn.addEventListener('click', () => {
        const rect = svg.getBoundingClientRect();
        zoomAt(rect.left + rect.width / 2, rect.top + rect.height / 2, 1.12);
    });
    fitBtn.addEventListener('click', () => { fitToView(); });
    resetBtn.addEventListener('click', () => { focusEntryBlock(); });
    const resizeObs = new ResizeObserver(() => applyTransform());
    resizeObs.observe(container);
    gBlocks.querySelectorAll('g').forEach(node => {
        node.addEventListener('click', e => {
            if (moved)
                e.stopImmediatePropagation();
        }, true);
    });
    if (blockCount <= 18)
        fitToView();
    else
        focusEntryBlock();
}
function parseCfgText(text, deps) {
    const blocks = new Map();
    let current = null;
    let inEdges = false;
    let entryId = null;
    for (const line of text.split('\n')) {
        const em = line.match(/entry\s*:\s*block_([0-9A-Fa-f]+)/);
        if (em) {
            entryId = em[1];
            continue;
        }
        const bm = line.match(/^block_([0-9A-Fa-f]+):\s+\[(\d+) insn\]/);
        if (bm) {
            current = { id: bm[1], insns: [], edges: [], startRva: null };
            blocks.set(bm[1], current);
            inEdges = false;
            continue;
        }
        if (!current)
            continue;
        if (line.trim() === 'edges:') {
            inEdges = true;
            continue;
        }
        if (inEdges) {
            const em2 = line.match(/\[(\w+)\]\s+(.+)/);
            if (em2) {
                const tm = em2[2].match(/block_([0-9A-Fa-f]+)/);
                current.edges.push({ kind: em2[1], label: em2[2], target: tm ? tm[1] : null });
            }
        }
        else if (line.startsWith('    0x')) {
            const im = line.match(/^\s*(0x[0-9A-Fa-f]+)\s+([0-9A-F ]+?)\s{2,}(.*?)(?:\s{2,};\s*(.*))?$/);
            if (!im)
                continue;
            const rva = deps.normalizeRva(im[1]);
            const bytes = im[2].trim();
            const txt = (im[3] || '').trim();
            const cmt = (im[4] || '').trim();
            if (!current.startRva)
                current.startRva = rva;
            current.insns.push({ rva, bytes, text: txt, comment: cmt });
        }
    }
    return { blocks, entryId: entryId || blocks.keys().next().value };
}
