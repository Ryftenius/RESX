export function createSearchBar(parent: HTMLElement, placeholder: string): { bar: HTMLDivElement; inp: HTMLInputElement; lbl: HTMLSpanElement } {
    const bar = document.createElement('div');
    bar.className = 'searchbar';

    const input = document.createElement('input');
    input.type = 'text';
    input.placeholder = placeholder;
    input.autocomplete = 'off';
    input.spellcheck = false;

    const label = document.createElement('span');
    label.className = 'count-lbl';

    bar.append(input, label);
    parent.appendChild(bar);
    return { bar, inp: input, lbl: label };
}

export function wireSearch(input: HTMLInputElement, rows: HTMLElement[], label: HTMLElement, totalLabel: string): void {
    input.addEventListener('input', () => {
        const raw = input.value.trim();
        let re: RegExp | null = null;
        let errEl = input.parentElement?.querySelector('.regex-err') as HTMLSpanElement | null;
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
            } catch (ex) {
                input.classList.add('invalid');
                errEl.textContent = ex instanceof Error ? ex.message : String(ex);
                return;
            }
        } else {
            input.classList.remove('invalid');
            errEl.textContent = '';
        }

        let visible = 0;
        rows.forEach(row => {
            const show = !re || re.test(row.textContent || '');
            row.style.display = show ? '' : 'none';
            if (show) visible++;
        });
        label.textContent = re ? `${visible} / ${rows.length}` : totalLabel;
    });
}

export function sortTable(th: HTMLTableCellElement, tbl: HTMLTableElement): void {
    const colIdx = Array.from(th.parentElement?.children || []).indexOf(th);
    const asc = !th.classList.contains('sort-asc');
    tbl.querySelectorAll('thead th').forEach(t => t.classList.remove('sort-asc', 'sort-desc'));
    th.classList.add(asc ? 'sort-asc' : 'sort-desc');
    const body = tbl.tBodies[0];
    const visible = Array.from(body.rows).filter(r => r.style.display !== 'none');
    const hidden = Array.from(body.rows).filter(r => r.style.display === 'none');
    visible.sort((a, b) => {
        const av = (a.cells[colIdx]?.textContent || '').trim();
        const bv = (b.cells[colIdx]?.textContent || '').trim();
        return asc ? compareTableValues(av, bv) : compareTableValues(bv, av);
    });
    [...visible, ...hidden].forEach(r => body.appendChild(r));
}

function compareTableValues(a: string, b: string): number {
    const bigintPattern = /^[-+]?(?:0x[0-9a-f]+|\d+)$/i;
    if (bigintPattern.test(a) && bigintPattern.test(b)) {
        try {
            const na = BigInt(a);
            const nb = BigInt(b);
            if (na < nb) return -1;
            if (na > nb) return 1;
            return 0;
        } catch {}
    }
    const na = a.startsWith('0x') ? parseInt(a, 16) : parseFloat(a);
    const nb = b.startsWith('0x') ? parseInt(b, 16) : parseFloat(b);
    if (!isNaN(na) && !isNaN(nb)) return na - nb;
    return a.localeCompare(b);
}
