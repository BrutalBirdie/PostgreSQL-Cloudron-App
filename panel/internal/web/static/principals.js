// Turns every textarea[data-principals] ("user:anna, group:developers") into a
// chip list with a fuzzy search over the Cloudron users and groups that may
// access this app. The textarea stays the form field, so the form also works
// without JavaScript.
'use strict';

(function () {
    const fields = document.querySelectorAll('textarea[data-principals]');
    if (!fields.length || !window.fetch) return;

    let directory = null;
    function load() {
        if (!directory) {
            directory = fetch('/admin/principals', { headers: { Accept: 'application/json' } })
                .then((r) => (r.ok ? r.json() : []))
                .catch(() => []);
        }
        return directory;
    }

    // characters of the query in order, earlier and contiguous matches score higher
    function score(query, text) {
        query = query.toLowerCase();
        text = text.toLowerCase();
        if (!query) return 1;
        const direct = text.indexOf(query);
        if (direct >= 0) return 1000 - direct;
        let pos = -1, gaps = 0;
        for (const ch of query) {
            const next = text.indexOf(ch, pos + 1);
            if (next < 0) return 0;
            gaps += next - pos - 1;
            pos = next;
        }
        return 500 - gaps;
    }

    function parse(value) {
        return value.split(/[,\n]/).map((t) => t.trim()).filter(Boolean).map((t) => {
            const i = t.indexOf(':');
            return i < 0 ? { kind: 'user', name: t } : { kind: t.slice(0, i).trim().toLowerCase(), name: t.slice(i + 1).trim() };
        });
    }

    fields.forEach(function (field) {
        const box = document.createElement('div');
        box.className = 'principals';
        const chips = document.createElement('div');
        chips.className = 'chips';
        const input = document.createElement('input');
        input.type = 'text';
        input.placeholder = 'Search users and groups';
        input.setAttribute('aria-label', 'Search users and groups');
        input.autocomplete = 'off';
        const list = document.createElement('ul');
        list.className = 'suggestions';
        list.hidden = true;
        box.append(chips, input, list);
        field.hidden = true;
        field.after(box);

        let selected = parse(field.value);
        let options = [];
        let active = 0;

        function sync() {
            field.value = selected.map((p) => `${p.kind}:${p.name}`).join(', ');
            chips.replaceChildren(...selected.map(function (p, i) {
                const chip = document.createElement('span');
                chip.className = 'chip';
                chip.textContent = (p.kind === 'group' ? 'group ' : '') + p.name + ' ';
                const remove = document.createElement('button');
                remove.type = 'button';
                remove.className = 'link';
                remove.textContent = '×';
                remove.setAttribute('aria-label', `Remove ${p.kind} ${p.name}`);
                remove.addEventListener('click', function () {
                    selected.splice(i, 1);
                    sync();
                });
                chip.append(remove);
                return chip;
            }));
        }

        function add(p) {
            if (!selected.some((s) => s.kind === p.kind && s.name === p.name)) selected.push({ kind: p.kind, name: p.name });
            input.value = '';
            list.hidden = true;
            sync();
            input.focus();
        }

        async function suggest() {
            const all = await load();
            const q = input.value.trim();
            options = all
                .filter((p) => !selected.some((s) => s.kind === p.kind && s.name === p.name))
                .map((p) => ({ p, s: Math.max(score(q, p.name), score(q, p.label)) }))
                .filter((x) => x.s > 0)
                .sort((a, b) => b.s - a.s || a.p.label.localeCompare(b.p.label))
                .slice(0, 8)
                .map((x) => x.p);
            active = 0;
            list.replaceChildren(...options.map(function (p, i) {
                const li = document.createElement('li');
                li.textContent = (p.kind === 'group' ? 'Group: ' : 'User: ') + p.label;
                li.dataset.kind = p.kind;
                li.dataset.name = p.name;
                if (i === active) li.className = 'active';
                li.addEventListener('mousedown', function (e) {
                    e.preventDefault();
                    add(p);
                });
                return li;
            }));
            list.hidden = options.length === 0;
        }

        input.addEventListener('input', suggest);
        input.addEventListener('focus', suggest);
        input.addEventListener('blur', function () { list.hidden = true; });
        input.addEventListener('keydown', function (e) {
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                e.preventDefault();
                active = (active + (e.key === 'ArrowDown' ? 1 : -1) + options.length) % Math.max(options.length, 1);
                list.querySelectorAll('li').forEach((li, i) => li.classList.toggle('active', i === active));
            } else if (e.key === 'Enter' && !list.hidden && options[active]) {
                e.preventDefault();
                add(options[active]);
            } else if (e.key === 'Backspace' && !input.value && selected.length) {
                selected.pop();
                sync();
            }
        });
        sync();
    });
})();
