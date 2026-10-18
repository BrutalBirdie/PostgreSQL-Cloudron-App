// Adds a copy icon button to the right of every code[data-copy]. Without
// JavaScript or the clipboard API the text stays selectable as before.
'use strict';

(function () {
    if (!navigator.clipboard) return;
    const svg = (paths) => `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
    const copyIcon = svg('<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>');
    const doneIcon = svg('<path d="M20 6 9 17l-5-5"/>');
    for (const code of document.querySelectorAll('code[data-copy]')) {
        const wrap = document.createElement('span');
        wrap.className = 'copyable';
        code.replaceWith(wrap);
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'copy';
        button.innerHTML = copyIcon;
        button.title = 'Copy ' + code.dataset.copy;
        button.setAttribute('aria-label', button.title);
        button.addEventListener('click', () => {
            navigator.clipboard.writeText(code.textContent.trim()).then(() => {
                button.innerHTML = doneIcon;
                button.title = 'Copied';
                setTimeout(() => { button.innerHTML = copyIcon; button.title = button.getAttribute('aria-label'); }, 2000);
            });
        });
        wrap.append(code, button);
    }
})();
