// Progressive enhancements for every page. Without JavaScript the sheets
// still open (popover attribute) and every form posts normally.
'use strict';

(function () {
    document.documentElement.classList.add('js');
    const toastEl = document.getElementById('toast');
    let toastTimer;

    function toast(text) {
        toastEl.textContent = text;
        toastEl.hidden = false;
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => { toastEl.hidden = true; }, 2600);
    }

    function init(root) {
        if (navigator.clipboard) {
            root.querySelectorAll('button.copy[data-copy]').forEach(function (button) {
                button.hidden = false;
                button.addEventListener('click', function () {
                    navigator.clipboard.writeText(button.dataset.copy).then(function () {
                        button.classList.add('done');
                        button.querySelector('use').setAttribute('href', '#i-check');
                        setTimeout(function () {
                            button.classList.remove('done');
                            button.querySelector('use').setAttribute('href', '#i-copy');
                        }, 1500);
                    });
                });
            });
        }
        // destructive buttons stay disabled until the name is typed
        root.querySelectorAll('input[data-confirm]').forEach(function (input) {
            const button = input.form.querySelector('button.needs-confirm');
            if (!button) return;
            const update = () => { button.disabled = input.value !== input.dataset.confirm; };
            input.addEventListener('input', update);
            update();
        });
        root.querySelectorAll('form[data-schedule]').forEach(function (form) {
            const cron = form.elements.cron;
            form.querySelectorAll('input[name=preset]').forEach(function (radio) {
                radio.addEventListener('change', function () {
                    if (radio.value !== 'custom') cron.value = radio.value;
                });
            });
            cron.addEventListener('input', function () { form.querySelector('input[name=preset][value=custom]').checked = true; });
        });
    }

    window.pgpanel = { init, toast };
    init(document);

    // a link like /admin/roles#sheet-role-shop opens that sheet
    const target = location.hash.startsWith('#sheet-') && document.getElementById(location.hash.slice(1));
    if (target && target.showPopover) target.showPopover();

    // the current admin tab starts at the left, the next ones are visible right of it
    // after the web fonts, they change the tab widths
    const tab = document.querySelector('.tabs [aria-current=page]');
    if (tab) document.fonts.ready.then(() => { tab.parentElement.scrollLeft = tab.offsetLeft; });

    const account = document.querySelector('form[data-autosave]');
    if (account) {
        account.addEventListener('change', function (event) {
            if (event.target.name === 'show_labels') document.documentElement.classList.toggle('labels', event.target.checked);
            fetch(account.action, {
                method: 'POST',
                body: new URLSearchParams(new FormData(account)),
                headers: { Accept: 'application/json' },
            }).then(
                (r) => toast(r.ok ? 'Saved' : 'Not saved, reload the page and try again'),
                () => toast('Not saved, check your connection'),
            );
        });
    }
})();
