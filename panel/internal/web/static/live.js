// Live job progress on the database page. The server sends the state of the
// newest job as server-sent events. Progress updates in place; when a job
// starts or ends, the parts of the page marked data-live are replaced with
// fresh ones, without reloading the page.
'use strict';

(function () {
    const url = document.currentScript.dataset.events;
    const slot = document.getElementById('job-slot');
    if (!url || !slot || !window.EventSource) return;
    let key = slot.dataset.key;
    let refreshing = false;

    async function refresh() {
        if (refreshing) return;
        refreshing = true;
        try {
            const res = await fetch(location.pathname, { headers: { Accept: 'text/html' } });
            if (!res.ok) return;
            const doc = new DOMParser().parseFromString(await res.text(), 'text/html');
            document.querySelectorAll('[data-live]').forEach(function (part) {
                const fresh = doc.querySelector(`[data-live="${part.dataset.live}"]`);
                if (!fresh) return;
                part.replaceChildren(...fresh.childNodes);
                window.pgpanel.init(part);
            });
            key = doc.getElementById('job-slot').dataset.key;
        } finally {
            refreshing = false;
        }
    }

    function update(job) {
        const bar = document.getElementById('job-bar');
        if (!bar) return refresh();
        document.getElementById('job-title').textContent = job.title;
        document.getElementById('job-step').textContent = job.step || 'Waiting for the worker';
        if (job.progress === null) {
            bar.removeAttribute('value');
            document.getElementById('job-pct').textContent = '';
        } else {
            bar.value = job.progress;
            document.getElementById('job-pct').textContent = ` · ${job.progress}%`;
        }
    }

    const events = new EventSource(url);
    events.onmessage = function (e) {
        const job = JSON.parse(e.data);
        if (job.key !== key) refresh();
        else if (job.active) update(job);
    };
})();
