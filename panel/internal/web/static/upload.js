// Hashes the chosen file in chunks with hash-wasm (Web Crypto has no streaming
// digest, so it cannot hash multi-GB files) and uploads it with the checksum in
// X-File-SHA256. Without JavaScript the form still posts normally.
'use strict';

(function () {
    const form = document.getElementById('upload-form');
    if (!form || !window.hashwasm || !window.XMLHttpRequest) return;

    const status = document.getElementById('upload-status');
    const progress = document.getElementById('upload-progress');
    const button = form.querySelector('button[type=submit]');
    const CHUNK = 8 * 1024 * 1024;

    function show(text, value, max) {
        status.textContent = text;
        progress.hidden = max === undefined;
        if (max !== undefined) {
            progress.max = max;
            progress.value = value;
        }
    }

    async function sha256(file) {
        const hasher = await window.hashwasm.createSHA256();
        hasher.init();
        for (let offset = 0; offset < file.size; offset += CHUNK) {
            const chunk = new Uint8Array(await file.slice(offset, offset + CHUNK).arrayBuffer());
            hasher.update(chunk);
            show(`Calculating checksum ${Math.floor((offset + chunk.length) / file.size * 100)}%`, offset + chunk.length, file.size);
        }
        return hasher.digest('hex');
    }

    form.addEventListener('submit', async function (event) {
        const file = form.elements.file.files[0];
        if (!file) return;
        event.preventDefault();
        button.disabled = true;
        status.classList.remove('error');

        let sum;
        try {
            sum = await sha256(file);
        } catch (e) {
            show('Could not calculate the checksum in this browser: ' + e.message);
            status.classList.add('error');
            button.disabled = false;
            return;
        }

        const xhr = new XMLHttpRequest();
        xhr.open('POST', form.action);
        xhr.setRequestHeader('X-File-SHA256', sum);
        xhr.setRequestHeader('Accept', 'application/json');
        xhr.upload.onprogress = function (e) {
            if (e.lengthComputable) show(`Uploading ${Math.floor(e.loaded / e.total * 100)}%`, e.loaded, e.total);
        };
        xhr.onload = function () {
            let body = {};
            try { body = JSON.parse(xhr.responseText); } catch (e) { body = { error: `Upload failed (HTTP ${xhr.status}).` }; }
            if (xhr.status === 200 && body.redirect) {
                window.location.assign(body.redirect);
                return;
            }
            show(body.error || `Upload failed (HTTP ${xhr.status}).`);
            status.classList.add('error');
            button.disabled = false;
        };
        xhr.onerror = function () {
            show('The upload was interrupted. Try again, or copy large files with the Cloudron File Manager.');
            status.classList.add('error');
            button.disabled = false;
        };
        // FormData keeps the field order: csrf first, file last
        xhr.send(new FormData(form));
        show('Uploading 0%', 0, file.size);
    });
})();
