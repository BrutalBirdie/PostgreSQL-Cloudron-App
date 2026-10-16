// Browser steps of the end-to-end test, driven by run.sh. Each step is a
// separate process so run.sh can check PostgreSQL in between.
import { chromium } from 'playwright';
import fs from 'node:fs';
import crypto from 'node:crypto';

const BASE = 'http://localhost:8000';
const STATE = '/work/state.json';
const step = process.argv[2];
const state = fs.existsSync(STATE) ? JSON.parse(fs.readFileSync(STATE, 'utf8')) : {};
let failures = 0;

function check(name, ok, detail = '') {
    console.log(`${ok ? 'PASS' : 'FAIL'} [${step}] ${name}${!ok && detail ? ' :: ' + detail : ''}`);
    if (!ok) failures++;
}

const browser = await chromium.launch();

let lastPage = null;

async function session(user) {
    const file = `/work/${user}.json`;
    const ctx = await browser.newContext({ acceptDownloads: true, storageState: fs.existsSync(file) ? file : undefined });
    const page = await ctx.newPage();
    lastPage = page;
    return { ctx, page, save: () => ctx.storageState({ path: file }) };
}

async function login(page, user, groups) {
    await page.goto(BASE + '/');
    if (await page.getByRole('button', { name: `Log out ${user}` }).count()) return;
    await page.getByRole('link', { name: 'Sign in with Cloudron' }).click();
    await page.fill('input[name=username]', user);
    await page.fill('textarea[name=claims]', JSON.stringify({ groups, name: user }));
    await page.click('input[type=submit]');
    await page.waitForURL(BASE + '/');
}

// waits until the newest job is done or failed, and reports a page that hides a
// job that is still queued or running
async function waitForJobs(page, url) {
    for (let i = 0; i < 120; i++) {
        await page.goto(url);
        const newest = page.locator('section', { hasText: 'Recent jobs' }).locator('tbody tr').first();
        const status = (await newest.count()) ? (await newest.locator('td').nth(3).textContent()).trim() : '';
        const banner = (await page.locator('.job-progress').count()) > 0;
        if (/^(done|failed)/.test(status)) return true;
        if (!banner) check('progress banner shown while a job is active', false, `status=${status.slice(0, 80)}`);
        await page.waitForTimeout(500);
    }
    return false;
}

async function csrf(page) {
    return page.locator('input[name=csrf]').first().inputValue();
}

async function secretFromPage(page) {
    return (await page.locator('code.secret').textContent()).trim();
}

const steps = {
    async admin() {
        const { page, save } = await session('ann');
        await login(page, 'ann', ['postgres-admins']);
        check('admin sees Admin link', await page.getByRole('link', { name: 'Admin', exact: true }).isVisible());

        const res = await page.goto(BASE + '/admin');
        check('admin page loads', res.status() === 200, String(res.status()));

        await page.fill('textarea[name=allowlist]', '1.2.3.4\nhost all all 0.0.0.0/0 trust');
        await page.click('form[action="/admin/allowlist"] button');
        check('injected allowlist rejected', (await page.content()).includes('Nothing saved'));

        await page.goto(BASE + '/admin');
        await page.fill('textarea[name=allowlist]', process.env.APP_IP);
        await page.click('form[action="/admin/allowlist"] button');
        await page.waitForURL(BASE + '/admin');
        check('allowlist saved', (await page.inputValue('textarea[name=allowlist]')).includes(process.env.APP_IP + '/32'));

        const form = page.locator('form[action="/admin/roles"]');
        await form.locator('input[name=name]').fill('e2e_bob');
        const search = form.locator('.principals input');
        check('owner picker replaces the text field', (await search.count()) === 1 && !(await form.locator('textarea[name=owners]').isVisible()));
        await search.fill('bbld'); // fuzzy: "Bob Builder"
        const suggestion = form.locator('.suggestions li').first();
        await suggestion.waitFor();
        check('fuzzy search finds bob', (await suggestion.textContent()) === 'User: bob (Bob Builder)', await suggestion.textContent());
        await search.press('Enter');
        await search.fill('dbt');
        await form.locator('.suggestions li', { hasText: 'Group: dbteam' }).click();
        await search.fill('xyzq');
        check('no suggestion for nonsense', (await form.locator('.suggestions li').count()) === 0);
        check('picker fills the owners field', (await form.locator('textarea[name=owners]').inputValue()) === 'user:bob, group:dbteam');
        await form.locator('input[name=conn_limit]').fill('5');
        check('max databases hidden while unchecked', !(await form.locator('input[name=max_databases]').isVisible()));
        await form.locator('input[name=allow_create_db]').check();
        check('max databases shown when checked', await form.locator('input[name=max_databases]').isVisible());
        await form.locator('input[name=max_databases]').fill('2');
        await form.locator('button[type=submit]').click();
        await page.waitForURL(BASE + '/admin/roles/e2e_bob');
        let html = await page.content();
        check('role page shows the owners', html.includes('user:bob, group:dbteam'));
        check('no password for the shared role', !html.includes('code class="secret"'));

        // without JavaScript the owners field is typed
        const plain = await browser.newContext({ storageState: undefined, javaScriptEnabled: false });
        await plain.addCookies((await page.context().cookies()));
        const noJs = await plain.newPage();
        await noJs.goto(BASE + '/admin');
        const plainForm = noJs.locator('form[action="/admin/roles"]');
        await plainForm.locator('input[name=name]').fill('e2e_eve');
        await plainForm.locator('textarea[name=owners]').fill('user:nobody');
        await plainForm.locator('button[type=submit]').click();
        check('unknown owner rejected', (await noJs.content()).includes('There is no Cloudron user'));
        await noJs.goto(BASE + '/admin');
        await plainForm.locator('input[name=name]').fill('e2e_eve');
        await plainForm.locator('textarea[name=owners]').fill('user:eve');
        await plainForm.locator('button[type=submit]').click();
        await noJs.waitForURL(BASE + '/admin/roles/e2e_eve');
        check('owners typed without JavaScript', (await noJs.content()).includes('user:eve'));
        await plain.close();
        await save();
    },

    async bobLogin() {
        const { page, save } = await session('bob');
        await login(page, 'bob', []);
        check('bob has no login yet', (await page.content()).includes('Create my password'));
        await page.click('form[action="/roles/e2e_bob/password"] button');
        state.bobPassword = await secretFromPage(page);
        check('bob login password shown once', state.bobPassword.length === 32);
        check('connection URL uses the own login', (await page.content()).includes('postgresql://e2e_bob.bob@pg.test:5432/e2e_bob'));
        await save();
    },

    async eveLogin() {
        const { page, save } = await session('eve');
        await login(page, 'eve', []);
        await page.click('form[action="/roles/e2e_eve/password"] button');
        state.evePassword = await secretFromPage(page);
        check('eve login created', state.evePassword.length === 32 && (await page.content()).includes('e2e_eve.eve'));
        await save();
    },

    async carol() {
        const { page, save } = await session('carol');
        await login(page, 'carol', []);
        let html = await page.content();
        check('carol sees the role through her group', html.includes('Role <code>e2e_bob</code>') && html.includes('group dbteam'));
        check('carol cannot open the admin page', (await page.goto(BASE + '/admin')).status() === 403);
        await page.goto(BASE + '/');
        await page.click('form[action="/roles/e2e_bob/password"] button');
        state.carolPassword = await secretFromPage(page);
        check('carol gets her own login', (await page.content()).includes('e2e_bob.carol'));
        check('carol manages the database', (await page.goto(BASE + '/databases/e2e_bob')).status() === 200);
        await save();
    },

    async carolGone() {
        const { page } = await session('carol');
        await page.goto(BASE + '/');
        check('carol no longer sees the role', !(await page.content()).includes('Role <code>e2e_bob</code>'));
        check('carol no longer opens the database', (await page.goto(BASE + '/databases/e2e_bob')).status() === 404);
    },

    async bob1() {
        const { page, save } = await session('bob');
        await login(page, 'bob', []);
        let html = await page.content();
        check('bob sees own role', html.includes('Role <code>e2e_bob</code>'));
        check('bob does not see eve role', !html.includes('e2e_eve'));
        check('bob has no Admin link', !(await page.getByRole('link', { name: 'Admin', exact: true }).count()));
        check('usage counter', html.includes('1 of 2 databases used'));

        await page.fill('form[action="/roles/e2e_bob/databases"] input[name=name]', 'e2e_bob_two');
        await page.click('form[action="/roles/e2e_bob/databases"] button');
        await page.waitForURL(BASE + '/');
        html = await page.content();
        check('self-service database created', html.includes('e2e_bob_two') && html.includes('2 of 2 databases used'));
        check('create form hidden at limit', !(await page.locator('form[action="/roles/e2e_bob/databases"]').count()));
        const over = await page.request.post(BASE + '/roles/e2e_bob/databases', { form: { csrf: await csrf(page), name: 'e2e_bob_three' } });
        check('limit enforced server side', over.status() === 400 && (await over.text()).includes('Limit reached'), String(over.status()));

        await page.goto(BASE + '/databases/e2e_bob');
        await page.fill('input[name=cron]', '*/5 * * * *');
        await page.click('button[value=save]');
        check('too frequent schedule rejected', (await page.content()).includes('at most once per hour'));
        await page.goto(BASE + '/databases/e2e_bob');
        await page.fill('input[name=cron]', '0 * * * *');
        await page.click('button[value=save]');
        await page.waitForURL(BASE + '/databases/e2e_bob');
        check('schedule saved', (await page.content()).includes('Schedule <code>0 * * * *</code>'));

        await page.click('text=Create snapshot now');
        check('snapshot job finished', await waitForJobs(page, BASE + '/databases/e2e_bob'));
        html = await page.content();
        check('snapshot listed', html.includes('class="tag">manual'), html.match(/<td class="error">[^<]*/)?.[0] ?? '');
        check('snapshot job done', !html.includes('failed'), html.match(/<span class="error">[^<]*/)?.[0] ?? '');

        const row = page.locator('tbody tr').first();
        state.bobSnapshot = (await row.locator('td').first().textContent()).trim();
        for (const [label, test] of [['Download .dump', (b) => b.subarray(0, 5).toString() === 'PGDMP'],
            ['Download .sql', (b) => b.toString().includes('CREATE TABLE "public"."t"') && b.toString().includes('COPY "public"."t"')]]) {
            const [dl] = await Promise.all([page.waitForEvent('download'), row.getByRole('link', { name: label }).click()]);
            const failure = await dl.failure();
            const body = failure ? Buffer.alloc(0) : fs.readFileSync(await dl.path());
            check(`${label} content`, !failure && test(body), failure ?? body.subarray(0, 80).toString());
        }

        await page.goto(BASE + '/');
        await page.click('form[action="/roles/e2e_bob/password"] button');
        state.bobOldPassword = state.bobPassword;
        state.bobPassword = await secretFromPage(page);
        check('password rotated', state.bobPassword.length === 32 && state.bobPassword !== state.bobOldPassword);
        await save();
    },

    async bob2() {
        const { page, save } = await session('bob');
        await page.goto(BASE + '/databases/e2e_bob');
        const row = page.locator('tbody tr', { hasText: 'manual' }).first();
        await row.getByRole('link', { name: 'Restore' }).click();
        check('restore confirmation page', (await page.content()).includes('Restore snapshot #'));
        await page.fill('input[name=confirm]', 'wrong');
        await page.click('button:has-text("Restore snapshot")');
        check('wrong confirmation rejected', (await page.content()).includes('Type the database name'));
        await page.goBack();
        await page.fill('input[name=confirm]', 'e2e_bob');
        await page.click('button:has-text("Restore snapshot")');
        await page.waitForURL(BASE + '/databases/e2e_bob');
        check('restore job finished', await waitForJobs(page, BASE + '/databases/e2e_bob'));
        const html = await page.content();
        check('restore job done', html.includes('restore of #') && !html.includes('>failed<'), html.match(/<span class="error">[^<]*/)?.[0] ?? '');
        check('safety snapshot taken', html.includes('before restore'));
        await save();
    },

    // screenshots for the manifest's mediaLinks, only run with SCREENSHOTS=1
    async screenshots() {
        fs.mkdirSync('/work/shots', { recursive: true });
        for (const [user, url, name] of [['bob', '/', 'databases'], ['bob', '/databases/e2e_bob', 'database'], ['ann', '/admin', 'admin']]) {
            const ctx = await browser.newContext({ storageState: `/work/${user}.json`, viewport: { width: 1280, height: 800 } });
            const page = await ctx.newPage();
            await page.goto(BASE + url);
            await page.screenshot({ path: `/work/shots/${name}.png` });
            await ctx.close();
        }
        check('screenshots written', fs.readdirSync('/work/shots').length === 3);
    },

    async uploads() {
        const { page, save } = await session('bob');
        const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
        const dump = '/work/files/import me.dump';
        await page.goto(BASE + '/');
        await page.click('a:has-text("Uploads and import")');
        await page.waitForURL(BASE + '/roles/e2e_bob/uploads');

        // upload.js navigates to the same URL when done, so wait for the navigation itself
        const upload = async (p, file, userSum = '') => {
            await p.fill('input[name=sha256]', userSum);
            await p.setInputFiles('input[type=file]', file);
            const done = Promise.race([p.waitForEvent('framenavigated'), p.waitForSelector('#upload-status.error')]);
            await p.click('#upload-form button');
            await done;
            await p.waitForLoadState();
        };
        const row = (name) => page.locator('tbody tr', { has: page.locator(`code:text-is("${name}")`) });

        await upload(page, dump);
        await page.waitForURL(BASE + '/roles/e2e_bob/uploads');
        let html = await page.content();
        check('custom dump listed with sanitized name', html.includes('<code>import_me.dump</code> <span class="tag">custom</span>'));
        check('browser checksum sent and matched', (await row('import_me.dump').textContent()).includes('matches browser checksum'));
        check('stored SHA-256 is the real one', (await row('import_me.dump').textContent()).includes(sha(dump)));

        await upload(page, '/work/files/big.bin', '0'.repeat(64));
        await page.waitForSelector('#upload-status.error');
        const status = await page.textContent('#upload-status');
        check('wrong user checksum rejects the upload', status.includes('The file was not saved') && status.includes(sha('/work/files/big.bin')), status);
        await page.goto(BASE + '/roles/e2e_bob/uploads');
        check('rejected file not stored', (await row('big.bin').count()) === 0);

        await upload(page, '/work/files/big.bin', `${sha('/work/files/big.bin').toUpperCase()}  big.bin`);
        await page.waitForURL(BASE + '/roles/e2e_bob/uploads');
        check('large file accepted by nginx', (await row('big.bin').textContent()).includes('3.0 MiB'));
        check('user checksum in sha256sum format matched', (await row('big.bin').textContent()).includes('matches your checksum'));

        const plain = await browser.newContext({ storageState: '/work/bob.json', javaScriptEnabled: false });
        const noJs = await plain.newPage();
        await noJs.goto(BASE + '/roles/e2e_bob/uploads');
        await noJs.setInputFiles('input[type=file]', '/work/files/evil.sql');
        await noJs.click('#upload-form button');
        await noJs.waitForURL(BASE + '/roles/e2e_bob/uploads');
        check('upload works without JavaScript', (await noJs.content()).includes('<code>evil.sql</code>'));
        await plain.close();
        await page.goto(BASE + '/roles/e2e_bob/uploads');
        html = await page.content();
        check('plain SQL flagged as not importable', html.includes('plain SQL files cannot be imported'));
        check('no-JS upload is hashed but not verified', (await row('evil.sql').textContent()).includes(sha('/work/files/evil.sql')) && (await row('evil.sql').locator('form[action$="/verify"]').count()) === 1);
        check('only importable files have an import button', (await page.locator('form[action$="/import"]').count()) === 1);

        state.bobUpload = (await row('import_me.dump').locator('form[action$="/import"]').getAttribute('action')).split('/')[2];
        await row('import_me.dump').locator('form[action$="/keep"] button').click();
        await page.waitForURL(BASE + '/roles/e2e_bob/uploads');
        check('keep toggled', (await row('import_me.dump').textContent()).includes('kept'));

        await upload(page, dump);
        await page.waitForURL(BASE + '/roles/e2e_bob/uploads');
        check('second upload with the same name is not overwritten', (await row('import_me-1.dump').count()) === 1);

        const noToken = await page.request.post(BASE + '/roles/e2e_bob/uploads', { multipart: { file: { name: 'x.dump', mimeType: 'application/octet-stream', buffer: Buffer.from('PGDMP') } } });
        check('upload without csrf rejected', noToken.status() === 403, String(noToken.status()));

        await row('import_me.dump').locator('form[action$="/import"] button').click();
        await page.waitForURL(/\/uploads\/\d+\/import/);
        check('import page shows the check', (await page.content()).includes('matches the checksum your browser calculated'));
        await page.selectOption('select[name=database]', 'e2e_bob');
        check('safety snapshot checked by default', await page.isChecked('input[name=safety_snapshot]'));
        await page.uncheck('input[name=safety_snapshot]');
        await page.fill('input[name=confirm]', 'e2e_bob');
        await page.click('button:has-text("Import")');
        await page.waitForURL(BASE + '/databases/e2e_bob');
        check('import job finished', await waitForJobs(page, BASE + '/databases/e2e_bob'));
        html = await page.content();
        const newest = await page.locator('section', { hasText: 'Recent jobs' }).locator('tbody tr').first().innerHTML();
        check('import job done without safety snapshot', newest.includes('import (without safety snapshot)') && newest.includes('done'), newest.slice(0, 300));
        check('no safety snapshot taken', !html.includes('taken before importing import_me.dump'));
        await save();
    },

    async uploads2() {
        const { page, save } = await session('bob');
        const row = (name) => page.locator('tbody tr', { has: page.locator(`code:text-is("${name}")`) });
        let text = '';
        for (let i = 0; i < 20 && !text.includes(state.manualSha); i++) {
            await page.goto(BASE + '/roles/e2e_bob/uploads');
            text = (await row('manual.dump').count()) ? await row('manual.dump').textContent() : '';
            if (!text.includes(state.manualSha)) await page.waitForTimeout(1000);
        }
        check('file manager copy picked up and hashed', text.includes('by file manager') && text.includes(state.manualSha), text.slice(0, 200));
        await row('manual.dump').locator('input[name=sha256]').fill('f'.repeat(64));
        await row('manual.dump').locator('form[action$="/verify"] button').click();
        check('wrong checksum reported', (await page.content()).includes('Checksum mismatch'));
        await page.goto(BASE + '/roles/e2e_bob/uploads');
        await row('manual.dump').locator('input[name=sha256]').fill(state.manualSha);
        await row('manual.dump').locator('form[action$="/verify"] button').click();
        await page.waitForURL(BASE + '/roles/e2e_bob/uploads');
        check('file manager copy verified', (await row('manual.dump').textContent()).includes('matches your checksum'));
        await save();
    },

    async tampered() {
        const { page, save } = await session('bob');
        await page.goto(BASE + '/roles/e2e_bob/uploads');
        const row = page.locator('tbody tr', { has: page.locator('code:text-is("import_me-1.dump")') });
        await row.locator('form[action$="/import"] button').click();
        await page.waitForURL(/\/uploads\/\d+\/import/);
        await page.fill('input[name=confirm]', 'e2e_bob');
        await page.click('button:has-text("Import")');
        await page.waitForURL(BASE + '/databases/e2e_bob');
        await waitForJobs(page, BASE + '/databases/e2e_bob');
        const html = await page.content();
        check('import of a file changed on disk refused', html.includes('the file changed since it was uploaded'), html.match(/<span class="error">[^<]*/)?.[0] ?? '');
        await save();
    },

    async bigImport() {
        const { page, save } = await session('bob');
        await page.goto(BASE + '/roles/e2e_bob/uploads');
        await page.setInputFiles('input[type=file]', '/work/files/big.dump');
        const uploaded = page.waitForEvent('framenavigated');
        await page.click('#upload-form button');
        await uploaded;
        await page.waitForLoadState();
        const row = page.locator('tbody tr', { has: page.locator('code:text-is("big.dump")') });
        await row.locator('form[action$="/import"] button').click();
        await page.waitForURL(/\/uploads\/\d+\/import/);
        await page.fill('input[name=confirm]', 'e2e_bob');
        await page.click('button:has-text("Import")');
        await page.waitForURL(BASE + '/databases/e2e_bob');

        const steps = new Set();
        const percents = new Set();
        for (let i = 0; i < 240; i++) {
            const res = await page.goto(BASE + '/databases/e2e_bob');
            if (res.status() !== 200) {
                check('database page reachable during the import', false, `HTTP ${res.status()}: ${(await page.textContent('main')).trim().slice(0, 200)}`);
                await page.waitForTimeout(250);
                continue;
            }
            const banner = page.locator('.job-progress');
            if (!(await banner.count())) {
                if (!(await page.content()).includes('Recent jobs')) check('database page shown during the import', false, (await page.textContent('body')).trim().slice(0, 200));
                break;
            }
            steps.add((await banner.locator('span').first().textContent()).replace(/ \(\d+%\)$/, '').replace(/[0-9.]+ [KMG]?i?B written/, 'N written'));
            const bar = banner.locator('progress');
            if (await bar.count()) percents.add(Number(await bar.getAttribute('value')));
            await page.waitForTimeout(250);
        }
        console.log('       seen steps:', [...steps].join(' | '));
        console.log('       seen percents:', [...percents].sort((a, b) => a - b).join(','));
        check('progress shows table data loading', [...steps].some((s) => s.includes('Processing data for table "public.big"')));
        check('progress bar moved during the import', [...percents].some((p) => p > 0 && p < 100));
        const newest = await page.locator('section', { hasText: 'Recent jobs' }).locator('tbody tr').first().innerHTML();
        check('big import done', newest.includes('<td>import</td>') && newest.includes('done'), newest);
        await save();
    },

    async bigSnapshot() {
        const { page, save } = await session('bob');
        await page.goto(BASE + '/databases/e2e_bob');
        await page.click('text=Create snapshot now');
        const steps = new Set();
        const percents = [];
        for (let i = 0; i < 240; i++) {
            await page.goto(BASE + '/databases/e2e_bob');
            const banner = page.locator('.job-progress');
            if (!(await banner.count())) break;
            steps.add((await banner.locator('span').first().textContent()).replace(/, [0-9.]+ [KMG]?i?B written/, '').replace(/ \(\d+%\)$/, ''));
            const bar = banner.locator('progress');
            if (await bar.count()) percents.push(Number(await bar.getAttribute('value')));
            await page.waitForTimeout(250);
        }
        console.log('       seen steps:', [...steps].join(' | '));
        console.log('       seen percents:', percents.join(','));
        check('snapshot shows the table being copied', [...steps].some((s) => s.includes('table public.big')));
        check('snapshot progress bar moved', percents.some((p) => p > 0 && p < 100));
        check('snapshot progress never goes backwards', percents.every((p, i) => i === 0 || p >= percents[i - 1]), percents.join(','));
        await save();
    },

    async failedImport() {
        const { page, save } = await session('bob');
        await page.goto(BASE + '/roles/e2e_bob/uploads');
        await page.setInputFiles('input[type=file]', '/work/files/ext.dump');
        const uploaded = page.waitForEvent('framenavigated');
        await page.click('#upload-form button');
        await uploaded;
        await page.waitForLoadState();
        await page.locator('tbody tr', { has: page.locator('code:text-is("ext.dump")') }).locator('form[action$="/import"] button').click();
        await page.waitForURL(/\/uploads\/\d+\/import/);
        await page.fill('input[name=confirm]', 'e2e_bob');
        await page.click('button:has-text("Import")');
        await page.waitForURL(BASE + '/databases/e2e_bob');
        await waitForJobs(page, BASE + '/databases/e2e_bob');
        const newest = await page.locator('section', { hasText: 'Recent jobs' }).locator('tbody tr').first().innerHTML();
        check('failed import reported', newest.includes('failed') && newest.includes('nothing changed') && newest.includes('file_fdw'), newest.slice(0, 400));
        await save();
    },

    async bob3() {
        const { page, save } = await session('bob');
        await page.goto(BASE + '/databases/e2e_bob');
        check('scheduled snapshot ran', (await page.content()).includes('class="tag">scheduled'));

        await page.goto(BASE + '/databases/e2e_bob_two');
        await page.fill('.danger-zone input[name=confirm]', 'e2e_bob_two');
        await page.click('.danger-zone button');
        await page.waitForLoadState();
        check('owner returns to My databases after delete', page.url() === BASE + '/', page.url());
        check('database gone', !(await page.content()).includes('e2e_bob_two'));
        await save();
    },

    async eve() {
        const { page, save } = await session('eve');
        await login(page, 'eve', []);
        check('eve sees own role only', (await page.content()).includes('e2e_eve') && !(await page.content()).includes('e2e_bob'));
        check('eve: /admin forbidden', (await page.goto(BASE + '/admin')).status() === 403);
        check('eve: bob database page hidden', (await page.goto(BASE + '/databases/e2e_bob')).status() === 404);
        check('eve: bob snapshot download hidden', (await page.goto(`${BASE}/snapshots/${state.bobSnapshot}/download?format=dump`)).status() === 404);
        await page.goto(BASE + '/');
        const token = await csrf(page);
        const post = (path, form, headers = {}) => page.request.post(BASE + path, { form, headers, maxRedirects: 0 });
        check('eve: rotate bob password hidden', (await post('/roles/e2e_bob/password', { csrf: token })).status() === 404);
        check('eve: restore bob snapshot hidden', (await post(`/snapshots/${state.bobSnapshot}/restore`, { csrf: token, confirm: 'e2e_bob' })).status() === 404);
        check('eve: bob uploads page hidden', (await page.goto(BASE + '/roles/e2e_bob/uploads')).status() === 404);
        check('eve: bob upload import page hidden', (await page.goto(`${BASE}/uploads/${state.bobUpload}/import`)).status() === 404);
        await page.goto(BASE + '/');
        check('eve: import bob upload into her database hidden', (await post(`/uploads/${state.bobUpload}/import`, { csrf: token, database: 'e2e_eve', confirm: 'e2e_eve' })).status() === 404);
        check('eve: delete bob upload hidden', (await post(`/uploads/${state.bobUpload}/delete`, { csrf: token })).status() === 404);
        const evil = await page.request.post(BASE + '/roles/e2e_bob/uploads', { multipart: { csrf: token, file: { name: 'x.dump', mimeType: 'application/octet-stream', buffer: Buffer.from('PGDMP') } } });
        check('eve: upload to bob role hidden', evil.status() === 404, String(evil.status()));
        check('eve: create role forbidden', (await post('/admin/roles', { csrf: token, name: 'evil_role' })).status() === 403);
        check('missing csrf rejected', (await post('/roles/e2e_eve/password', {})).status() === 403);
        check('foreign origin rejected', (await post('/roles/e2e_eve/password', { csrf: token }, { Origin: 'https://evil.example' })).status() === 403);
        check('cross-site fetch rejected', (await post('/roles/e2e_eve/password', { csrf: token }, { 'Sec-Fetch-Site': 'cross-site' })).status() === 403);
        await save();
    },

    async admin2() {
        const { page, save } = await session('ann');
        await page.goto(BASE + '/databases/e2e_eve');
        await page.fill('.danger-zone input[name=confirm]', 'e2e_eve');
        await page.click('.danger-zone button');
        await page.waitForLoadState();
        check('admin returns to /admin after deleting another user database', page.url() === BASE + '/admin', page.url());
        await page.goto(BASE + '/admin/roles/e2e_eve');
        check('role page lists the login', (await page.content()).includes('<code>e2e_eve.eve</code>'));
        await page.click('form[action="/admin/roles/e2e_eve/logins/e2e_eve.eve/revoke"] button');
        await page.waitForURL(BASE + '/admin/roles/e2e_eve');
        check('revoked login marked', (await page.content()).includes('being removed'));
        const del = page.locator('form[action="/admin/roles/e2e_eve/delete"]');
        await del.locator('input[name=confirm]').fill('e2e_eve');
        await del.locator('button').click();
        await page.waitForURL(BASE + '/admin');
        check('role deleted', !(await page.content()).includes('<code>e2e_eve</code>'));
        await page.goto(BASE + '/admin/audit');
        const audit = await page.content();
        for (const action of ['role.create', 'database.create', 'snapshot.restore', 'schedule.set', 'database.drop', 'role.drop', 'allowlist.update']) {
            check(`audit has ${action}`, audit.includes(action));
        }
        await page.click('button:has-text("Log out")');
        await page.waitForURL(BASE + '/');
        check('logout shows login page', (await page.content()).includes('Sign in with Cloudron'));
        check('old session invalid', (await page.goto(BASE + '/admin')).status() === 200 && (await page.content()).includes('Sign in with Cloudron'));
        await save();
    },

    async bobAdminByEnv() {
        const { page } = await session('bob');
        const res = await page.goto(BASE + '/admin');
        check('PG_ADMINS applies to an existing session', res.status() === 200 && (await page.content()).includes('Create role'), String(res.status()));
    },

    async afterRestore() {
        const { page } = await session('bob');
        await page.goto(BASE + '/databases/e2e_bob');
        check('session and snapshots survive app restore', (await page.content()).includes('class="tag">manual'));
        const row = page.locator('tbody tr', { hasText: 'manual' }).first();
        const [dl] = await Promise.all([page.waitForEvent('download'), row.getByRole('link', { name: 'Download .dump' }).click()]);
        check('download works after app restore', !(await dl.failure()) && fs.readFileSync(await dl.path()).subarray(0, 5).toString() === 'PGDMP');
    },
};

try {
    await steps[step]();
} catch (e) {
    check('step completed without exception', false, e.message.split('\n')[0]);
    if (lastPage) {
        fs.writeFileSync(`/work/fail-${step}.html`, `<!-- ${lastPage.url()} -->\n` + (await lastPage.content().catch(() => '')));
        console.log(`       page saved to fail-${step}.html (${lastPage.url()})`);
    }
}
fs.writeFileSync(STATE, JSON.stringify(state, null, 1));
await browser.close();
process.exit(failures ? 1 : 0);
