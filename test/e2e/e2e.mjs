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
    if (await page.locator('#sheet-account').count()) return;
    await page.getByRole('link', { name: 'Sign in with Cloudron' }).click();
    await page.fill('input[name=username]', user);
    await page.fill('textarea[name=claims]', JSON.stringify({ groups, name: user }));
    await page.click('input[type=submit]');
    await page.waitForURL(BASE + '/');
}

// opens a sheet with its visible trigger and returns the sheet
async function sheet(page, id) {
    await page.locator(`[popovertarget="${id}"]:visible`).first().click();
    const el = page.locator('#' + id);
    await el.waitFor({ state: 'visible' });
    // clicks during the slide-in animation never count as stable
    await el.evaluate((e) => Promise.all(e.getAnimations().map((a) => a.finished)));
    return el;
}

// counts real page loads, live updates must not cause any
function navigations(page) {
    let n = 0;
    page.on('framenavigated', (f) => { if (f === page.mainFrame()) n++; });
    return () => n;
}

const newestJob = (page) => page.locator('[data-live=jobs] .list > li').first();

// waits on the open database page until no job is active, without reloading
async function waitForJobs(page) {
    try {
        await page.waitForFunction(() => !document.getElementById('job') && document.querySelector('[data-live=jobs] .list > li .chip'), null, { timeout: 180000, polling: 250 });
        return true;
    } catch {
        return false;
    }
}

async function csrf(page) {
    return page.locator('input[name=csrf]').first().inputValue();
}

async function secretFromPage(page) {
    return (await page.locator('code.secret').textContent()).trim();
}

const fileRow = (page, name) => page.locator('main .list > li', { has: page.locator(`.row-title > span.mono:text-is("${name}")`) });

async function importFile(page, name, { database = 'e2e_bob', safety = true } = {}) {
    const id = (await fileRow(page, name).locator('[popovertarget^="sheet-import-"]').getAttribute('popovertarget'));
    const s = await sheet(page, id);
    await s.locator('select[name=database]').selectOption(database);
    if (!safety) await s.locator('input[name=safety_snapshot]').uncheck();
    await s.locator('input[name=confirm]').fill(database);
    await s.getByRole('button', { name: 'Import' }).click();
    await page.waitForURL(BASE + '/databases/' + database);
    return id.replace('sheet-import-', '');
}

async function uploadFile(page, file, userSum = '') {
    if (userSum) {
        await page.locator('details.checksum summary').click();
        await page.fill('input[name=sha256]', userSum);
    }
    await page.setInputFiles('input[type=file]', file);
    const done = Promise.race([page.waitForEvent('framenavigated'), page.waitForSelector('#upload-status.error')]);
    await page.click('#upload-form button[type=submit]');
    await done;
    await page.waitForLoadState();
}

const steps = {
    async admin() {
        const { page, save } = await session('ann');
        await login(page, 'ann', ['postgres-admins']);
        check('admin sees Admin link', await page.getByRole('link', { name: 'Admin', exact: true }).isVisible());

        const res = await page.goto(BASE + '/admin');
        check('admin page loads', res.status() === 200, String(res.status()));
        check('overview shows the data volume', (await page.locator('.tile', { hasText: 'Data volume' }).locator('progress').count()) === 1);
        check('overview tiles open their lists', (await page.locator('a.tile[href="/admin/connections"]').count()) === 1 && (await page.locator('a.tile[href="/admin/snapshots"]').count()) === 1);
        check('data volume tile is not a link', (await page.locator('a.tile', { hasText: 'Data volume' }).count()) === 0);

        await page.goto(BASE + '/admin/network');
        await page.fill('textarea[name=allowlist]', '1.2.3.4\nhost all all 0.0.0.0/0 trust');
        await page.click('form[action="/admin/allowlist"] button');
        check('injected allowlist rejected', (await page.content()).includes('Nothing saved'));

        await page.goto(BASE + '/admin/network');
        await page.fill('textarea[name=allowlist]', process.env.APP_IP);
        await page.click('form[action="/admin/allowlist"] button');
        await page.waitForURL(BASE + '/admin/network');
        check('allowlist saved', (await page.inputValue('textarea[name=allowlist]')).includes(process.env.APP_IP + '/32'));

        await page.goto(BASE + '/admin/notifications');
        await page.fill('input[name=notify_to]', 'not an address');
        await page.click('form[action="/admin/notifications"] button[value=save]');
        check('invalid notification address rejected', (await page.content()).includes('is not a list of email addresses'));
        await page.goto(BASE + '/admin/notifications');
        check('no owner opted in yet', (await page.content()).includes('0 users have turned them on'));
        await page.fill('input[name=notify_to]', 'DBA <dba@example.test>');
        await page.click('form[action="/admin/notifications"] button[value=test]');
        check('test mail reported as sent', (await page.content()).includes('Test mail sent.'));
        await page.fill('input[name=notify_to]', 'dba@example.test');
        await page.click('form[action="/admin/notifications"] button[value=save]');
        await page.waitForURL(BASE + '/admin/notifications');
        check('notification address saved', (await page.inputValue('input[name=notify_to]')) === 'dba@example.test');

        await page.goto(BASE + '/admin/roles');
        const form = await sheet(page, 'sheet-newrole');
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
        await form.getByRole('button', { name: 'Create role' }).click();
        await page.waitForURL(BASE + '/admin/roles#sheet-role-e2e_bob');
        const roleSheet = page.locator('#sheet-role-e2e_bob');
        check('new role opens its sheet', await roleSheet.isVisible());
        check('role sheet shows the owners', (await roleSheet.locator('textarea[name=owners]').inputValue()) === 'user:bob, group:dbteam');
        check('no password for the shared role', !(await page.content()).includes('code class="secret"'));
        await page.goto(BASE + '/admin/roles/e2e_bob');
        check('old role address redirects to the sheet', page.url() === BASE + '/admin/roles#sheet-role-e2e_bob' && (await page.locator('#sheet-role-e2e_bob').isVisible()), page.url());

        // without JavaScript the sheets still open and the owners field is typed
        const plain = await browser.newContext({ storageState: undefined, javaScriptEnabled: false });
        await plain.addCookies((await page.context().cookies()));
        const noJs = await plain.newPage();
        await noJs.goto(BASE + '/admin/roles');
        let plainForm = await sheet(noJs, 'sheet-newrole');
        await plainForm.locator('input[name=name]').fill('e2e_eve');
        await plainForm.locator('textarea[name=owners]').fill('user:nobody');
        await plainForm.getByRole('button', { name: 'Create role' }).click();
        check('unknown owner rejected', (await noJs.content()).includes('There is no Cloudron user'));
        await noJs.goto(BASE + '/admin/roles');
        plainForm = await sheet(noJs, 'sheet-newrole');
        await plainForm.locator('input[name=name]').fill('e2e_eve');
        await plainForm.locator('textarea[name=owners]').fill('user:eve');
        await plainForm.getByRole('button', { name: 'Create role' }).click();
        await noJs.waitForURL(BASE + '/admin/roles#sheet-role-e2e_eve');
        check('owners typed without JavaScript', (await noJs.content()).includes('user:eve'));
        await plain.close();
        await save();
    },

    async adminServer() {
        const { page, save } = await session('ann');
        await page.goto(BASE + '/admin/server');
        check('server tab lists the parameters', (await page.locator('.param').count()) === 8);
        check('running value shown', (await page.locator('.param', { hasText: 'max_connections' }).textContent()).includes('running 100'));
        check('managed parameters explained', (await page.content()).includes('log_min_duration_statement'));
        await page.fill('input[name=work_mem]', '1TB');
        await page.click('form[action="/admin/server"] button[type=submit]');
        check('out of range value rejected', (await page.content()).includes('work_mem must be between'));
        const evil = await page.request.post(BASE + '/admin/server', { form: { csrf: await csrf(page), work_mem: "8MB'\narchive_command = 'touch /tmp/pwned" }, maxRedirects: 0 });
        check('config injection rejected', evil.status() === 400 && (await evil.text()).includes('Nothing saved'), String(evil.status()));
        await page.goto(BASE + '/admin/server');
        await page.fill('input[name=work_mem]', '8 mb');
        await page.fill('input[name=max_connections]', '150');
        await page.fill('input[name=idle_in_transaction_session_timeout]', '10min');
        await page.click('form[action="/admin/server"] button[type=submit]');
        await page.waitForURL(BASE + '/admin/server');
        check('values saved in the canonical form', (await page.inputValue('input[name=work_mem]')) === '8MB');
        check('apply notice shown', (await page.content()).includes('applies the saved values'));
        await save();
    },

    async adminServer2() {
        const { page } = await session('ann');
        await page.goto(BASE + '/admin/server');
        const html = await page.content();
        check('no apply error', !html.includes('was not applied'), html.match(/was not applied[^<]*/)?.[0] ?? '');
        check('reloadable value running', (await page.locator('.param', { has: page.locator('input[name=work_mem]') }).textContent()).includes('running 8MB'));
        check('restart pending shown', html.includes('Restart pending') && (await page.locator('.param', { hasText: 'max_connections' }).textContent()).includes('restart pending'));
    },

    async bobLogin() {
        const { ctx, page, save } = await session('bob');
        await login(page, 'bob', []);
        check('bob has no login yet', (await page.locator('#role-e2e_bob .chip', { hasText: 'No login yet' }).count()) === 1);
        check('no connection URL without a login', (await page.content()).includes('Create your login in the role settings'));
        const s = await sheet(page, 'sheet-role-e2e_bob');
        await s.getByRole('button', { name: 'Create my password' }).click();
        state.bobPassword = await secretFromPage(page);
        check('bob login password shown once', state.bobPassword.length === 32);
        check('connection URL uses the own login', (await page.content()).includes('postgresql://e2e_bob.bob@pg.test:5432/e2e_bob'));
        await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: BASE });
        await page.getByRole('button', { name: 'Copy password' }).click();
        check('password copied', (await page.evaluate(() => navigator.clipboard.readText())) === state.bobPassword);
        await page.goto(BASE + '/');
        const copyURL = page.getByRole('button', { name: 'Copy connection URL' }).first();
        await copyURL.click();
        check('connection URL copied', (await page.evaluate(() => navigator.clipboard.readText())) === 'postgresql://e2e_bob.bob@pg.test:5432/e2e_bob?sslmode=verify-full&sslrootcert=system');
        check('copy button confirms', await copyURL.evaluate((b) => b.classList.contains('done')));
        const [codeBox, buttonBox] = [await page.locator('.dbrow .url code').first().boundingBox(), await copyURL.boundingBox()];
        check('copy button right of the URL', buttonBox.x > codeBox.x + codeBox.width - 1 && Math.abs((buttonBox.y + buttonBox.height / 2) - (codeBox.y + codeBox.height / 2)) < codeBox.height);
        await save();
    },

    async eveLogin() {
        const { page, save } = await session('eve');
        await login(page, 'eve', []);
        const s = await sheet(page, 'sheet-role-e2e_eve');
        await s.getByRole('button', { name: 'Create my password' }).click();
        state.evePassword = await secretFromPage(page);
        check('eve login created', state.evePassword.length === 32 && (await page.content()).includes('e2e_eve.eve'));
        await save();
    },

    async carol() {
        const { page, save } = await session('carol');
        await login(page, 'carol', []);
        check('carol sees the role through her group', (await page.locator('#role-e2e_bob').count()) === 1 && (await page.content()).includes('dbteam'));
        check('carol cannot open the admin page', (await page.goto(BASE + '/admin')).status() === 403);
        await page.goto(BASE + '/');
        const s = await sheet(page, 'sheet-role-e2e_bob');
        await s.getByRole('button', { name: 'Create my password' }).click();
        state.carolPassword = await secretFromPage(page);
        check('carol gets her own login', (await page.content()).includes('e2e_bob.carol'));
        check('carol manages the database', (await page.goto(BASE + '/databases/e2e_bob')).status() === 200);
        await save();
    },

    async carolGone() {
        const { page } = await session('carol');
        await page.goto(BASE + '/');
        check('carol no longer sees the role', (await page.locator('#role-e2e_bob').count()) === 0);
        check('carol no longer opens the database', (await page.goto(BASE + '/databases/e2e_bob')).status() === 404);
    },

    async bob1() {
        const { page, save } = await session('bob');
        await login(page, 'bob', []);
        const card = page.locator('#role-e2e_bob');
        check('bob sees own role', (await card.count()) === 1);
        check('bob does not see eve role', !(await page.content()).includes('e2e_eve'));
        check('bob has no Admin link', !(await page.getByRole('link', { name: 'Admin', exact: true }).count()));
        check('usage counter', (await card.locator('.chip', { hasText: '1 of 2' }).count()) === 1);

        const acc = await sheet(page, 'sheet-account');
        await acc.locator('input[name=notify_failures]').check();
        await page.locator('#toast', { hasText: 'Saved' }).waitFor();
        await acc.locator('input[name=show_labels]').check();
        await page.locator('#toast', { hasText: 'Saved' }).waitFor();
        check('labels shown right away', await page.evaluate(() => document.documentElement.classList.contains('labels')));
        await page.reload();
        check('labels setting kept', await page.evaluate(() => document.documentElement.classList.contains('labels')));
        check('labels visible on icon buttons', await page.locator('#role-e2e_bob [popovertarget="sheet-role-e2e_bob"] .lbl').isVisible());
        await (await sheet(page, 'sheet-account')).locator('input[name=show_labels]').uncheck();
        await page.locator('#toast', { hasText: 'Saved' }).waitFor();
        await page.reload();
        check('labels hidden again', !(await page.locator('#role-e2e_bob [popovertarget="sheet-role-e2e_bob"] .lbl').isVisible()));
        check('notification opt-in kept', await page.locator('#sheet-account input[name=notify_failures]').isChecked());

        const newdb = await sheet(page, 'sheet-newdb-e2e_bob');
        check('new database sheet has no role picker', (await newdb.locator('select').count()) === 0);
        await newdb.locator('input[name=name]').fill('e2e_bob_two');
        await newdb.getByRole('button', { name: 'Create database' }).click();
        await page.waitForURL(BASE + '/');
        check('self-service database created', (await page.content()).includes('e2e_bob_two') && (await card.locator('.chip', { hasText: '2 of 2' }).count()) === 1);
        check('new database button disabled at limit', await card.locator('button[aria-label^="Limit of 2 databases"]').isDisabled());
        const over = await page.request.post(BASE + '/roles/e2e_bob/databases', { form: { csrf: await csrf(page), name: 'e2e_bob_three' } });
        check('limit enforced server side', over.status() === 400 && (await over.text()).includes('Limit reached'), String(over.status()));

        await page.locator('.dbrow', { hasText: 'e2e_bob_two' }).click({ position: { x: 5, y: 5 } });
        await page.waitForURL(BASE + '/databases/e2e_bob_two');
        check('whole database row opens the database', true);

        await page.goto(BASE + '/databases/e2e_bob');
        let s = await sheet(page, 'sheet-db');
        await s.locator('input[name=cron]').fill('*/5 * * * *');
        check('typing a schedule selects Custom', await s.locator('input[name=preset][value=custom]').isChecked());
        await s.getByRole('button', { name: 'Save schedule' }).click();
        check('too frequent schedule rejected', (await page.content()).includes('at most once per hour'));
        await page.goto(BASE + '/databases/e2e_bob');
        s = await sheet(page, 'sheet-db');
        await s.locator('label', { hasText: 'Every hour' }).click();
        check('preset fills the cron field', (await s.locator('input[name=cron]').inputValue()) === '0 * * * *');
        await s.getByRole('button', { name: 'Save schedule' }).click();
        await page.waitForURL(BASE + '/databases/e2e_bob');
        check('schedule saved', await page.locator('#sheet-db input[name=preset][value="0 * * * *"]').isChecked());
        check('next snapshot tile shows the schedule', !(await page.locator('.tile', { hasText: 'Next snapshot' }).textContent()).includes('Off'));

        const loads = navigations(page);
        await page.locator('form[action="/databases/e2e_bob/snapshots"] button').click();
        await page.waitForURL(BASE + '/databases/e2e_bob');
        const afterPost = loads();
        await page.locator('#job').waitFor({ timeout: 10000 }).catch(() => {});
        check('job card shown', (await page.locator('#job .live').count()) === 1 || (await page.locator('[data-live=snapshots] li[id^=snap-]').count()) > 0);
        check('snapshot job finished', await waitForJobs(page));
        check('snapshot appeared without reloading the page', loads() === afterPost && (await page.locator('[data-live=snapshots] li[id^=snap-]').count()) === 1, `loads ${afterPost} -> ${loads()}`);
        check('snapshot button enabled again', await page.locator('form[action="/databases/e2e_bob/snapshots"] button').isEnabled());
        check('snapshot job done', (await newestJob(page).textContent()).includes('done'), await newestJob(page).textContent());
        await page.reload();
        check('size tile shows MiB', /[\d.]+ MiB/.test(await page.locator('.tile', { hasText: 'Size' }).textContent()));
        check('snapshot tile counts the snapshot', /Snapshots\s*1\s*[\d.]+ KiB in total/.test((await page.locator('.tile', { hasText: 'Snapshots' }).textContent()).replace(/\s+/g, ' ')));

        const row = page.locator('[data-live=snapshots] li[id^=snap-]').first();
        state.bobSnapshot = (await row.getAttribute('id')).replace('snap-', '');
        check('snapshot listed as manual', (await row.locator('.chip', { hasText: 'manual' }).count()) === 1);
        for (const [label, test] of [['.dump', (b) => b.subarray(0, 5).toString() === 'PGDMP'],
            ['.sql', (b) => b.toString().includes('CREATE TABLE "public"."t"') && b.toString().includes('COPY "public"."t"')]]) {
            const dlSheet = await sheet(page, `sheet-dl-${state.bobSnapshot}`);
            const [dl] = await Promise.all([page.waitForEvent('download'), dlSheet.getByRole('link', { name: label }).click()]);
            const failure = await dl.failure();
            const body = failure ? Buffer.alloc(0) : fs.readFileSync(await dl.path());
            check(`download ${label} content`, !failure && test(body), failure ?? body.subarray(0, 80).toString());
            await page.keyboard.press('Escape');
        }

        await page.goto(BASE + '/');
        s = await sheet(page, 'sheet-role-e2e_bob');
        await s.getByRole('button', { name: 'New password' }).click();
        state.bobOldPassword = state.bobPassword;
        state.bobPassword = await secretFromPage(page);
        check('password rotated', state.bobPassword.length === 32 && state.bobPassword !== state.bobOldPassword);
        await save();
    },

    async bob2() {
        const { page, save } = await session('bob');
        await page.goto(BASE + '/databases/e2e_bob');
        const id = (await page.locator('[data-live=snapshots] li[id^=snap-]', { has: page.locator('.chip', { hasText: 'manual' }) }).first().getAttribute('id')).replace('snap-', '');
        const wrong = await page.request.post(`${BASE}/snapshots/${id}/restore`, { form: { csrf: await csrf(page), confirm: 'wrong' }, maxRedirects: 0 });
        check('wrong confirmation rejected', wrong.status() === 400 && (await wrong.text()).includes('Type the database name'), String(wrong.status()));
        const s = await sheet(page, `sheet-restore-${id}`);
        const button = s.getByRole('button', { name: 'Restore snapshot' });
        check('restore button disabled until the name is typed', await button.isDisabled());
        await s.locator('input[name=confirm]').fill('e2e_bob');
        await button.click();
        await page.waitForURL(BASE + '/databases/e2e_bob');
        check('restore job finished', await waitForJobs(page));
        const newest = await newestJob(page).textContent();
        check('restore job done', newest.includes('Restore of #') && newest.includes('done'), newest);
        check('safety snapshot taken', (await page.locator('[data-live=snapshots] .chip', { hasText: 'before restore' }).count()) === 1);
        await save();
    },

    async adminConnections() {
        const { page } = await session('ann');
        await page.goto(BASE + '/admin');
        await page.locator('a.tile[href="/admin/connections"]').click();
        await page.waitForURL(BASE + '/admin/connections');
        check('overview tab stays selected', (await page.locator('.tabs [aria-current=page]').textContent()).includes('Overview'));
        const row = page.locator('main .list > li', { hasText: 'e2e_bob.bob' }).first();
        const text = (await row.count()) ? await row.textContent() : '';
        check('connection of bob listed', text.includes('active') && text.includes(process.env.APP_IP) && text.includes('TLSv1.3'), text.replace(/\s+/g, ' ').slice(0, 200));
        check('query text not shown', !(await page.content()).includes('pg_sleep'));
        check('connections are read only', (await page.locator('main form').count()) === 0);
        await page.locator('.pills a', { hasText: 'e2e_bob' }).click();
        check('connections filtered by database', page.url().endsWith('/admin/connections?f=e2e_bob'));
        await page.goto(BASE + '/admin/snapshots');
        check('all snapshots listed', (await page.locator('main .list > li[id^=snap-]').count()) >= 2);
        await page.locator('.pills a', { hasText: 'Before restore' }).click();
        const kinds = await page.locator('main .list > li[id^=snap-] .chip').allTextContents();
        check('snapshots filtered by type', kinds.length > 0 && kinds.every((k) => k.includes('before restore')), kinds.join(','));
        await page.setViewportSize({ width: 390, height: 844 });
        await page.goto(BASE + '/admin/server');
        await page.evaluate(() => document.fonts.ready);
        await page.waitForTimeout(100);
        const scroll = await page.locator('.tabs').evaluate((t) => [t.scrollLeft, Math.min(t.querySelector('[aria-current=page]').offsetLeft, t.scrollWidth - t.clientWidth)]);
        check('current admin tab scrolled to the left on phones', scroll[0] > 0 && Math.abs(scroll[0] - scroll[1]) < 2, scroll.join(','));
        check('bottom navigation on phones', await page.locator('.tabbar').isVisible());
        check('no horizontal page scroll on phones', await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    },

    // screenshots for the manifest's mediaLinks, only run with SCREENSHOTS=1 or ARTIFACTS
    async screenshots() {
        fs.mkdirSync('/work/shots', { recursive: true });
        for (const [user, url, name, width, height] of [['bob', '/', 'databases', 1280, 800], ['bob', '/databases/e2e_bob', 'database', 1280, 800], ['ann', '/admin', 'admin', 1280, 800], ['bob', '/databases/e2e_bob', 'database-phone', 390, 844]]) {
            const ctx = await browser.newContext({ storageState: `/work/${user}.json`, viewport: { width, height } });
            const page = await ctx.newPage();
            await page.goto(BASE + url);
            await page.screenshot({ path: `/work/shots/${name}.png`, fullPage: true });
            await ctx.close();
        }
        check('screenshots written', fs.readdirSync('/work/shots').length === 4);
    },

    async uploads() {
        const { page, save } = await session('bob');
        const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
        const dump = '/work/files/import me.dump';
        await page.goto(BASE + '/');
        await page.getByRole('link', { name: 'Uploads' }).click();
        await page.waitForURL(BASE + '/roles/e2e_bob/uploads');
        check('role picker shows the current role', (await page.locator('.pills a[aria-current=page]').textContent()) === 'e2e_bob');

        await uploadFile(page, dump);
        await page.waitForURL(BASE + '/roles/e2e_bob/uploads');
        let html = await page.content();
        check('custom dump listed with sanitized name', (await fileRow(page, 'import_me.dump').locator('.chip', { hasText: 'custom' }).count()) === 1);
        check('browser checksum sent and matched', (await fileRow(page, 'import_me.dump').textContent()).includes('checked'));
        check('stored SHA-256 is the real one', html.includes(sha(dump)));

        await uploadFile(page, '/work/files/big.bin', '0'.repeat(64));
        await page.waitForSelector('#upload-status.error');
        const status = await page.textContent('#upload-status');
        check('wrong user checksum rejects the upload', status.includes('The file was not saved') && status.includes(sha('/work/files/big.bin')), status);
        await page.goto(BASE + '/roles/e2e_bob/uploads');
        check('rejected file not stored', (await fileRow(page, 'big.bin').count()) === 0);

        await uploadFile(page, '/work/files/big.bin', `${sha('/work/files/big.bin').toUpperCase()}  big.bin`);
        await page.waitForURL(BASE + '/roles/e2e_bob/uploads');
        check('large file accepted by nginx', (await fileRow(page, 'big.bin').textContent()).includes('3.0 MiB'));
        check('user checksum in sha256sum format matched', (await fileRow(page, 'big.bin').textContent()).includes('matches your checksum'));

        const plain = await browser.newContext({ storageState: '/work/bob.json', javaScriptEnabled: false });
        const noJs = await plain.newPage();
        await noJs.goto(BASE + '/roles/e2e_bob/uploads');
        await noJs.setInputFiles('input[type=file]', '/work/files/evil.sql');
        await noJs.click('#upload-form button[type=submit]');
        await noJs.waitForURL(BASE + '/roles/e2e_bob/uploads');
        check('upload works without JavaScript', (await fileRow(noJs, 'evil.sql').count()) === 1);
        await plain.close();
        await page.goto(BASE + '/roles/e2e_bob/uploads');
        check('plain SQL flagged as not importable', (await fileRow(page, 'evil.sql').textContent()).includes('plain SQL files cannot be imported'));
        const evilSheet = await sheet(page, await fileRow(page, 'evil.sql').locator('[popovertarget^="sheet-import-"]').getAttribute('popovertarget'));
        check('no-JS upload is hashed but not verified', (await evilSheet.textContent()).includes(sha('/work/files/evil.sql')) && (await evilSheet.locator('form[action$="/verify"]').count()) === 1);
        check('plain SQL has no import form', (await evilSheet.locator('form[action$="/import"]').count()) === 0);
        await page.keyboard.press('Escape');

        state.bobUpload = (await fileRow(page, 'import_me.dump').locator('[popovertarget^="sheet-import-"]').getAttribute('popovertarget')).replace('sheet-import-', '');
        await fileRow(page, 'import_me.dump').locator('form[action$="/keep"] button').click();
        await page.waitForURL(BASE + '/roles/e2e_bob/uploads');
        check('keep toggled', (await fileRow(page, 'import_me.dump').textContent()).includes('kept'));

        await uploadFile(page, dump);
        await page.waitForURL(BASE + '/roles/e2e_bob/uploads');
        check('second upload with the same name is not overwritten', (await fileRow(page, 'import_me-1.dump').count()) === 1);

        const noToken = await page.request.post(BASE + '/roles/e2e_bob/uploads', { multipart: { file: { name: 'x.dump', mimeType: 'application/octet-stream', buffer: Buffer.from('PGDMP') } } });
        check('upload without csrf rejected', noToken.status() === 403, String(noToken.status()));

        const importSheet = await sheet(page, `sheet-import-${state.bobUpload}`);
        check('import sheet shows the check', (await importSheet.textContent()).includes('Matches the checksum your browser calculated'));
        check('safety snapshot checked by default', await importSheet.locator('input[name=safety_snapshot]').isChecked());
        await page.keyboard.press('Escape');
        await importFile(page, 'import_me.dump', { safety: false });
        check('import job finished', await waitForJobs(page));
        const newest = await newestJob(page).textContent();
        check('import job done without safety snapshot', newest.includes('Import (without safety snapshot)') && newest.includes('done'), newest.replace(/\s+/g, ' ').slice(0, 300));
        check('no safety snapshot taken', !(await page.content()).includes('taken before importing import_me.dump'));
        await save();
    },

    async uploads2() {
        const { page, save } = await session('bob');
        let text = '';
        for (let i = 0; i < 20 && !text.includes(state.manualSha); i++) {
            await page.goto(BASE + '/roles/e2e_bob/uploads');
            text = (await fileRow(page, 'manual.dump').count()) ? await page.content() : '';
            if (!text.includes(state.manualSha)) await page.waitForTimeout(1000);
        }
        check('file manager copy picked up and hashed', (await fileRow(page, 'manual.dump').textContent()).includes('by file manager') && text.includes(state.manualSha));
        const id = (await fileRow(page, 'manual.dump').locator('[popovertarget^="sheet-import-"]').getAttribute('popovertarget'));
        let s = await sheet(page, id);
        await s.locator('input[name=sha256]').fill('f'.repeat(64));
        await s.getByRole('button', { name: 'Compare' }).click();
        check('wrong checksum reported', (await page.content()).includes('Checksum mismatch'));
        await page.goto(BASE + '/roles/e2e_bob/uploads');
        s = await sheet(page, id);
        await s.locator('input[name=sha256]').fill(state.manualSha);
        await s.getByRole('button', { name: 'Compare' }).click();
        await page.waitForURL(BASE + '/roles/e2e_bob/uploads');
        check('file manager copy verified', (await fileRow(page, 'manual.dump').textContent()).includes('matches your checksum'));
        await save();
    },

    async tampered() {
        const { page, save } = await session('bob');
        await page.goto(BASE + '/roles/e2e_bob/uploads');
        await importFile(page, 'import_me-1.dump');
        await waitForJobs(page);
        const newest = await newestJob(page).textContent();
        check('import of a file changed on disk refused', newest.includes('the file changed since it was uploaded'), newest.replace(/\s+/g, ' ').slice(0, 300));
        await save();
    },

    // watches the live progress on the open page, it must update without reloads
    async bigImport() {
        const { page, save } = await session('bob');
        await page.goto(BASE + '/roles/e2e_bob/uploads');
        await uploadFile(page, '/work/files/big.dump');
        await importFile(page, 'big.dump');
        const loads = navigations(page);
        const { steps, percents } = await watchJob(page);
        console.log('       seen steps:', [...steps].join(' | '));
        console.log('       seen percents:', [...percents].sort((a, b) => a - b).join(','));
        check('progress shows table data loading', [...steps].some((s) => s.includes('Processing data for table "public.big"')));
        check('progress bar moved during the import', [...percents].some((p) => p > 0 && p < 100));
        check('no page reload during the import', loads() === 0, String(loads()));
        const newest = await newestJob(page).textContent();
        check('big import done', newest.includes('Import') && newest.includes('done'), newest);
        await save();
    },

    async bigSnapshot() {
        const { page, save } = await session('bob');
        await page.goto(BASE + '/databases/e2e_bob');
        await page.locator('form[action="/databases/e2e_bob/snapshots"] button').click();
        await page.waitForURL(BASE + '/databases/e2e_bob');
        const loads = navigations(page);
        const { steps, percents } = await watchJob(page);
        console.log('       seen steps:', [...steps].join(' | '));
        console.log('       seen percents:', percents.join(','));
        check('snapshot shows the table being copied', [...steps].some((s) => s.includes('table public.big')));
        check('snapshot progress bar moved', percents.some((p) => p > 0 && p < 100));
        check('snapshot progress never goes backwards', percents.every((p, i) => i === 0 || p >= percents[i - 1]), percents.join(','));
        check('no page reload during the snapshot', loads() === 0, String(loads()));
        await save();
    },

    async failedImport() {
        const { page, save } = await session('bob');
        await page.goto(BASE + '/roles/e2e_bob/uploads');
        await uploadFile(page, '/work/files/ext.dump');
        await importFile(page, 'ext.dump');
        await waitForJobs(page);
        const newest = await newestJob(page).textContent();
        check('failed import reported', newest.includes('failed') && newest.includes('nothing changed') && newest.includes('file_fdw'), newest.replace(/\s+/g, ' ').slice(0, 400));
        await save();
    },

    async bob3() {
        const { page, save } = await session('bob');
        await page.goto(BASE + '/databases/e2e_bob');
        check('scheduled snapshot ran', (await page.locator('[data-live=snapshots] .chip', { hasText: 'scheduled' }).count()) > 0);

        await page.goto(BASE + '/databases/e2e_bob_two');
        const s = await sheet(page, 'sheet-db');
        await s.locator('input[name=confirm]').fill('e2e_bob_two');
        await s.getByRole('button', { name: 'Delete database' }).click();
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
        check('eve: /admin/server forbidden', (await page.goto(BASE + '/admin/server')).status() === 403);
        check('eve: bob database page hidden', (await page.goto(BASE + '/databases/e2e_bob')).status() === 404);
        check('eve: bob live events hidden', (await page.request.get(BASE + '/databases/e2e_bob/events')).status() === 404);
        check('eve: bob snapshot download hidden', (await page.goto(`${BASE}/snapshots/${state.bobSnapshot}/download?format=dump`)).status() === 404);
        await page.goto(BASE + '/');
        const token = await csrf(page);
        const post = (path, form, headers = {}) => page.request.post(BASE + path, { form, headers, maxRedirects: 0 });
        check('eve: rotate bob password hidden', (await post('/roles/e2e_bob/password', { csrf: token })).status() === 404);
        check('eve: restore bob snapshot hidden', (await post(`/snapshots/${state.bobSnapshot}/restore`, { csrf: token, confirm: 'e2e_bob' })).status() === 404);
        check('eve: bob uploads page hidden', (await page.goto(BASE + '/roles/e2e_bob/uploads')).status() === 404);
        await page.goto(BASE + '/');
        check('eve: import bob upload into her database hidden', (await post(`/uploads/${state.bobUpload}/import`, { csrf: token, database: 'e2e_eve', confirm: 'e2e_eve' })).status() === 404);
        check('eve: delete bob upload hidden', (await post(`/uploads/${state.bobUpload}/delete`, { csrf: token })).status() === 404);
        const evil = await page.request.post(BASE + '/roles/e2e_bob/uploads', { multipart: { csrf: token, file: { name: 'x.dump', mimeType: 'application/octet-stream', buffer: Buffer.from('PGDMP') } } });
        check('eve: upload to bob role hidden', evil.status() === 404, String(evil.status()));
        check('eve: create role forbidden', (await post('/admin/roles', { csrf: token, name: 'evil_role' })).status() === 403);
        check('eve: server parameters forbidden', (await post('/admin/server', { csrf: token, work_mem: '64MB' })).status() === 403);
        check('account redirect stays on this site', (await post('/account', { csrf: token, next: '//evil.example/' })).headers()['location'] === '/');
        check('missing csrf rejected', (await post('/roles/e2e_eve/password', {})).status() === 403);
        check('foreign origin rejected', (await post('/roles/e2e_eve/password', { csrf: token }, { Origin: 'https://evil.example' })).status() === 403);
        check('cross-site fetch rejected', (await post('/roles/e2e_eve/password', { csrf: token }, { 'Sec-Fetch-Site': 'cross-site' })).status() === 403);
        await save();
    },

    async admin2() {
        const { page, save } = await session('ann');
        await page.goto(BASE + '/databases/e2e_eve');
        check('admin goes back to the databases tab', (await page.locator('a.back').getAttribute('href')) === '/admin/databases');
        const s = await sheet(page, 'sheet-db');
        await s.locator('input[name=confirm]').fill('e2e_eve');
        await s.getByRole('button', { name: 'Delete database' }).click();
        await page.waitForLoadState();
        check('admin returns to the databases tab after deleting another user database', page.url() === BASE + '/admin/databases', page.url());
        await page.goto(BASE + '/admin/roles');
        let role = await sheet(page, 'sheet-role-e2e_eve');
        check('role sheet lists the login', (await role.textContent()).includes('e2e_eve.eve'));
        await role.locator('form[action="/admin/roles/e2e_eve/logins/e2e_eve.eve/revoke"] button').click();
        await page.waitForURL(BASE + '/admin/roles#sheet-role-e2e_eve');
        role = page.locator('#sheet-role-e2e_eve');
        check('revoked login marked', (await role.textContent()).includes('being removed'));
        await role.locator('form[action="/admin/roles/e2e_eve/delete"] input[name=confirm]').fill('e2e_eve');
        await role.getByRole('button', { name: 'Delete role' }).click();
        await page.waitForURL(BASE + '/admin/roles');
        check('role deleted', (await page.locator('#sheet-role-e2e_eve').count()) === 0);
        await page.goto(BASE + '/admin/audit');
        const audit = await page.content();
        for (const action of ['role.create', 'database.create', 'snapshot.restore', 'schedule.set', 'database.drop', 'role.drop', 'allowlist.update', 'server.params', 'account.prefs']) {
            check(`audit has ${action}`, audit.includes(action));
        }
        await (await sheet(page, 'sheet-account')).getByRole('button', { name: 'Log out' }).click();
        await page.waitForURL(BASE + '/');
        check('logout shows login page', (await page.content()).includes('Sign in with Cloudron'));
        check('old session invalid', (await page.goto(BASE + '/admin')).status() === 200 && (await page.content()).includes('Sign in with Cloudron'));
        await save();
    },

    async bobAdminByEnv() {
        const { page } = await session('bob');
        const res = await page.goto(BASE + '/admin/roles');
        check('PG_ADMINS applies to an existing session', res.status() === 200 && (await page.content()).includes('New role'), String(res.status()));
    },

    async afterRestore() {
        const { page } = await session('bob');
        await page.goto(BASE + '/databases/e2e_bob');
        const row = page.locator('[data-live=snapshots] li[id^=snap-]', { has: page.locator('.chip', { hasText: 'manual' }) }).first();
        check('session and snapshots survive app restore', (await row.count()) === 1);
        const s = await sheet(page, (await row.getAttribute('id')).replace('snap-', 'sheet-dl-'));
        const [dl] = await Promise.all([page.waitForEvent('download'), s.getByRole('link', { name: '.dump' }).click()]);
        check('download works after app restore', !(await dl.failure()) && fs.readFileSync(await dl.path()).subarray(0, 5).toString() === 'PGDMP');
    },

    async eveAppPassword() {
        const { page, save } = await session('eve');
        await login(page, 'eve', []);
        const s = await sheet(page, 'sheet-role-e2e_eve');
        await s.getByRole('button', { name: 'Use a Cloudron app password' }).click();
        await page.waitForURL(BASE + '/');
        check('eve switched to an app password', (await page.locator('#role-e2e_eve .chip', { hasText: 'Cloudron app password' }).count()) === 1);
        check('profile link shown', (await page.content()).includes('/#/profile'));
        check('switch button hidden once used', !(await page.locator('form[action="/roles/e2e_eve/apppw"]').count()));
        await save();
    },

    async eveGeneratedAgain() {
        const { page, save } = await session('eve');
        await login(page, 'eve', []);
        const s = await sheet(page, 'sheet-role-e2e_eve');
        await s.getByRole('button', { name: 'Switch to a generated password' }).click();
        state.evePassword = await secretFromPage(page);
        check('eve gets a generated password again', state.evePassword.length === 32);
        await page.goto(BASE + '/');
        check('app password option offered again', (await page.locator('form[action="/roles/e2e_eve/apppw"]').count()) === 1);
        await save();
    },
};

// follows the job card of the open database page until the job ends
async function watchJob(page) {
    const steps = new Set();
    const percents = [];
    await page.locator('#job').waitFor({ timeout: 10000 }).catch(() => {});
    for (let i = 0; i < 1200; i++) {
        const card = page.locator('#job');
        if (!(await card.count())) break;
        const step = await page.locator('#job-step').textContent().catch(() => '');
        steps.add(step.replace(/[,:] [0-9.]+ [KMG]?i?B written/, '').replace(/ \(\d+%\)$/, ''));
        const value = await page.locator('#job-bar').getAttribute('value').catch(() => null);
        if (value !== null) percents.push(Number(value));
        await page.waitForTimeout(250);
    }
    return { steps, percents };
}

try {
    await steps[step]();
} catch (e) {
    check('step completed without exception', false, e.message.split('\n')[0]);
    if (lastPage) {
        fs.writeFileSync(`/work/fail-${step}.html`, `<!-- ${lastPage.url()} -->\n` + (await lastPage.content().catch(() => '')));
        console.log(`       page saved to fail-${step}.html (${lastPage.url()})`);
    }
}
if (lastPage) {
    fs.mkdirSync('/work/steps', { recursive: true });
    await lastPage.screenshot({ path: `/work/steps/${step}.png`, fullPage: true }).catch(() => {});
}
fs.writeFileSync(STATE, JSON.stringify(state, null, 1));
await browser.close();
process.exit(failures ? 1 : 0);
