// Minimal Cloudron SCIM addon for the end-to-end test. Reads /work/scim.json on
// every request, so the test can change users and groups while the app runs.
import http from 'node:http';
import fs from 'node:fs';

const TOKEN = process.env.SCIM_TOKEN;

function filterBy(list, filter, fields) {
    if (!filter) return list;
    const m = filter.match(/^(\w+)\s+(eq|co|sw)\s+"([^"]*)"$/i);
    if (!m) return list;
    const field = fields[m[1].toLowerCase()];
    const value = m[3].toLowerCase();
    return list.filter((item) => {
        const v = String(item[field] ?? '').toLowerCase();
        return m[2] === 'eq' ? v === value : m[2] === 'co' ? v.includes(value) : v.startsWith(value);
    });
}

http.createServer((req, res) => {
    const url = new URL(req.url, 'http://scim');
    if (req.headers.authorization !== `Bearer ${TOKEN}`) {
        res.writeHead(401).end();
        return;
    }
    const data = JSON.parse(fs.readFileSync('/work/scim.json', 'utf8'));
    let list;
    if (url.pathname === '/v2/Users') {
        list = filterBy(data.users, url.searchParams.get('filter'), { username: 'userName', displayname: 'displayName' }).map((u) => ({
            schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
            id: 'uid-' + u.userName,
            userName: u.userName,
            displayName: u.displayName,
            active: true,
            emails: [{ value: u.userName + '@example.test', primary: true }],
            groups: u.groups.map((id) => ({ value: id, display: data.groups.find((g) => g.id === id).displayName })),
        }));
    } else if (url.pathname === '/v2/Groups') {
        list = filterBy(data.groups, url.searchParams.get('filter'), { displayname: 'displayName' });
    } else {
        res.writeHead(404).end();
        return;
    }
    const start = Number(url.searchParams.get('startIndex') || 1);
    const count = Math.min(Number(url.searchParams.get('count') || 100), 100);
    res.writeHead(200, { 'Content-Type': 'application/scim+json' });
    res.end(JSON.stringify({ totalResults: list.length, startIndex: start, itemsPerPage: count, Resources: list.slice(start - 1, start - 1 + count) }));
}).listen(8080);

// app bridge of the box: POST /verify-app-password, app passwords come from /work/scim.json
http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
        if (req.method !== 'POST' || req.url !== '/verify-app-password') {
            res.writeHead(404).end();
            return;
        }
        const { identifier, password } = JSON.parse(body || '{}');
        const data = JSON.parse(fs.readFileSync('/work/scim.json', 'utf8'));
        if (!(data.appPasswords?.[identifier] ?? []).includes(password)) {
            res.writeHead(401, { 'Content-Type': 'application/json' }).end('{"message":"Password is not valid"}');
            return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ id: 'uid-' + identifier, username: identifier }));
    });
}).listen(3006);
