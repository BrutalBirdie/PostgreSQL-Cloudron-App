// Minimal SMTP server for the end-to-end test, stands in for the Cloudron
// sendmail addon with requiresValidCertificate: AUTH only after STARTTLS.
// Each message is written to /work/mail/<n>-<recipient>.eml.
import net from 'node:net';
import tls from 'node:tls';
import fs from 'node:fs';

const secureContext = tls.createSecureContext({ key: fs.readFileSync('/work/certs/mail_key.pem'), cert: fs.readFileSync('/work/certs/mail_cert.pem') });
let n = 0;
fs.mkdirSync('/work/mail', { recursive: true });

net.createServer((plain) => {
    let sock = plain, buf = '', data = null, rcpt = '', secure = false, authed = false;
    const reply = (s) => sock.write(s + '\r\n');
    const onLine = (line) => {
        if (data !== null) {
            if (line === '.') {
                fs.writeFileSync(`/work/mail/${String(++n).padStart(3, '0')}-${rcpt}.eml`, data);
                data = null;
                reply('250 queued');
            } else {
                data += (line.startsWith('..') ? line.slice(1) : line) + '\n';
            }
            return;
        }
        const cmd = line.split(' ')[0].toUpperCase();
        if (cmd === 'EHLO' || cmd === 'HELO') reply(secure ? '250-smtp-mock\r\n250 AUTH PLAIN' : '250-smtp-mock\r\n250 STARTTLS');
        else if (cmd === 'STARTTLS') {
            reply('220 go ahead');
            plain.removeAllListeners('data');
            sock = new tls.TLSSocket(plain, { isServer: true, secureContext });
            sock.on('data', onData);
            secure = true;
        } else if (cmd === 'AUTH') {
            authed = secure && Buffer.from(line.split(' ')[2] ?? '', 'base64').toString() === '\0app\0mailpass';
            reply(authed ? '235 ok' : '530 STARTTLS and valid credentials required');
        } else if (cmd === 'MAIL') reply(authed ? '250 ok' : '530 auth required');
        else if (cmd === 'RCPT') { rcpt = line.match(/<([^>]+)>/)[1]; reply('250 ok'); }
        else if (cmd === 'DATA') { data = ''; reply('354 go'); }
        else if (cmd === 'QUIT') { reply('221 bye'); sock.end(); }
        else reply('250 ok');
    };
    const onData = (chunk) => {
        buf += chunk.toString('utf8');
        let i;
        while ((i = buf.indexOf('\r\n')) >= 0) {
            const line = buf.slice(0, i);
            buf = buf.slice(i + 2);
            onLine(line);
        }
    };
    plain.on('data', onData);
    plain.on('error', () => {});
    reply('220 smtp-mock');
}).listen(2587);
