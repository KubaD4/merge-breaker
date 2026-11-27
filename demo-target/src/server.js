import http from 'node:http';
import fs from 'node:fs';
import { parseQuery, isValidEmail, resolveUpload, mergeSettings, cartTotal } from './index.js';

const settings = { theme: 'light' };

http.createServer((req, res) => {
  const [p, qs = ''] = req.url.split('?');
  const q = parseQuery(qs);
  if (p === '/signup') return res.end(isValidEmail(q.email) ? 'ok' : 'bad email');
  if (p.startsWith('/files/')) return fs.createReadStream(resolveUpload(p.slice(7))).pipe(res);
  if (p === '/settings' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => (body += c));
    return req.on('end', () => res.end(JSON.stringify(mergeSettings(settings, JSON.parse(body)))));
  }
  if (p === '/total') return res.end(String(cartTotal(JSON.parse(q.items || '[]'))));
  res.end('tiny-shop-api');
}).listen(process.env.PORT || 3000);
