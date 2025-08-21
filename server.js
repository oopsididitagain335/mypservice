const express = require('express');
const httpProxy = require('http-proxy');
const basicAuth = require('basic-auth');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const proxy = httpProxy.createProxyServer({});
const PORT = process.env.PORT || 10000;

// Load blocked URLs
let blockedUrls = [];
try {
  blockedUrls = fs.readFileSync('links.txt', 'utf-8')
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0);
  console.log('Blocked URLs:', blockedUrls);
} catch (err) {
  console.warn('links.txt missing or empty');
}

// Authentication
function auth(req, res, next) {
  const user = basicAuth(req);
  if (!user || user.name !== process.env.USERNAME || user.pass !== process.env.PASSWORD) {
    res.set('WWW-Authenticate', 'Basic realm="Proxy"');
    return res.status(401).send('Authentication required.');
  }
  next();
}

// Blocked URL check
function checkBlocked(req, res, next) {
  const target = req.query.url;
  if (!target) return res.status(400).send('Provide a ?url parameter');

  if (blockedUrls.some(blocked => target.startsWith(blocked))) {
    return res.status(403).send('This URL is blocked.');
  }
  next();
}

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: 'Too many requests, slow down!'
});
app.use(limiter);

// Authentication
app.use(auth);

// Proxy endpoint
app.get('/proxy', checkBlocked, (req, res) => {
  const target = req.query.url;
  proxy.web(req, res, { target, changeOrigin: true }, (err) => {
    console.error(err);
    res.status(500).send('Proxy error');
  });
});

// Link generator endpoint
app.get('/links', (req, res) => {
  const baseUrl = `http://${process.env.USERNAME}:${process.env.PASSWORD}@${req.headers.host}/proxy?url=`;
  const exampleUrls = [
    'https://example.com',
    'https://google.com',
    'https://github.com'
  ];
  const links = exampleUrls.map(u => baseUrl + encodeURIComponent(u));
  res.json({ links });
});

app.listen(PORT, () => console.log(`Private proxy running on port ${PORT}`));
