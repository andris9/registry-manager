/* eslint no-console: 0*/

'use strict';
const http = require('http');

const hostname = '127.0.0.1';
const port = 5060;

const server = http.createServer((req, res) => {
    console.log(req.remoteAddress);
    console.log(req.method);
    console.log(req.url);
    console.log(req.headers);
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/plain');
    res.end('Hello World\n');
});

server.listen(port, hostname, () => {
    console.log(`Server running at http://${hostname}:${port}/`);
});
