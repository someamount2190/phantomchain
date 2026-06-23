// tiny static server for cloud-init NoCloud-net: serves seed/ dir (user-data, meta-data)
const http = require('http'), fs = require('fs'), path = require('path');
const dir = process.argv[2], port = parseInt(process.argv[3] || '8000', 10);
http.createServer((req, res) => {
  const name = (req.url.split('?')[0] || '/').replace(/^\//, '') || 'index';
  try {
    const data = fs.readFileSync(path.join(dir, name));
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(data);
    console.log('served', name);
  } catch (e) {
    res.writeHead(404); res.end('not found');
    console.log('404', name);
  }
}).listen(port, '0.0.0.0', () => console.log('cloud-init server on', port, 'dir', dir));
