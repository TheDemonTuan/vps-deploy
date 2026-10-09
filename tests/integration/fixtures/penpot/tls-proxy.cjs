'use strict';
// Real TLS on both hops; this namespace is the sole allowed tunnel peer.
const https=require('node:https'), fs=require('node:fs');
const tls={key:fs.readFileSync('/fixture/server.key'),cert:fs.readFileSync('/fixture/server.crt')};
const safePath=req=>req.url.split(/[?#]/,1)[0];
const options=req=>({hostname:'172.31.250.4',port:8080,servername:'design.tuannguyenviet.site',
  ca:fs.readFileSync('/fixture/ca.crt'),rejectUnauthorized:true,path:req.url,method:req.method,
  headers:{...req.headers,host:'design.tuannguyenviet.site'}});
const observed=(req,status,cause)=>console.log(JSON.stringify({path:safePath(req),status,...(cause?{cause}:{})}));
const server=https.createServer(tls,(req,res)=>{
  if(fs.existsSync('/fixture/reject-maintenance') && safePath(req)==='/readyz'){
    res.writeHead(503);res.end('fixture acknowledgement rejected');return;
  }
  const upstream=https.request(options(req),reply=>{
    res.writeHead(reply.statusCode,reply.headers);reply.pipe(res);observed(req,reply.statusCode);
  });
  upstream.on('error',err=>{observed(req,502,err.code||'UPSTREAM_ERROR');res.writeHead(502);res.end('upstream unavailable');});
  req.pipe(upstream);
});
const responseHead=reply=>'HTTP/1.1 '+reply.statusCode+' '+reply.statusMessage+'\r\n'+
  Object.entries(reply.headers).map(([key,value])=>key+': '+value+'\r\n').join('')+'\r\n';
server.on('upgrade',(req,client,head)=>{
  const upstream=https.request(options(req));
  upstream.on('upgrade',(reply,peer,pending)=>{
    client.write(responseHead(reply));if(pending.length)client.write(pending);if(head.length)peer.write(head);
    observed(req,reply.statusCode);peer.pipe(client);client.pipe(peer);
    client.on('error',()=>peer.destroy());peer.on('error',()=>client.destroy());
    client.on('close',()=>peer.destroy());peer.on('close',()=>client.destroy());
  });
  upstream.on('response',reply=>{client.write(responseHead(reply));reply.pipe(client);observed(req,reply.statusCode);});
  upstream.on('error',err=>{observed(req,502,err.code||'UPSTREAM_ERROR');client.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n');});
  upstream.end();
});
server.listen(8443,'0.0.0.0');
