// Execute the production inline scripts with a deterministic EventSource/DOM.
// No browser, network, Go application or provider credentials are used.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';
const root=process.argv[2]??new URL('../internal/web/templates/',import.meta.url);
function element() {
  return {children:[],className:'',textContent:'',innerHTML:'',classList:{add(){},remove(){}},
    appendChild(n){this.children.push(n);},remove(){}};
}
for(const file of ['layout.html','logs.html']) {
  const html=await readFile(new URL(file,typeof root==='string'?new URL(root,'file://'+process.cwd()+'/'):root),'utf8');
  const scripts=[...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)].map(m=>m[1]);
  const code=scripts.find(s=>s.includes('new EventSource'));
  assert(code,`${file}: missing production stream script`);
  const handlers=new Map(), streams=[], nodes=new Map();
  class EventSource {
    constructor(url){assert.equal(url,'/api/logs-stream');this.closed=false;this.handlers={};streams.push(this);}
    close(){assert(!this.closed,'stream closed twice');this.closed=true;}
    addEventListener(name,fn){this.handlers[name]=fn;}
  }
  const window={addEventListener(name,fn){const list=handlers.get(name)??[];list.push(fn);handlers.set(name,list);}};
  const document={getElementById(id){if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);},querySelectorAll(){return[];},createElement:element};
  const fire=name=>{for(const fn of handlers.get(name)??[])fn({persisted:true});};
  runInNewContext(code,{window,document,EventSource,location:{pathname:'/logs'},setTimeout:fn=>fn()},{timeout:1000});
  assert.equal(streams.length,1,`${file}: initial stream`);
  fire('pageshow');fire('pageshow');assert.equal(streams.length,1,'duplicate pageshow opens extra stream');
  const stale=streams[0];fire('pagehide');assert(stale.closed,`${file}: pagehide must close stream`);
  fire('pagehide');assert.equal(streams.filter(s=>!s.closed).length,0);
  fire('pageshow');assert.equal(streams.length,2);const current=streams[1];
  assert.doesNotThrow(()=>stale.onmessage?.({data:'invalid JSON from stale stream'}),'stale queued message must be ignored');
  fire('pageshow');assert.equal(streams.length,2);
  if(file==='layout.html') {
    const container=nodes.get('toast-container');
    const message={data:JSON.stringify({message:'synthetic',level:'info'})};
    current.onmessage(message);assert.equal(container.children.length,0,'history replay must not toast');
    stale.handlers.ready();current.onmessage(message);assert.equal(container.children.length,0,'stale ready must not unlock current stream');
    current.handlers.ready();current.onmessage(message);assert.equal(container.children.length,1,'live log should toast');
  } else {
    const status=nodes.get('stream-status');current.onopen();assert.equal(status.textContent,'● ライブ');
    stale.onerror();assert.equal(status.textContent,'● ライブ','stale errors must not alter restored status');
    const container=nodes.get('log-container');container.innerHTML='old history';
    current.onmessage({data:JSON.stringify({message:'synthetic',level:'info',ts:'00:00'})});
    assert.equal(container.innerHTML,'','restored log history replaces old snapshot');
  }
  for(let i=0;i<12;i++){fire('pagehide');fire('pageshow');assert.equal(streams.filter(s=>!s.closed).length,1,'repeat navigation leaks streams');}
  fire('pagehide');assert(streams.every(s=>s.closed));
  console.log(`PASS ${file}: initial/repeated show, hide, history restore, stale callbacks and bounded streams`);
}
