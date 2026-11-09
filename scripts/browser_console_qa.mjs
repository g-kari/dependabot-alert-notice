// Opt-in normal-runner QA only. Node 22/24 builtins; no package or browser install.
// Screenshots are actual CDP responses. Visual review remains a separate gate.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { readFile, writeFile, mkdir, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { PassThrough } from 'node:stream';
const MAX_PACKET=16*1024*1024, MAX_PNG=512*1024, IMAGE_BUDGET=7*1024*1024;
const sha256=b=>createHash('sha256').update(b).digest('hex');
const delay=ms=>new Promise(resolve=>setTimeout(resolve, ms));
function pngSize(b) {
  assert(b.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])), 'not a PNG');
  assert.equal(b.toString('ascii', 12, 16), 'IHDR');
  return {
    width:b.readUInt32BE(16), height:b.readUInt32BE(20)
  };
}
function allowedOrigin(raw, origins) {
  try {
    const u=new URL(raw);
    return u.protocol==='http:'&&!u.username&&!u.password&&u.hostname==='127.0.0.1'&&origins.has(u.origin);
  }catch {
    return false;
  }
}
function argumentsMap(args) {
  assert.equal(args.length%2, 0, 'arguments must be key/value pairs');
  const r= {};
  for(let i=0; i<args.length; i+=2) {
    assert(['--fixture', '--chrome', '--profile', '--out'].includes(args[i]), 'unknown argument');
    assert(!(args[i] in r), 'duplicate argument');
    r[args[i]]=args[i+1];
  }
  for(const key of ['--fixture', '--chrome', '--profile', '--out'])assert(r[key], `missing ${key}`);
  return r;
}
class CDP {
  constructor(input, output) {
    this.input=input;
    this.buffer=Buffer.alloc(0);
    this.next=0;
    this.pending=new Map();
    this.listeners=[];
    this.closed=false;
    output.on('data', b=>this.accept(b));
    output.on('error', e=>this.close(e));
    output.on('end', ()=>this.close(new Error('CDP pipe ended')));
    input.on('error', e=>this.close(e));
  }
  accept(chunk) {
    try {
      this.buffer=Buffer.concat([this.buffer, chunk]);
      assert(this.buffer.length<=MAX_PACKET, 'CDP packet bound exceeded');
      let end;
      while((end=this.buffer.indexOf(0))>=0) {
        const message=JSON.parse(this.buffer.subarray(0, end).toString('utf8'));
        this.buffer=this.buffer.subarray(end+1);
        if(Number.isInteger(message.id)) {
          const p=this.pending.get(message.id);
          if(p) {
            clearTimeout(p.timer);
            this.pending.delete(message.id);
            message.error?p.reject(new Error(`CDP ${p.method}: ${JSON.stringify(message.error)}`)):p.resolve(message.result?? {});
          }
        }else {
          for(const listener of this.listeners)listener(message);
        }
      }
    }catch(e) {
      this.close(e);
    }
  }
  call(method, params= {}, sessionId) {
    if(this.closed)return Promise.reject(new Error('CDP is closed'));
    if(this.pending.size>=64)return Promise.reject(new Error('CDP pending-command bound exceeded'));
    const id=++this.next;
    return new Promise((resolve, reject)=> {
      const timer=setTimeout(()=> {
        this.pending.delete(id);
        reject(new Error(`CDP timeout: ${method}`));
      }, 10000);
      this.pending.set(id, {
        resolve, reject, timer, method
      });
      this.input.write(JSON.stringify( {
        id, method, params, ...(sessionId? {
          sessionId
        }
        : {})
      })+'\0');
    });
  }
  close(error) {
    if(this.closed)return;
    this.closed=true;
    for(const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(error);
    }
    this.pending.clear();
  }
}
function rgb(text) {
  let m=text.match(/^rgba?\(([^)]+)\)$/);
  if(m) {
    const parts=m[1].split(/[, /]+/).filter(Boolean).map(Number);
    assert(parts.length>=3&&parts.slice(0, 3).every(Number.isFinite), 'unsupported RGB');
    assert(parts.length<4||parts[3]===1, 'transparent contrast surface');
    return parts.slice(0, 3).map(v=>v/255);
  }
  m=text.match(/^color\(srgb ([\d.]+) ([\d.]+) ([\d.]+)\)$/);
  assert(m, `unsupported computed color ${text}`);
  return m.slice(1).map(Number);
}
function contrast(fg, bg) {
  const lum=s=>rgb(s).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4).reduce((n, v, i)=>n+v*[.2126, .7152, .0722][i], 0);
  const a=lum(fg), b=lum(bg);
  return (Math.max(a, b)+.05)/(Math.min(a, b)+.05);
}
function netlogViolations(log, origins) {
  const bad=[];
  function visit(v) {
    if(!v||typeof v!=='object')return;
    for(const [key, value]of Object.entries(v)) {
      if(typeof value==='string'&&/url/i.test(key)&&/^(https?|wss?):/i.test(value)&&!allowedOrigin(value, origins)) {
        if(bad.length<16)bad.push(value.slice(0, 256));
      }else if(value&&typeof value==='object')visit(value);
    }
  }
  visit(log);
  return bad;
}
async function selfTest() {
  const input=new PassThrough(), output=new PassThrough(), client=new CDP(input, output);
  let sent='';
  input.on('data', b=>sent+=b.toString());
  const pending=client.call('Browser.getVersion');
  assert(sent.endsWith('\0'));
  output.write('{"id":1,"res');
  output.write('ult":{"product":"synthetic protocol framing only"}}\0');
  assert.equal((await pending).product, 'synthetic protocol framing only');
  client.close(new Error('self-test done'));
  assert(allowedOrigin('http://127.0.0.1:123/assets', new Set(['http://127.0.0.1:123'])));
  for(const u of ['https://example.invalid', 'http://localhost:123', 'http://127.0.0.1:124', 'file:///tmp/x', 'data:text/html,x', 'http://user:secret@127.0.0.1:123'])assert(!allowedOrigin(u, new Set(['http://127.0.0.1:123'])));
  assert(contrast('rgb(6, 43, 36)', 'rgb(120, 221, 194)')>=4.5);
  assert.deepEqual(netlogViolations( {
    events:[ {
      params: {
        url:'https://example.invalid'
      }
    }]
  }, new Set()), ['https://example.invalid']);
  assert.throws(()=>argumentsMap(['--out', 'a', '--out', 'b']));
  const errorIn=new PassThrough(),errorOut=new PassThrough(),errorClient=new CDP(errorIn,errorOut);
  const rejected=errorClient.call('Runtime.evaluate');errorOut.write('{"id":1,"error":{"message":"synthetic protocol error"}}\0');await assert.rejects(rejected,/synthetic protocol error/);errorClient.close(new Error('done'));
  const header=Buffer.alloc(24);Buffer.from([137,80,78,71,13,10,26,10]).copy(header);header.write('IHDR',12);header.writeUInt32BE(1440,16);header.writeUInt32BE(1000,20);assert.deepEqual(pngSize(header),{width:1440,height:1000});assert.throws(()=>pngSize(Buffer.alloc(24)));
  console.log('PASS stdlib-only framing/error/origin/contrast/PNG-header/argument self-tests; no Chrome, application, screenshot or network used');
}
async function main() {
  assert([22,24].includes(Number(process.versions.node.split('.')[0])),'requested QA requires reviewed Node 22 or 24');
  const args=argumentsMap(process.argv.slice(2)), out=path.resolve(args['--out']), profile=path.resolve(args['--profile']);
  assert.notEqual(out, profile, 'profile must not enter artifacts');
  const fixture=JSON.parse(await readFile(args['--fixture'], 'utf8'));
  assert.equal(fixture.synthetic, true);
  assert(Array.isArray(fixture.cases)&&fixture.cases.length<=20);
  assert.deepEqual([...fixture.cases.map(c=>c.name)].sort(),['overview','assets','asset-detail','findings','finding-detail','integrations','legacy-dashboard','legacy-detail','legacy-logs','legacy-settings','legacy-reports','empty-assets','empty-findings','empty-integrations','partial-overview','invalid-asset'].sort(),'required QA case matrix changed');
  const origins=new Set(Object.values(fixture.origins));
  assert.equal(origins.size, 3);
  for(const raw of origins) {
    const u=new URL(raw);
    assert.equal(u.protocol, 'http:');
    assert.equal(u.hostname, '127.0.0.1');
    assert(u.port);
    assert.equal(u.pathname, '/');
  }
  const checks= {
    synthetic:true, automated_status:'running', visual_review:'pending', cases:[], flows:[], violations:[], fonts:[], metadata:fixture.metadata
  }, manifest= {
    synthetic:true, visual_review:'pending', metadata:fixture.metadata, as_of:fixture.as_of, images:[]
  };
  let imageBytes=0, chrome, client, proxy, watchdog, chromeStderr='', fatal, exitCode, exitSignal, spawnError, proxyOrigin;
  const netlog=path.join(profile, 'network.json'), sessions=new Map(), requests=new Map(), documents=new Map(), allRequests=[];
  const chromeRunning=()=>!!chrome&&!spawnError&&chrome.exitCode===null&&chrome.signalCode===null;
  const violation=text=> {
    if(checks.violations.length<32)checks.violations.push(String(text).slice(0, 512));
  };
  async function writeJSON(name, value) {
    const bytes=Buffer.from(JSON.stringify(value, null, 2)+'\n');
    assert(bytes.length<=256*1024, 'JSON evidence too large');
    await writeFile(path.join(out, name), bytes, {
      mode:0o600
    });
  }
  async function ev(session, expression) {
    const r=await client.call('Runtime.evaluate', {
      expression, returnByValue:true, awaitPromise:true
    }, session);
    if(r.exceptionDetails)throw new Error(`runtime evaluation failed: ${r.exceptionDetails.text}`);
    return r.result?.value;
  }
  async function until(session, expression, label) {
    const deadline=Date.now()+10000;
    while(Date.now()<deadline) {
      if(await ev(session, expression))return;
      await delay(40);
    }
    throw new Error(`real browser readiness timeout: ${label}`);
  }
  async function ready(session, url) {
    await until(session, `document.readyState==='complete'&&location.href===${JSON.stringify(url)}`, 'navigation');
    await ev(session, "(async()=>{await document.fonts.ready;await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));return true})()");
  }
  async function reload(session, url) {
    const prior=documents.get(session)?.loader;
    await client.call('Page.reload', {}, session);
    const deadline=Date.now()+10000;
    while(documents.get(session)?.loader===prior&&Date.now()<deadline)await delay(40);
    assert(documents.get(session)?.loader&&documents.get(session).loader!==prior, 'reload did not produce a new actual document');
    await ready(session, url);
  }
  async function navigate(session, url, status=200) {
    assert(allowedOrigin(url, origins), 'navigation escaped loopback');
    const r=await client.call('Page.navigate', {
      url
    }, session);
    assert(!r.errorText, `navigation error ${r.errorText}`);
    await ready(session, url);
    assert.equal(documents.get(session)?.status, status, `actual HTTP status for ${new URL(url).pathname}`);
  }
  async function key(session, key, code, number, modifiers=0) {
    for(const type of ['keyDown', 'keyUp'])await client.call('Input.dispatchKeyEvent', {
      type, key, code, windowsVirtualKeyCode:number, nativeVirtualKeyCode:number, modifiers
    }, session);
  }
  async function follow(session, selector) {
    const href=await ev(session, `(()=>{const el=document.querySelector(${JSON.stringify(selector)});if(!el)throw Error('missing keyboard link');el.focus();return el.href})()`);
    assert(allowedOrigin(href, origins));
    await key(session, 'Enter', 'Enter', 13);
    await ready(session, href);
    return href;
  }
  async function snapshot(session, name, viewport, caseInfo) {
    const r=await client.call('Page.captureScreenshot', {
      format:'png', fromSurface:true, captureBeyondViewport:false
    }, session);
    const data=Buffer.from(r.data, 'base64');
    assert(data.length<=MAX_PNG, 'PNG exceeds 512 KiB bound');
    assert(imageBytes+data.length<=IMAGE_BUDGET, 'PNG total exceeds 7 MiB bound');
    const dimensions=pngSize(data);
    assert.deepEqual(dimensions, {
      width:viewport.width, height:viewport.height
    });
    const file=`${name}.${viewport.name}.png`;
    assert(/^[a-z-]+\.(desktop|mobile)\.png$/.test(file));
    await writeFile(path.join(out, file), data, {
      mode:0o600
    });
    imageBytes+=data.length;
    manifest.images.push( {
      file, bytes:data.length, sha256:sha256(data), ...dimensions, viewport: {
        ...viewport
      }, case:caseInfo.name, path:caseInfo.path, origin:caseInfo.origin, status:caseInfo.status, actual_cdp:true
    });
  }
  async function platformFonts(session, caseInfo) {
    const doc=await client.call('DOM.getDocument', {}, session);
    const found=await client.call('DOM.querySelector', {
      nodeId:doc.root.nodeId, selector:'h1'
    }, session);
    if(!found.nodeId)return[];
    const value=await client.call('CSS.getPlatformFontsForNode', {
      nodeId:found.nodeId
    }, session);
    const text=await ev(session, "document.querySelector('h1')?.textContent??''");
    const fonts=value.fonts??[];
    checks.fonts.push( {
      case:caseInfo.name, heading:text.slice(0, 128), fonts
    });
    if(/[\u3040-\u30ff\u3400-\u9fff]/u.test(text))assert(fonts.some(f=>/(Noto.*(CJK|JP)|Hiragino|Yu Gothic|IPA|WenQuanYi|Droid Sans Fallback|Takao|Source Han|HanaMin)/i.test(f.familyName)), 'Japanese glyph font coverage unverified; inspect retained PNG, do not install fonts');
    return fonts;
  }
  async function inspect(session, info, viewport, start) {
    if(info.name==='legacy-settings')await until(session, "document.querySelector('#codex-auth-status')?.textContent!=='確認中'", 'synthetic Codex status');
    if(info.name==='legacy-logs')await until(session, "document.querySelector('#stream-status')?.textContent.includes('ライブ')", 'actual log SSE');
    const data=await ev(session, `(()=>{const main=document.querySelector('main'),ids=[...document.querySelectorAll('[id]')].map(n=>n.id),labels=[...document.querySelectorAll('label')],refs=[...document.querySelectorAll('[aria-labelledby],[aria-describedby]')].flatMap(n=>((n.getAttribute('aria-labelledby')||'')+' '+(n.getAttribute('aria-describedby')||'')).trim().split(/\\s+/).filter(Boolean));return {text:document.body.innerText.slice(0,40000),duplicateIds:ids.filter((id,i)=>ids.indexOf(id)!==i),unboundLabels:labels.filter(n=>!n.control).map(n=>n.textContent.slice(0,80)),missingRefs:refs.filter(id=>!document.getElementById(id)),current:[...document.querySelectorAll('.finding-nav [aria-current="page"]')].map(n=>n.getAttribute('href')),overflow:main?main.scrollWidth>main.clientWidth+1:true,unsafeLinks:[...document.querySelectorAll('a[href]')].filter(n=>!n.href.startsWith(location.origin+'/')&&!n.href.startsWith(location.origin+'#')).map(n=>n.getAttribute('href')).slice(0,8),injected:window.__qa_injected===true,rich:!![...document.querySelectorAll('.markdown-body strong')].find(n=>n.textContent.includes('Synthetic browser Markdown')),reduced:matchMedia('(prefers-reduced-motion: reduce)').matches}})()`);
    const observed=(requests.get(session)??[]).slice(start), sse=observed.some(r=>new URL(r.url).pathname==='/api/logs-stream');
    checks.cases.push( {
      name:info.name, viewport:viewport.name, status:documents.get(session)?.status, duplicate_ids:data.duplicateIds, unbound_labels:data.unboundLabels, missing_aria:data.missingRefs, main_overflow:data.overflow, sse, rich:data.rich, legacy_label_scope:info.native?'enforced':'reported; existing form migration is not declared complete'
    });
    if(info.screenshot)await snapshot(session, info.name, viewport, info);
    assert(data.text.includes(info.want), `missing expected ${info.name} content`);
    assert.equal(data.injected, false, 'synthetic untrusted text executed');
    assert.deepEqual(data.duplicateIds, [], 'duplicate DOM IDs');
    assert.deepEqual(data.missingRefs, [], 'broken ARIA reference');
    assert.equal(data.overflow, false, 'main body horizontally overflows');
    assert(data.reduced, 'reduced-motion override absent');
    assert.deepEqual(data.current, info.nav?[info.nav]:[], 'selected navigation mismatch');
    if(info.native) {
      assert.deepEqual(data.unboundLabels, [], 'unassociated native form label');
      assert.deepEqual(data.unsafeLinks, [], 'native evidence became an external/executable URL');
      assert.equal(sse, false, 'native page opened a legacy SSE stream');
    }else {
      assert(sse, 'legacy page did not open actual log SSE');
    }
    if(info.rich)assert(data.rich, 'actual Goldmark strong markup absent');
    if(info.name==='overview')for(const [name, count]of Object.entries(fixture.metrics)) {
      const n=await ev(session, `[...document.querySelectorAll('.console-metric')].find(n=>n.querySelector('h2')?.textContent===${JSON.stringify(name)})?.querySelector('strong')?.textContent`);
      assert.equal(Number(n), count, `retained global metric ${name}`);
    }
    if(info.name==='integrations')for(const word of ['failed', 'running', 'partial', 'unknown', 'epss_offline', 'kev_offline', 'github_code_scanning', 'github_secret_scanning'])assert(data.text.includes(word), `recorded state/source missing ${word}`);
    await platformFonts(session, info);
    console.log(`PASS real browser ${viewport.name} ${info.name}`);
  }
  async function hoverContrast(session, selector, label) {
    await ev(session, `document.querySelector(${JSON.stringify(selector)}).scrollIntoView({block:'center'})`);
    const p=await ev(session, `(()=>{const r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2}})()`);
    await client.call('Input.dispatchMouseEvent', {
      type:'mouseMoved', x:p.x, y:p.y
    }, session);
    const colors=await ev(session, `(()=>{const s=getComputedStyle(document.querySelector(${JSON.stringify(selector)}));return{fg:s.color,bg:s.backgroundColor}})()`);
    const ratio=contrast(colors.fg, colors.bg);
    checks.flows.push( {
      check:label, ratio, colors
    });
    assert(ratio>=4.5, `${label} hover contrast below 4.5:1`);
  }
  async function flows(session, viewport) {
    const base=fixture.origins.primary;
    await navigate(session, base+'/assets');
    await key(session, 'Tab', 'Tab', 9);
    assert(await ev(session, "document.activeElement.classList.contains('finding-skip')"), 'first Tab did not reach skip link');
    const focus=await ev(session, "(()=>{const s=getComputedStyle(document.activeElement),r=document.activeElement.getBoundingClientRect();return{style:s.outlineStyle,width:parseFloat(s.outlineWidth),visible:r.top>=0&&r.bottom<=innerHeight}})()");
    assert(focus.style!=='none'&&focus.width>=2&&focus.visible, 'keyboard focus is not visible');
    await key(session, 'Tab', 'Tab', 9);
    await key(session, 'Tab', 'Tab', 9, 8);
    assert(await ev(session, "document.activeElement.classList.contains('finding-skip')"), 'Shift-Tab lost skip link');
    await key(session, 'Enter', 'Enter', 13);
    assert(await ev(session, "location.hash==='#main-content'"), 'skip Enter did not navigate');
    await navigate(session, base+'/assets?limit=1&source=dependabot');
    await ev(session, "document.querySelector('#asset-q').focus()");
    await client.call('Input.insertText', {
      text:'browser'
    }, session);
    await key(session, 'Enter', 'Enter', 13);
    await until(session, "document.readyState==='complete'&&new URL(location.href).searchParams.get('q')==='browser'", 'keyboard filter submission');
    await hoverContrast(session, '.btn-primary', 'native primary');
    const next=await follow(session, 'a[rel="next"]');
    assert.equal(new URL(next).searchParams.get('source'), 'dependabot');
    const selected=await follow(session, '.console-table tbody td:first-child a');
    assert(new URL(selected).pathname.startsWith('/assets/'));
    let history=await client.call('Page.getNavigationHistory', {}, session);
    assert(history.currentIndex>0);
    await client.call('Page.navigateToHistoryEntry', {
      entryId:history.entries[history.currentIndex-1].id
    }, session);
    await ready(session, next);
    await reload(session, next);
    assert.equal(await ev(session, "new URL(location.href).searchParams.get('q')"), 'browser');
    history=await client.call('Page.getNavigationHistory', {}, session);
    assert(history.currentIndex+1<history.entries.length);
    await client.call('Page.navigateToHistoryEntry', {
      entryId:history.entries[history.currentIndex+1].id
    }, session);
    await ready(session, selected);
    const back=await follow(session, '.finding-topline a');
    assert.equal(new URL(back).searchParams.get('q'), 'browser');
    assert.equal(new URL(back).searchParams.get('source'), 'dependabot');
    await navigate(session, base+fixture.long_asset_url);
    const longBack=await follow(session, '.finding-topline a');
    assert.equal(Buffer.byteLength(new URL(longBack).searchParams.get('q')), 256);
    await reload(session, longBack);
    await navigate(session, base+fixture.cleared_source_url);
    const cleared=await ev(session, `(()=>{const link=[...document.querySelectorAll('a')].find(a=>a.getAttribute('href')?.startsWith('/findings?asset_id='));return{all:link?!new URL(link.href).searchParams.has('source'):false,anchor:!!document.querySelector('a[href="/findings/${fixture.anchor_id}"]')}})()`);
    assert(cleared.all&&cleared.anchor, 'cleared source inherited return-list source');
    await navigate(session, base+'/');
    await hoverContrast(session, '.btn-reject', 'legacy danger');
    checks.flows.push( {
      check:'actual keyboard/filter/paging/Back/Forward/reload/long-query/cleared-source', viewport:viewport.name, passed:true
    });
  }
  try {
    await mkdir(profile, {
      recursive:false, mode:0o700
    });
    // A rejecting loopback proxy gives browser background traffic no external
    // destination, including literal IPs. It never forwards, and any use fails QA.
    proxy=createServer((req, res)=> {
      violation(`blocked browser proxy request ${req.url}`);
      res.writeHead(403);
      res.end('offline synthetic QA');
    });
    proxy.on('connect', (req, socket)=> {
      violation(`blocked browser proxy CONNECT ${req.url}`);
      socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    });
    proxy.listen(0, '127.0.0.1');
    await once(proxy, 'listening');
    proxyOrigin=`http://127.0.0.1:${proxy.address().port}`;
    const flags=['--headless=new', '--remote-debugging-pipe', `--user-data-dir=${profile}`, '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-default-apps', '--disable-extensions', '--disable-breakpad', '--disable-quic', '--no-first-run', '--no-default-browser-check', `--proxy-server=http://127.0.0.1:${proxy.address().port}`, '--proxy-bypass-list=127.0.0.1;localhost;[::1]', '--host-resolver-rules=MAP * ~NOTFOUND', `--log-net-log=${netlog}`, '--net-log-capture-mode=Default', 'about:blank'];
    assert(!flags.some(s=>/^--(no-sandbox|disable-setuid-sandbox|disable-web-security|ignore-certificate-errors)/.test(s)), 'unsafe browser flag');
    const chromeEnv=Object.fromEntries(['PATH','HOME','TMPDIR','LANG','LC_ALL'].filter(k=>process.env[k]!==undefined).map(k=>[k,process.env[k]]));
    chrome=spawn(args['--chrome'], flags, {
      stdio:['ignore', 'ignore', 'pipe', 'pipe', 'pipe'], env:chromeEnv
    });
    chrome.stderr.on('data', b=> {
      chromeStderr=(chromeStderr+b.toString()).slice(-16384);
    });
    client=new CDP(chrome.stdio[3], chrome.stdio[4]);
    chrome.on('error', e=>{spawnError=e;client.close(e);});
    chrome.on('exit', (code,signal)=> {
      exitCode=code;
      exitSignal=signal;
      client.close(new Error(`Chrome exited ${code}`));
    });
    watchdog=setTimeout(()=> {
      violation('browser QA real-time watchdog');
      chrome.kill('SIGTERM');
      setTimeout(()=> {
        if(chromeRunning())chrome.kill('SIGKILL');
      }, 2000).unref();
    }, 180000);
    const stop=()=> {
      violation('browser QA interrupted');
      chrome.kill('SIGTERM');
    };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
    client.listeners.push(message=> {
      if(message.method==='Target.attachedToTarget') {
        const {
          sessionId, targetInfo
        }
        =message.params;
        const configure=(async()=> {
          assert(sessions.size<=8,'unexpected browser target count');
          if(!['page', 'iframe'].includes(targetInfo.type)) {
            violation(`unexpected target type ${targetInfo.type}`);
            await client.call('Target.closeTarget', {
              targetId:targetInfo.targetId
            });
            return sessionId;
          }
          await client.call('Network.enable', {}, sessionId);
          await client.call('Network.setBypassServiceWorker', {
            bypass:true
          }, sessionId);
          await client.call('Network.setBlockedURLs', {
            urls:['ws://*', 'wss://*']
          }, sessionId);
          await client.call('Fetch.enable', {
            patterns:[ {
              urlPattern:'*'
            }]
          }, sessionId);
          await client.call('Runtime.enable', {}, sessionId);
          await client.call('Page.enable', {}, sessionId);
          await client.call('DOM.enable', {}, sessionId);
          await client.call('CSS.enable', {}, sessionId);
          await client.call('Target.setAutoAttach', {
            autoAttach:true, waitForDebuggerOnStart:true, flatten:true
          }, sessionId);
          await client.call('Runtime.runIfWaitingForDebugger', {}, sessionId);
          return sessionId;
        })();
        sessions.set(targetInfo.targetId, configure);
        configure.catch(e=>violation(e.message));
      }else if(message.method==='Fetch.requestPaused') {
        const {
          requestId, request
        }
        =message.params;
        const safe=(request.url==='about:blank'||allowedOrigin(request.url, origins))&&['GET', 'HEAD'].includes(request.method);
        if(!safe)violation(`off-origin/action request ${request.method} ${request.url}`);
        client.call(safe?'Fetch.continueRequest':'Fetch.failRequest', safe? {
          requestId
        }
        : {
          requestId, errorReason:'BlockedByClient'
        }, message.sessionId).catch(e=>violation(e.message));
      }else if(message.method==='Network.requestWillBeSent') {
        const request=message.params.request;
        if(request.url==='about:blank')return;
        if(!allowedOrigin(request.url, origins))violation(`non-loopback page request ${request.url}`);
        const list=requests.get(message.sessionId)??[];
        if(list.length<512)list.push( {
          url:request.url, method:request.method
        });
        else violation('request bound exceeded');
        requests.set(message.sessionId, list);
        if(allRequests.length<1024)allRequests.push(request.url);
      }else if(message.method==='Network.responseReceived'&&message.params.type==='Document') {
        documents.set(message.sessionId, {
          url:message.params.response.url, status:message.params.response.status, loader:message.params.loaderId
        });
      } else if(message.method==='Network.webSocketCreated') {
        violation('unexpected WebSocket');
      }
    });
    checks.browser=await client.call('Browser.getVersion');
    checks.cdp_pipe_handshake=true;
    manifest.browser=checks.browser;
    checks.node=process.version;
    checks.network_guard='exact fixture origins; rejecting loopback proxy; no DIRECT fallback';
    checks.sandbox_disable_flags=false;
    checks.configured_deadlines_ms={cdp_command:10000,navigation:10000,browser_watchdog:180000,graceful_exit:3000,signal_exit:2000};
    manifest.node=process.version;
    await client.call('Target.setAutoAttach', {
      autoAttach:true, waitForDebuggerOnStart:true, flatten:true
    });
    for(const viewport of [ {
      name:'desktop', width:1440, height:1000, mobile:false
    }, {
      name:'mobile', width:390, height:844, mobile:true
    }]) {
      const {
        targetId
      }
      =await client.call('Target.createTarget', {
        url:'about:blank'
      });
      const deadline=Date.now()+10000;
      while(!sessions.has(targetId)&&Date.now()<deadline)await delay(20);
      assert(sessions.has(targetId), 'CDP auto-attach handshake failed');
      const session=await sessions.get(targetId);
      await client.call('Target.activateTarget', {
        targetId
      });
      await client.call('Emulation.setDeviceMetricsOverride', {
        width:viewport.width, height:viewport.height, screenWidth:viewport.width, screenHeight:viewport.height, mobile:viewport.mobile, deviceScaleFactor:1
      }, session);
      await client.call('Emulation.setEmulatedMedia', {
        features:[ {
          name:'prefers-reduced-motion', value:'reduce'
        }]
      }, session);
      await client.call('Emulation.setFocusEmulationEnabled', {
        enabled:true
      }, session);
      for(const info of fixture.cases) {
        const start=(requests.get(session)??[]).length;
        await navigate(session, new URL(info.path, fixture.origins[info.origin]).href, info.status);
        await inspect(session, info, viewport, start);
        assert.equal(checks.violations.length, 0, 'offline/browser guard violation');
      }
      await flows(session, viewport);
      await client.call('Target.closeTarget', {
        targetId
      });
    }
  }catch(e) {
    fatal=e;
    checks.error=String(e.stack??e).slice(0, 16384);
  } finally {
    clearTimeout(watchdog);
    if(chrome&&!spawnError) {
      if(chromeRunning()) {
        try {
          await client?.call('Browser.close');
        }catch {}
        if(chromeRunning())await Promise.race([once(chrome, 'exit'), delay(3000)]);
        if(chromeRunning()) {
          chrome.kill('SIGTERM');
          await Promise.race([once(chrome, 'exit'), delay(2000)]);
        }
        if(chromeRunning()) {
          chrome.kill('SIGKILL');
          await once(chrome, 'exit');
          violation('Chrome required forced cleanup');
        }
      }
      try {
        const log=JSON.parse(await readFile(netlog, 'utf8'));
        for(const u of netlogViolations(log, new Set([...origins,proxyOrigin])))violation(`non-loopback NetLog URL ${u}`);
        checks.network_audit='completed';
      }catch(e) {
        violation(`network audit unavailable: ${e.message}`);
      }
    }
    if(proxy) {
      proxy.closeAllConnections();
      await new Promise(resolve=>proxy.close(resolve));
    }
    checks.chrome_stderr=chromeStderr;
    checks.chrome_exit_code=exitCode??null;
    checks.chrome_exit_signal=exitSignal??null;
    checks.chrome_cleanup_complete=!!chrome&&!spawnError&&!chromeRunning();
    checks.loopback_proxy_closed=!!proxy;
    if(chrome&&!spawnError&&exitCode!==0)violation(`Chrome exited abnormally: ${exitCode}/${exitSignal}`);
    checks.request_count=allRequests.length;
    checks.automated_status=!fatal&&checks.violations.length===0?'passed':'failed';
    checks.visual_review='pending';
    await writeJSON('checks.json', checks);
    manifest.automated_status=checks.automated_status;
    manifest.configured_deadlines_ms=checks.configured_deadlines_ms??{};
    manifest.child_cleanup={chrome_exit_code:checks.chrome_exit_code,chrome_exit_signal:checks.chrome_exit_signal,chrome_cleanup_complete:checks.chrome_cleanup_complete,loopback_proxy_closed:checks.loopback_proxy_closed};
    await writeJSON('manifest.json', manifest);
    const files=await readdir(out);
    assert(files.length<=31, 'artifact file count exceeds Node budget');
    let bytes=0;
    for(const f of files) {
      assert(/^[a-z-]+\.(desktop|mobile)\.png$/.test(f)||['manifest.json', 'checks.json'].includes(f), 'unexpected artifact entry');
      const s=await stat(path.join(out, f));
      assert(s.isFile());
      bytes+=s.size;
    }
    assert(bytes<=8*1024*1024, 'artifact size exceeds bound');
  }
  if(fatal)throw fatal;
  assert.equal(checks.cases.length,fixture.cases.length*2,'incomplete desktop/mobile matrix');
  assert.equal(manifest.images.length,28,'incomplete runtime screenshot matrix');
  assert.equal(checks.violations.length, 0, `offline guard failed: ${checks.violations.join('; ')}`);
  assert.equal(checks.automated_status, 'passed');
  console.log(`PASS automated real Chrome checks; ${manifest.images.length} runtime PNGs saved. Download/materialization/visual review remain pending.`);
}
if(process.argv.slice(2).length===1&&process.argv[2]==='--self-test')await selfTest();
else await main();
