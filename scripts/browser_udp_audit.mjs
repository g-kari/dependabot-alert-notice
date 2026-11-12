// Classify captured failed operations, never infer their Chromium call site.
// This is not packet capture or proof about operations omitted from NetLog.
const ENDPOINT='[2001:4860:4860::8888]:443';
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const exactKeys=(x,keys)=>object(x)&&Object.keys(x).every(k=>keys.includes(k));
const id=x=>Number.isSafeInteger(x)&&x>0;
export function classifyFailedUDPConnects(log,details) {
  const rejected=reason=>({eventIndexes:new Set(),operations:0,reasons:[reason]});
  if(details?.details_complete!==true||details.overflow!==false||!Array.isArray(details.failure_reasons)||details.failure_reasons.length||details.has_send_attempt!==false||details.has_send_event!==false)return rejected('incomplete_or_prohibited_udp_details');
  if(!Array.isArray(log?.events)||log.events.length>100000)return rejected('invalid_event_bound');
  const maps={};
  for(const key of ['logEventTypes','logSourceType','logEventPhase','netError']) {
    const entries=Object.entries(log.constants?.[key]??{});
    if(!entries.length||entries.some(([,v])=>!Number.isSafeInteger(v)||(key==='netError'?v>0:v<0))||new Set(entries.map(([,v])=>v)).size!==entries.length)return rejected('ambiguous_constants');
    maps[key]=new Map(entries.map(([k,v])=>[v,k]));
  }
  if(log.constants.netError.ADDRESS_UNREACHABLE!==-109)return rejected('unexpected_error_constant');
  const sources=new Map(),edges=[];
  for(let i=0;i<log.events.length;i++) {
    const event=log.events[i];
    if(!object(event)||!id(event.source?.id)||!Number.isSafeInteger(event.source.type))return rejected('invalid_source_identity');
    const type=maps.logSourceType.get(event.source.type),name=maps.logEventTypes.get(event.type),phase=maps.logEventPhase.get(event.phase);
    if(!type||!name||!['PHASE_NONE','PHASE_BEGIN','PHASE_END'].includes(phase))return rejected('unknown_event_identity');
    const params=event.params===undefined?{}:event.params;
    if(!object(params))return rejected('invalid_event_params');
    let source=sources.get(event.source.id);
    if(!source){source={type,events:[]};sources.set(event.source.id,source);}
    if(source.type!==type)return rejected('source_type_collision');
    source.events.push({i,name,phase,params});
    if(params.source_dependency!==undefined) {
      const d=params.source_dependency;
      if(!exactKeys(d,['id','type'])||!id(d.id)||!Number.isSafeInteger(d.type)||!maps.logSourceType.has(d.type)||d.id===event.source.id)return rejected('invalid_dependency');
      edges.push({from:event.source.id,to:d.id,type:maps.logSourceType.get(d.type)});
    }
    if(/^UDP_/.test(name)&&name!=='UDP_CONNECT')return rejected('other_udp_operation');
    if(/^(DNS_TRANSACTION|MDNS_)/.test(name))return rejected('dns_operation');
    if(name==='UDP_CONNECT'&&type!=='UDP_SOCKET')return rejected('unexpected_connect_source');
  }
  for(const edge of edges)if(sources.get(edge.to)?.type!==edge.type)return rejected('dependency_identity_mismatch');
  const shape=(events,expected)=>events.length===expected.length&&events.every((e,i)=>e.name===expected[i][0]&&e.phase===expected[i][1]);
  const empty=e=>exactKeys(e.params,[]);
  const alive=e=>exactKeys(e.params,['source_dependency'])&&object(e.params.source_dependency);
  const failure=e=>exactKeys(e.params,['net_error'])&&e.params.net_error===-109;
  const connected=e=>exactKeys(e.params,['address','net_error'])&&e.params.address===ENDPOINT&&e.params.net_error===-109;
  const result={eventIndexes:new Set(),operations:0,reasons:[]},clients=new Set();
  for(const [socketID,socket]of sources) {
    if(socket.type!=='UDP_SOCKET')continue;
    const e=socket.events;
    if(!shape(e,[['SOCKET_ALIVE','PHASE_BEGIN'],['UDP_CONNECT','PHASE_BEGIN'],['UDP_CONNECT','PHASE_END'],['SOCKET_ALIVE','PHASE_END']]))return rejected('unexpected_socket_sequence');
    if(!alive(e[0])||!exactKeys(e[1].params,['address'])||e[1].params.address!==ENDPOINT||!failure(e[2])||!empty(e[3]))return rejected('unexpected_socket_parameters');
    const clientID=e[0].params.source_dependency.id,client=sources.get(clientID);
    if(client?.type!=='UDP_CLIENT_SOCKET'||clients.has(clientID))return rejected('unexpected_or_reused_client');
    const c=client.events;
    if(!shape(c,[['SOCKET_ALIVE','PHASE_BEGIN'],['SOCKET_OPEN','PHASE_NONE'],['SOCKET_CONNECT','PHASE_NONE'],['SOCKET_ALIVE','PHASE_END']]))return rejected('unexpected_client_sequence');
    if(!alive(c[0])||!exactKeys(c[1].params,['net_error'])||(c[1].params.net_error!==undefined&&c[1].params.net_error!==0)||!connected(c[2])||!empty(c[3]))return rejected('unexpected_client_parameters');
    const parentID=c[0].params.source_dependency.id,parent=sources.get(parentID);
    if(!parent||['UDP_SOCKET','UDP_CLIENT_SOCKET'].includes(parent.type)||parentID===socketID)return rejected('invalid_parent');
    const order=[e[0].i,c[0].i,c[1].i,e[1].i,e[2].i,c[2].i,c[3].i,e[3].i];
    if(order.some((x,i)=>i>0&&x<=order[i-1]))return rejected('lifetime_order_mismatch');
    // Only the captured socket->client->parent ownership edges are expected.
    if(edges.filter(x=>x.from===socketID).length!==1||edges.filter(x=>x.from===clientID).length!==1||edges.some(x=>x.to===socketID||(x.to===clientID&&x.from!==socketID)))return rejected('socket_dependency_anomaly');
    clients.add(clientID);result.eventIndexes.add(e[1].i);result.eventIndexes.add(e[2].i);result.operations++;
  }
  if([...sources].some(([key,s])=>s.type==='UDP_CLIENT_SOCKET'&&!clients.has(key)))return rejected('orphan_udp_client');
  return result;
}
