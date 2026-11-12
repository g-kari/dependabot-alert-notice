import assert from 'node:assert/strict';
import {classifyFailedUDPConnects,validNetLogSourceID} from './browser_udp_audit.mjs';
const details={details_complete:true,overflow:false,failure_reasons:[],has_send_attempt:false,has_send_event:false};
const constants={logEventTypes:{SOCKET_ALIVE:1,SOCKET_OPEN:2,UDP_CONNECT:3,SOCKET_CONNECT:4,HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK:5,UDP_BYTES_SENT:6,UDP_SEND_ERROR:7,DNS_TRANSACTION:8,UDP_BYTES_RECEIVED:9,NEW_EVENT:10},logSourceType:{UDP_SOCKET:1,UDP_CLIENT_SOCKET:2,HTTP_PROXY_CONNECT_JOB:3},logEventPhase:{PHASE_NONE:0,PHASE_BEGIN:1,PHASE_END:2},netError:{'net::OK':0,ERR_ADDRESS_UNREACHABLE:-109,ERR_FAILED:-2}};
const event=(type,phase,id,sourceType,params)=>({type,phase,source:{id,type:sourceType},...(params===undefined?{}:{params})});
const endpoint='[2001:4860:4860::8888]:443';
const fixture=()=>({constants:structuredClone(constants),events:[
 event(1,1,3,1,{source_dependency:{id:2,type:2}}),
 event(1,1,2,2,{source_dependency:{id:1,type:3}}),
 event(2,0,2,2),event(3,1,3,1,{address:endpoint}),event(3,2,3,1,{net_error:-109}),
 event(4,0,2,2,{address:endpoint,net_error:-109}),event(1,2,2,2),event(1,2,3,1),
 event(5,0,1,3,{ipv6_available:false,cached:false})]});
const result=classifyFailedUDPConnects(fixture(),details);
assert.equal(result.operations,1);assert.deepEqual([...result.eventIndexes],[3,4]);assert.deepEqual(result.reasons,[]);
for(const value of [-2147483648,-1,1,2147483647])assert(validNetLogSourceID(value));
for(const value of [0,-0,-2147483649,2147483648,4294967295,1.5,'-1',NaN,Infinity,null,undefined])assert(!validNetLogSourceID(value));
for(const mapping of [x=>-x,x=>x===3?-2147483648:x===2?2147483647:-1]) {
 const f=fixture();
 for(const e of f.events){e.source.id=mapping(e.source.id);if(e.params?.source_dependency)e.params.source_dependency.id=mapping(e.params.source_dependency.id);}
 assert.equal(classifyFailedUDPConnects(f,details).operations,1);
}
const negative=(label,edit)=>{const f=fixture();edit(f);const r=classifyFailedUDPConnects(f,details);assert.equal(r.operations,0,label);assert.equal(r.eventIndexes.size,0,label);assert(r.reasons.length,label);};
for(const [label,edit]of [
 ['successful connect',f=>f.events[4].params.net_error=0],
 ['implicit successful connect',f=>delete f.events[4].params.net_error],
 ['different error',f=>f.events[4].params.net_error=-2],
 ['error string',f=>f.events[4].params.net_error='-109'],
 ['different destination',f=>f.events[3].params.address='[2001:db8::1]:443'],
 ['different port',f=>f.events[3].params.address='[2001:4860:4860::8888]:53'],
 ['wrapper destination differs',f=>f.events[5].params.address='127.0.0.1:443'],
 ['wrapper result differs',f=>f.events[5].params.net_error=0],
 ['end contradictory address',f=>f.events[4].params.address='127.0.0.1:443'],
 ['payload field',f=>f.events[3].params.bytes='secret'],
 ['zero byte send',f=>f.events.splice(5,0,event(6,0,3,1,{byte_count:0}))],
 ['failed send',f=>f.events.splice(5,0,event(7,0,3,1,{net_error:-109}))],
 ['unrelated failed send',f=>f.events.push(event(7,0,19,1,{net_error:-109}))],
 ['DNS event',f=>f.events.push(event(8,0,1,3,{}))],
 ['receive',f=>f.events.splice(5,0,event(9,0,3,1,{byte_count:0}))],
 ['new socket event',f=>f.events.splice(5,0,event(10,0,3,1,{}))],
 ['missing lifetime end',f=>f.events.splice(7,1)],
 ['duplicate lifetime',f=>f.events.push(...structuredClone(f.events.slice(0,8)))],
 ['missing connect end',f=>f.events.splice(4,1)],
 ['duplicate connect',f=>f.events.splice(5,0,...structuredClone(f.events.slice(3,5)))],
 ['source collision',f=>f.events[4].source.type=2],
 ['source zero',f=>f.events[4].source.id=0],
 ['defined unknown source',f=>{f.constants.logSourceType.NEW_UNKNOWN=999;f.events[8].source.type=999;}],
 ['defined unknown dependency',f=>{f.constants.logSourceType.NEW_UNKNOWN=999;f.events[0].params.source_dependency.type=999;}],
 ['source too negative',f=>f.events[4].source.id=-2147483649],
 ['source unsigned alias',f=>f.events[4].source.id=4294967295],
 ['source too positive',f=>f.events[4].source.id=2147483648],
 ['dependency unsigned alias',f=>f.events[0].params.source_dependency.id=4294967295],
 ['dependency zero',f=>f.events[0].params.source_dependency.id=0],
 ['negative source collision',f=>{f.events[4].source.id=-1;f.events.push(event(5,0,-1,3,{}));}],
 ['orphan client',f=>f.events.push(event(1,1,23,2,{source_dependency:{id:1,type:3}}))],
 ['ambiguous event constants',f=>f.constants.logEventTypes.ALIAS=3],
 ['ambiguous source constants',f=>f.constants.logSourceType.ALIAS=1],
 ['unprefixed error key',f=>{f.constants.netError.ADDRESS_UNREACHABLE=f.constants.netError.ERR_ADDRESS_UNREACHABLE;delete f.constants.netError.ERR_ADDRESS_UNREACHABLE;}],
 ['wrong error mapping',f=>f.constants.netError.ERR_ADDRESS_UNREACHABLE=-110],
 ['ambiguous phase constants',f=>f.constants.logEventPhase.ALIAS=1],
 ['bad dependency type',f=>f.events[0].params.source_dependency.type=3],
 ['bad dependency shape',f=>f.events[0].params.source_dependency=[]],
 ['extra dependency field',f=>f.events[0].params.source_dependency.bytes='secret'],
 ['self dependency',f=>f.events[0].params.source_dependency={id:3,type:1}],
 ['parent missing',f=>f.events.pop()],
 ['reverse dependency',f=>f.events[8].params.source_dependency={id:3,type:1}],
 ['null params',f=>f.events[7].params=null],
 ['array params',f=>f.events[7].params=[]],
 ['unknown phase',f=>f.events[4].phase=99],
 ['unknown event',f=>f.events[4].type=99],
 ['too many events',f=>f.events=Array(100001).fill(f.events[0])]
])negative(label,edit);
const globalEvent=fixture();
globalEvent.constants.logSourceType.NONE=4;
globalEvent.events.unshift(event(10,0,-2147483647,4,{}));
assert.equal(classifyFailedUDPConnects(globalEvent,details).operations,1);
for(const invalid of [0,2147483648,4294967295,'-2147483647']) {
 const f=structuredClone(globalEvent);f.events[0].source.id=invalid;
 assert.equal(classifyFailedUDPConnects(f,details).operations,0);
}
const malformedIdentity=fixture();
malformedIdentity.events[0].source={id:'secret-source',type:'secret-type'};
const identityResult=classifyFailedUDPConnects(malformedIdentity,details);
assert.deepEqual(identityResult.diagnostic,{event_index:0,source_id:null,source_type:null});
assert(!JSON.stringify(identityResult).includes('secret'));
assert.equal(identityResult.operations,0);
// Every pairwise ordering mutation in the lifetime fails closed.
for(let i=0;i<8;i++)for(let j=i+1;j<8;j++)negative(`reordered lifetime ${i}/${j}`,f=>{[f.events[i],f.events[j]]=[f.events[j],f.events[i]];});
for(const bad of [{details_complete:false},{details_complete:'true'},{failure_reasons:null},{has_send_attempt:undefined},{overflow:true},{has_send_event:true},{has_send_attempt:true},{failure_reasons:[{reason:'unknown'}]}])assert.equal(classifyFailedUDPConnects(fixture(),{...details,...bad}).operations,0);
console.log('PASS failed UDP classifier: exact failure, malformed/schema/constants/source/dependency/lifetime/order/endpoint/send/DNS/boundary negatives');
