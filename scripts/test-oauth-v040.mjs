import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { encryptSecret, decryptSecret, getConnectionStatus, withNewRelicSession, callNewRelicRawTool, callNewRelicTool } from "../worker/newrelic.js";
import { updateUsageConsents } from "../worker/usage-consent.js";
globalThis.crypto ||= webcrypto;
class MemoryD1 {
  states = new Map();
  connections = new Map();
  rates = new Map();
  locks = new Map();
  consents = new Map();

  prepare(query) {
    const normalized = query.replace(/\s+/g, " ").trim().toUpperCase();
    const database = this;
    return {
      values: [],
      bind(...values) { this.values = values; return this; },
      async run() { return database.run(normalized, this.values); },
      async first() { return database.first(normalized, this.values); },
      async all() { return database.all(normalized, this.values); },
    };
  }

  async batch(statements) {
    const results = [];
    for (const statement of statements) results.push(await statement.run());
    return results;
  }

  async run(query, values) {
    if (query.startsWith("INSERT INTO NR_USAGE_CONSENTS")) {
      const [user_id, capability, granted_at, expires_at] = values;
      this.consents.set(user_id + ":" + capability, { user_id, capability, granted_at, expires_at });
      return { meta: { changes: 1 } };
    }
    if (query.startsWith("DELETE FROM NR_USAGE_CONSENTS WHERE USER_ID = ? AND CAPABILITY = ?")) {
      const changed = this.consents.delete(values[0] + ":" + values[1]);
      return { meta: { changes: changed ? 1 : 0 } };
    }
    if (query.startsWith("INSERT INTO NR_REFRESH_LOCKS")) {
      const [userId, owner, expires, now] = values;
      const prior = this.locks.get(userId);
      if (prior && prior.expires_at >= now) return { meta: { changes: 0 } };
      this.locks.set(userId, { owner, expires_at: expires });
      return { meta: { changes: 1 } };
    }
    if (query.startsWith("DELETE FROM NR_REFRESH_LOCKS")) {
      const [userId, owner] = values;
      if (this.locks.get(userId)?.owner === owner) this.locks.delete(userId);
      return { meta: { changes: 1 } };
    }
    if (query.startsWith("UPDATE NR_CONNECTIONS SET ENCRYPTED_ACCESS_TOKEN")) {
      const [access, refresh, expiry, userId, oldRefresh, lockUser, owner, now] = values;
      const row = this.connections.get(userId);
      const lock = this.locks.get(lockUser);
      if (!row || row.encrypted_refresh_token !== oldRefresh || lock?.owner !== owner || lock.expires_at <= now) return { meta: { changes: 0 } };
      Object.assign(row, { encrypted_access_token: access, encrypted_refresh_token: refresh, access_expires_at: expiry });
      return { meta: { changes: 1 } };
    }
    if (query.startsWith("DELETE FROM NR_OAUTH_STATES WHERE EXPIRES_AT <")) {
      for (const [key, row] of this.states) if (row.expires_at < values[0]) this.states.delete(key);
      return { meta: { changes: 0 } };
    }
    if (query.startsWith("INSERT INTO NR_OAUTH_STATES")) {
      const [state_hash, user_id, encrypted_verifier, redirect_uri, region, expires_at] = values;
      this.states.set(state_hash, { state_hash, user_id, encrypted_verifier, redirect_uri, region, expires_at });
      return { meta: { changes: 1 } };
    }
    if (query.startsWith("DELETE FROM NR_OAUTH_STATES WHERE STATE_HASH = ? AND USER_ID = ?")) {
      const [stateHash, userId] = values;
      const row = this.states.get(stateHash);
      if (row?.user_id === userId) this.states.delete(stateHash);
      return { meta: { changes: row?.user_id === userId ? 1 : 0 } };
    }
    if (query.startsWith("DELETE FROM NR_RATE_LIMITS")) {
      const [userId, before] = values;
      for (const [key, row] of this.rates) if (row.user_id === userId && row.window_start < before) this.rates.delete(key);
      return { meta: { changes: 0 } };
    }
    if (query.startsWith("INSERT INTO NR_RATE_LIMITS")) {
      const [userId, windowStart] = values;
      const key = userId + ":" + windowStart;
      const row = this.rates.get(key) || { user_id: userId, window_start: windowStart, call_count: 0 };
      row.call_count += 1;
      this.rates.set(key, row);
      return { meta: { changes: 1 } };
    }
    if (query.startsWith("INSERT INTO NR_CONNECTIONS")) {
      const [user_id, encrypted_access_token, encrypted_refresh_token, access_expires_at, connected_at, region] = values;
      this.connections.set(user_id, { user_id, encrypted_access_token, encrypted_refresh_token, access_expires_at, connected_at, region });
      return { meta: { changes: 1 } };
    }
    throw new Error("Unexpected mock D1 run query: " + query);
  }

  async first(query, values) {
    if (query.includes("FROM NR_CONNECTIONS WHERE USER_ID = ?")) { const row = this.connections.get(values[0]); return row ? { ...row } : null; }
    if (query.includes("FROM NR_PREFERENCES WHERE USER_ID = ?")) return null;
    if (query.startsWith("SELECT USER_ID, ENCRYPTED_VERIFIER")) return this.states.get(values[0]) || null;
    if (query.startsWith("SELECT CALL_COUNT FROM NR_RATE_LIMITS")) {
      const [userId, windowStart] = values;
      return this.rates.get(userId + ":" + windowStart) || null;
    }
    throw new Error("Unexpected mock D1 first query: " + query);
  }

  async all(query, values) {
    if (query.includes("FROM NR_USAGE_CONSENTS WHERE USER_ID = ?")) {
      return { results: [...this.consents.values()].filter(row => row.user_id === values[0]).map(row => ({ ...row })) };
    }
    throw new Error("Unexpected mock D1 all query: " + query);
  }
}

const key = Buffer.alloc(32, 17).toString("base64url");
const user = "mock-user";
async function fixture(expires = 0) {
  const DB = new MemoryD1();
  const env = { DB, NEW_RELIC_TOKEN_ENCRYPTION_KEY: key };
  DB.connections.set(user, { user_id: user, encrypted_access_token: await encryptSecret("test-old-access", env), encrypted_refresh_token: await encryptSecret("test-old-refresh", env), access_expires_at: expires, connected_at: Date.now(), region: "us" });
  return env;
}
const originalFetch = globalThis.fetch;
let tests = 0;
async function test(name, fn) { try { await fn(); tests++; console.log("PASS", name); } finally { globalThis.fetch = originalFetch; } }
function validTokenResponse() { return Response.json({ access_token:"test-new-access", refresh_token:"test-new-refresh", expires_in:300, token_type:"Bearer" }); }
function mcpResponse(options, tools = []) {
  const p = JSON.parse(options.body);
  if (p.method === "notifications/initialized") return new Response(null, {status:202});
  return Response.json({ jsonrpc:"2.0", id:p.id, result: p.method === "tools/list" ? {tools} : p.method === "tools/call" ? {content:[{type:"text",text:"ok"}]} : {} });
}
await test("valid token does not refresh", async () => {
 const env=await fixture(Date.now()+120000); globalThis.fetch=()=>{throw Error("must not fetch")};
 const status=await getConnectionStatus(env,user); assert.equal(status.refreshError,null); assert.equal(status.requiresReauthentication,false); assert.equal(status.statusSource,"local_metadata");
});
await test("local status leaves an expired grant untouched", async () => {
 const env=await fixture(Date.now()-1000);const prior={...env.DB.connections.get(user)};let calls=0;
 globalThis.fetch=()=>{calls++;throw Error("local status must not contact New Relic")};
 const status=await getConnectionStatus(env,user);
 assert.equal(status.tokenRefreshDue,true);assert.equal(status.statusSource,"local_metadata");assert.equal(status.refreshError,null);
 assert.equal(status.providerReachable,null);assert.deepEqual(env.DB.connections.get(user),prior);assert.equal(calls,0);
});
await test("pre-expiry refresh rotates encrypted tokens atomically", async()=>{
 const env=await fixture(Date.now()+10000); globalThis.fetch=async(url,o)=>{assert.equal(o.redirect,"error");assert.equal(url,"https://oauth2.service.newrelic.com/oauth2/token");return validTokenResponse()};
 const s=await getConnectionStatus(env,user,{refreshIfNeeded:true});assert.equal(s.requiresReauthentication,false);assert.equal(s.refreshError,null);
 const row=env.DB.connections.get(user);assert.equal(await decryptSecret(row.encrypted_access_token,env),"test-new-access");assert.equal(await decryptSecret(row.encrypted_refresh_token,env),"test-new-refresh");assert.ok(row.access_expires_at>Date.now()+200000);
});
for(const [name,response,code,reauth] of [
 ["expired grant",()=>Response.json({error:"invalid_grant",error_description:"test-secret-never-return"},{status:400}),"oauth_invalid_grant",true],
 ["revoked grant",()=>Response.json({error:"access_denied"},{status:403}),"oauth_access_denied",true],
 ["invalid client",()=>Response.json({error:"invalid_client"},{status:401}),"oauth_configuration_error",false],
 ["server failure",()=>new Response("test-secret-never-return",{status:503}),"oauth_unavailable",false],
 ["malformed success",()=>Response.json({access_token:"",refresh_token:"test-secret-never-return"}),"invalid_token_response",false],
 ["bad expiry",()=>Response.json({access_token:"test-new-access",expires_in:-1}),"invalid_token_response",false],
 ["network ambiguity",()=>{throw Error("test-secret-never-return")},"oauth_network_error",false],
]) await test(name+" preserves credentials and classifies safely",async()=>{
 const env=await fixture();const prior={...env.DB.connections.get(user)};let calls=0;globalThis.fetch=async()=>{calls++;return response()};
 const s=await getConnectionStatus(env,user,{refreshIfNeeded:true});assert.equal(s.requiresReauthentication,reauth);assert.equal(s.refreshError.code,code);assert.deepEqual(env.DB.connections.get(user),prior);assert.equal(calls,1);assert.equal(JSON.stringify(s).includes("test-secret-never-return"),false);
});
await test("429 retries rejected request once",async()=>{
 const env=await fixture();let calls=0;globalThis.fetch=async()=>++calls===1?new Response(null,{status:429,headers:{"retry-after":"0"}}):validTokenResponse();
 assert.equal((await getConnectionStatus(env,user,{refreshIfNeeded:true})).refreshError,null);assert.equal(calls,2);
});
await test("429 long retry-after is not retried early",async()=>{
 const env=await fixture();let calls=0;globalThis.fetch=async()=>{calls++;return new Response(null,{status:429,headers:{"retry-after":"60"}})};
 assert.equal((await getConnectionStatus(env,user,{refreshIfNeeded:true})).refreshError.code,"oauth_rate_limited");assert.equal(calls,1);
});
await test("multi-instance requests share D1 lease",async()=>{
 const env=await fixture();let calls=0;globalThis.fetch=async()=>{calls++;await new Promise(r=>setTimeout(r,50));return validTokenResponse()};
 const statuses=await Promise.all(Array.from({length:4},()=>getConnectionStatus({...env},user,{refreshIfNeeded:true})));assert.equal(calls,1);assert.ok(statuses.every(s=>s.refreshError===null));assert.equal(env.DB.locks.size,0);
});
await test("different users do not share credentials",async()=>{
 const env=await fixture();globalThis.fetch=()=>{throw Error("must not fetch")};assert.equal((await getConnectionStatus(env,"other-user")).connected,false);
});
await test("key mismatch is configuration failure not revoked grant",async()=>{
 const env=await fixture();env.NEW_RELIC_TOKEN_ENCRYPTION_KEY=Buffer.alloc(32,18).toString("base64url");globalThis.fetch=()=>{throw Error("must not fetch")};
 const s=await getConnectionStatus(env,user,{refreshIfNeeded:true});assert.equal(s.requiresReauthentication,false);assert.equal(s.refreshError.code,"credential_storage_error");
});
await test("CAS conflict never overwrites replacement or demands reauth",async()=>{
 const env=await fixture();const replacement=await encryptSecret("replacement-refresh",env);globalThis.fetch=async()=>{env.DB.connections.get(user).encrypted_refresh_token=replacement;return validTokenResponse()};
 const s=await getConnectionStatus(env,user,{refreshIfNeeded:true});assert.equal(s.refreshError.code,"connection_changed");assert.equal(s.requiresReauthentication,false);assert.equal(env.DB.connections.get(user).encrypted_refresh_token,replacement);
});
await test("401 refreshes once and rebuilds session",async()=>{
 const env=await fixture(Date.now()+120000);let refreshes=0,initializes=0;globalThis.fetch=async(url,o)=>{if(url.includes("oauth2/token")){refreshes++;return validTokenResponse()};const p=JSON.parse(o.body);if(p.method==="initialize"&&++initializes===1)return new Response(null,{status:401});return mcpResponse(o)};
 assert.equal(await withNewRelicSession(env,user,()=>"read-ok"),"read-ok");assert.equal(refreshes,1);assert.equal(initializes,2);
});
await test("second 401 after refresh requires reconnect",async()=>{
 const env=await fixture(Date.now()+120000);let refreshes=0,initializes=0;
 globalThis.fetch=async(url,o)=>{
  if(String(url).includes("oauth2/token")){refreshes++;return validTokenResponse()}
  const p=JSON.parse(o.body);
  if(p.method==="initialize"){initializes++;return new Response(null,{status:401})}
  throw new Error("unexpected method");
 };
 await assert.rejects(()=>withNewRelicSession(env,user,()=>"unreachable"),e=>e.code==="access_token_rejected_after_refresh"&&e.requiresReauthentication===true&&e.refreshable===false);
 assert.equal(refreshes,1);assert.equal(initializes,2);
});
await test("Core Compute legacy reads require explicit per-user consent",async()=>{
 const env={...(await fixture(Date.now()+120000)),NEW_RELIC_ENABLE_METERED_READS:"true"};let toolCalls=0;
 globalThis.fetch=async(_url,o)=>{
  const p=JSON.parse(o.body);
  if(p.method==="notifications/initialized")return new Response(null,{status:202});
  if(p.method==="initialize")return Response.json({jsonrpc:"2.0",id:p.id,result:{}});
  if(p.method==="tools/list")return Response.json({jsonrpc:"2.0",id:p.id,result:{tools:[{name:"list_available_new_relic_accounts",inputSchema:{type:"object",properties:{},additionalProperties:false}}]}});
  if(p.method==="tools/call"){toolCalls++;return Response.json({jsonrpc:"2.0",id:p.id,result:{content:[{type:"text",text:"accounts"}]}})}
  throw new Error("unexpected method");
 };
 await assert.rejects(()=>withNewRelicSession(env,user,session=>callNewRelicTool(session,"list_available_new_relic_accounts",{})),e=>e.code==="usage_consent_required");
 assert.equal(toolCalls,0,"a disabled read must not reach tools/call");
});
await test("metered legacy reads run only after explicit opt-in",async()=>{
 const env=await fixture(Date.now()+120000);await updateUsageConsents(env,user,{core_compute:true,advanced_compute:false,preview:false});let toolCalls=0;
 globalThis.fetch=async(_url,o)=>{
  const p=JSON.parse(o.body);
  if(p.method==="notifications/initialized")return new Response(null,{status:202});
  if(p.method==="initialize")return Response.json({jsonrpc:"2.0",id:p.id,result:{}});
  if(p.method==="tools/list")return Response.json({jsonrpc:"2.0",id:p.id,result:{tools:[{name:"list_available_new_relic_accounts",inputSchema:{type:"object",properties:{},additionalProperties:false}}]}});
  if(p.method==="tools/call"){toolCalls++;return Response.json({jsonrpc:"2.0",id:p.id,result:{content:[{type:"text",text:"accounts"}]}})}
  throw new Error("unexpected method");
 };
 await withNewRelicSession(env,user,session=>callNewRelicTool(session,"list_available_new_relic_accounts",{}));
 assert.equal(toolCalls,1);
});
await test("revocation during MCP discovery blocks an unsent legacy read",async()=>{
 const env=await fixture(Date.now()+120000);await updateUsageConsents(env,user,{core_compute:true,advanced_compute:false,preview:false});let toolCalls=0;
 globalThis.fetch=async(_url,o)=>{
  const p=JSON.parse(o.body);
  if(p.method==="notifications/initialized")return new Response(null,{status:202});
  if(p.method==="initialize")return Response.json({jsonrpc:"2.0",id:p.id,result:{}});
  if(p.method==="tools/list"){
   await updateUsageConsents(env,user,{core_compute:false,advanced_compute:false,preview:false});
   return Response.json({jsonrpc:"2.0",id:p.id,result:{tools:[{name:"list_available_new_relic_accounts",inputSchema:{type:"object",properties:{},additionalProperties:false}}]}});
  }
  if(p.method==="tools/call"){toolCalls++;return Response.json({jsonrpc:"2.0",id:p.id,result:{content:[{type:"text",text:"accounts"}]}})}
  throw new Error("unexpected method");
 };
 await assert.rejects(()=>withNewRelicSession(env,user,session=>callNewRelicTool(session,"list_available_new_relic_accounts",{})),e=>e.code==="usage_consent_required");
 assert.equal(toolCalls,0,"revoked consent is re-read immediately before the provider call");
});
await test("expiry during MCP discovery blocks an unsent legacy read",async()=>{
 const env=await fixture(Date.now()+120000);await updateUsageConsents(env,user,{core_compute:true,advanced_compute:false,preview:false});let toolCalls=0;
 globalThis.fetch=async(_url,o)=>{
  const p=JSON.parse(o.body);
  if(p.method==="notifications/initialized")return new Response(null,{status:202});
  if(p.method==="initialize")return Response.json({jsonrpc:"2.0",id:p.id,result:{}});
  if(p.method==="tools/list"){
   const row=env.DB.consents.get(user+":core_compute");row.expires_at=Date.now()-1;
   return Response.json({jsonrpc:"2.0",id:p.id,result:{tools:[{name:"list_available_new_relic_accounts",inputSchema:{type:"object",properties:{},additionalProperties:false}}]}});
  }
  if(p.method==="tools/call"){toolCalls++;return Response.json({jsonrpc:"2.0",id:p.id,result:{content:[{type:"text",text:"accounts"}]}})}
  throw new Error("unexpected method");
 };
 await assert.rejects(()=>withNewRelicSession(env,user,session=>callNewRelicTool(session,"list_available_new_relic_accounts",{})),e=>e.code==="usage_consent_required");
 assert.equal(toolCalls,0,"expired consent is not accepted from a stale session snapshot");
});
await test("revocation between legacy reads blocks the next call",async()=>{
 const env=await fixture(Date.now()+120000);await updateUsageConsents(env,user,{core_compute:true,advanced_compute:false,preview:false});let toolCalls=0;
 globalThis.fetch=async(_url,o)=>{
  const p=JSON.parse(o.body);
  if(p.method==="notifications/initialized")return new Response(null,{status:202});
  if(p.method==="initialize")return Response.json({jsonrpc:"2.0",id:p.id,result:{}});
  if(p.method==="tools/list")return Response.json({jsonrpc:"2.0",id:p.id,result:{tools:[
   {name:"list_available_new_relic_accounts",inputSchema:{type:"object",properties:{},additionalProperties:false}},
   {name:"execute_nrql_query",inputSchema:{type:"object",properties:{},additionalProperties:false}},
  ]}});
  if(p.method==="tools/call"){
   toolCalls++;
   await updateUsageConsents(env,user,{core_compute:false,advanced_compute:false,preview:false});
   return Response.json({jsonrpc:"2.0",id:p.id,result:{content:[{type:"text",text:"ok"}]}});
  }
  throw new Error("unexpected method");
 };
 await assert.rejects(()=>withNewRelicSession(env,user,async session=>{
  await callNewRelicTool(session,"list_available_new_relic_accounts",{});
  await callNewRelicTool(session,"execute_nrql_query",{});
 }),e=>e.code==="usage_consent_required");
 assert.equal(toolCalls,1,"a multi-step investigation stops at the first read after revocation");
});
await test("legacy AI tools require Advanced Compute opt-in",async()=>{
 const env={...(await fixture(Date.now()+120000)),NEW_RELIC_ENABLE_ADVANCED_COMPUTE:"true"};
 globalThis.fetch=async(_url,o)=>mcpResponse(o,[{name:"analyze_deployment_impact",inputSchema:{type:"object",properties:{},additionalProperties:false}}]);
 await assert.rejects(()=>withNewRelicSession(env,user,s=>callNewRelicTool(s,"analyze_deployment_impact",{})),e=>e.code==="advanced_compute_consent_required");
 await updateUsageConsents(env,user,{core_compute:false,advanced_compute:true,preview:false});
 await withNewRelicSession(env,user,s=>callNewRelicTool(s,"analyze_deployment_impact",{}));
});
await test("unclassified legacy tools remain blocked after Core opt-in",async()=>{
 const env=await fixture(Date.now()+120000);
 await updateUsageConsents(env,user,{core_compute:true,advanced_compute:false,preview:false});
 globalThis.fetch=async(_url,o)=>mcpResponse(o,[{name:"future_unknown_tool",inputSchema:{type:"object",properties:{},additionalProperties:false}}]);
 await assert.rejects(()=>withNewRelicSession(env,user,s=>callNewRelicTool(s,"future_unknown_tool",{})),e=>e.code==="legacy_tool_billing_unverified");
});
await test("403 does not refresh and retry request",async()=>{
 const env=await fixture(Date.now()+120000);let calls=0;globalThis.fetch=async()=>{calls++;return new Response(null,{status:403})};
 await assert.rejects(()=>withNewRelicSession(env,user,()=>null),e=>e.code==="permission_denied"&&!e.requiresReauthentication);assert.equal(calls,1);
});
await test("provider error text cannot trigger auth refresh or leak",async()=>{
 const env=await fixture(Date.now()+120000);let calls=0;globalThis.fetch=async(_url,o)=>{calls++;const p=JSON.parse(o.body);return Response.json({jsonrpc:"2.0",id:p.id,error:{code:-32001,message:"token unauthorized test-secret-never-return"}})};
 await assert.rejects(()=>withNewRelicSession(env,user,()=>null),e=>!e.requiresReauthentication&&!e.message.includes("test-secret"));assert.equal(calls,1);
});
await test("response id mismatch fails closed",async()=>{
 const env=await fixture(Date.now()+120000);globalThis.fetch=async()=>Response.json({jsonrpc:"2.0",id:999,result:{}});
 await assert.rejects(()=>withNewRelicSession(env,user,()=>null),e=>e.code==="invalid_mcp_response");
});
await test("raw exact arguments and no restrictive discovery tags",async()=>{
 const env=await fixture(Date.now()+120000);await updateUsageConsents(env,user,{core_compute:true,advanced_compute:false,preview:false});let args;globalThis.fetch=async(_url,o)=>{assert.equal(new Headers(o.headers).get("include-tags"),null);const p=JSON.parse(o.body);if(p.method==="tools/call")args=p.params.arguments;return mcpResponse(o,[{name:"get_entity",inputSchema:{type:"object"}}])};
 await withNewRelicSession(env,user,s=>callNewRelicRawTool(s,"get_entity",{entity_guid:"fixture"},{operation:"read",billing:"core_compute",preview:false}));assert.deepEqual(args,{entity_guid:"fixture"});
});
await test("raw transport rejects missing billing policy before tools/call",async()=>{
 const env=await fixture(Date.now()+120000);let toolCalls=0;
 globalThis.fetch=async(_url,o)=>{const p=JSON.parse(o.body);if(p.method==="tools/call")toolCalls++;return mcpResponse(o,[{name:"get_entity",inputSchema:{type:"object"}}])};
 await assert.rejects(()=>withNewRelicSession(env,user,s=>callNewRelicRawTool(s,"get_entity",{entity_guid:"fixture"})),e=>e.code==="legacy_tool_billing_unverified");
 assert.equal(toolCalls,0,"the internal raw transport requires an explicit reviewed policy");
});
await test("transient OAuth failure recovers on later request",async()=>{
 const env=await fixture();globalThis.fetch=async()=>new Response(null,{status:503});
 assert.equal((await getConnectionStatus(env,user,{refreshIfNeeded:true})).refreshError.code,"oauth_unavailable");globalThis.fetch=async()=>validTokenResponse();
 assert.equal((await getConnectionStatus(env,user,{refreshIfNeeded:true})).refreshError,null);
});
await test("refresh response without rotation preserves refresh secret",async()=>{
 const env=await fixture();globalThis.fetch=async()=>Response.json({access_token:"test-new-access",expires_in:300});
 assert.equal((await getConnectionStatus(env,user,{refreshIfNeeded:true})).refreshError,null);assert.equal(await decryptSecret(env.DB.connections.get(user).encrypted_refresh_token,env),"test-old-refresh");
});
await test("mutating callbacks cannot be replayed on 401",async()=>{
 const env=await fixture(Date.now()+120000);let calls=0;globalThis.fetch=async()=>{calls++;return new Response(null,{status:401})};
 await assert.rejects(()=>withNewRelicSession(env,user,()=>null,{readOnly:false}),e=>e.code==="access_token_rejected");assert.equal(calls,1);
});
console.log(`${tests} OAuth/transport v0.4.0 mock tests passed; no live provider validation performed`);
