// Fail-closed policy for the schema-driven official MCP adapter.
// Provider descriptions and readOnlyHint are data, never authorization.
export class McpPolicyError extends Error {
  constructor(code, message) { super(message); this.name = 'McpPolicyError'; this.code = code; }
}
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const forbidden = new Set(['__proto__', 'prototype', 'constructor']);
const supported = new Set(['type','properties','required','additionalProperties','items','enum','const','anyOf','oneOf','allOf','minimum','maximum','exclusiveMinimum','exclusiveMaximum','minLength','maxLength','minItems','maxItems','uniqueItems','description','title','default','$schema','examples','deprecated']);
const MAX_CANONICAL_DEPTH = 32;
const MAX_CANONICAL_NODES = 25000;
const MAX_CANONICAL_BYTES = 1024 * 1024;
function appendCanonicalToken(token, state) {
  state.bytes += new TextEncoder().encode(token).byteLength;
  if (state.bytes > MAX_CANONICAL_BYTES) throw new McpPolicyError('unsupported_schema', 'MCP schema / policy validation failed: canonical_size_limit');
  return token;
}
export function canonicalJson(value, depth = 0, state = { nodes: 0, bytes: 0 }) {
  state.nodes += 1;
  if (depth > MAX_CANONICAL_DEPTH || state.nodes > MAX_CANONICAL_NODES) {
    throw new McpPolicyError('unsupported_schema', 'MCP schema / policy validation failed: canonical_complexity_limit');
  }
  if (Array.isArray(value)) {
    let result = appendCanonicalToken('[', state);
    value.forEach((item, index) => {
      if (index) result += appendCanonicalToken(',', state);
      result += canonicalJson(item, depth + 1, state);
    });
    return result + appendCanonicalToken(']', state);
  }
  if (plain(value)) {
    let result = appendCanonicalToken('{', state);
    Object.keys(value).sort().forEach((key, index) => {
      if (index) result += appendCanonicalToken(',', state);
      result += appendCanonicalToken(JSON.stringify(key), state) + appendCanonicalToken(':', state)
        + canonicalJson(value[key], depth + 1, state);
    });
    return result + appendCanonicalToken('}', state);
  }
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new McpPolicyError('unsupported_schema', 'MCP schema / policy validation failed: unsupported_json_value');
  return appendCanonicalToken(serialized, state);
}
export async function schemaFingerprint(tool) {
  const data = new TextEncoder().encode(canonicalJson({name:tool.name,inputSchema:tool.inputSchema,outputSchema:tool.outputSchema ?? null,annotations:tool.annotations ?? null,metadata:tool._meta ?? null}));
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', data))].map(v=>v.toString(16).padStart(2,'0')).join('');
}
/** @returns {never} */
function fail(code='invalid_arguments') { throw new McpPolicyError(code, 'MCP schema / policy validation failed: ' + code); }
export function checkSchema(schema, depth=0) {
  if (depth > 12 || !plain(schema) || Object.keys(schema).some(k=>!supported.has(k))) fail('unsupported_schema');
  for (const key of ['minimum','maximum','exclusiveMinimum','exclusiveMaximum']) if(schema[key]!==undefined && (typeof schema[key]!=='number'||!Number.isFinite(schema[key]))) fail('unsupported_schema');
  for (const key of ['minLength','maxLength','minItems','maxItems']) if(schema[key]!==undefined && (!Number.isSafeInteger(schema[key])||schema[key]<0)) fail('unsupported_schema');
  if(schema.uniqueItems!==undefined && typeof schema.uniqueItems!=='boolean') fail('unsupported_schema');
  if(schema.enum!==undefined && (!Array.isArray(schema.enum)||!schema.enum.length||schema.enum.length>100)) fail('unsupported_schema');
  if (schema.type !== undefined && !['object','array','string','integer','number','boolean','null'].includes(schema.type)) fail('unsupported_schema');
  for (const key of ['description','title']) if(schema[key]!==undefined && typeof schema[key]!=='string') fail('unsupported_schema');
  if (Object.hasOwn(schema,'properties')) {
    if (!plain(schema.properties) || Object.keys(schema.properties).length > 100) fail('unsupported_schema');
    for (const [k,v] of Object.entries(schema.properties)) { if (forbidden.has(k)) fail('unsafe_schema'); checkSchema(v, depth+1); }
  }
  if (Object.hasOwn(schema,'required')) {
    if (!Array.isArray(schema.required) || schema.required.length>100
      || schema.required.some(k=>typeof k!=='string'||forbidden.has(k))
      || new Set(schema.required).size!==schema.required.length) fail('unsafe_schema');
  }
  if (schema.additionalProperties !== undefined && typeof schema.additionalProperties !== 'boolean') checkSchema(schema.additionalProperties,depth+1);
  if (Object.hasOwn(schema,'items')) checkSchema(schema.items,depth+1);
  for (const key of ['anyOf','oneOf','allOf']) if (Object.hasOwn(schema,key)) {
    if (!Array.isArray(schema[key]) || !schema[key].length || schema[key].length>10) fail('unsupported_schema');
    for(const child of schema[key]) checkSchema(child,depth+1);
  }
}
export function validateSchema(value, schema, depth=0) {
  if (depth===0) checkSchema(schema);
  if (depth>16) fail();
  if (schema.enum && !schema.enum.some(v=>canonicalJson(v)===canonicalJson(value))) fail();
  if (Object.hasOwn(schema,'const') && canonicalJson(schema.const)!==canonicalJson(value)) fail();
  for(const key of ['anyOf','oneOf']) if(schema[key]) {
    let count=0;
    for(const child of schema[key]) { try { validateSchema(value,child,depth+1); count++; } catch {} }
    if(key==='anyOf' ? count===0 : count!==1) fail();
  }
  for(const child of schema.allOf || []) validateSchema(value,child,depth+1);
  const type=schema.type;
  if(type==='null' && value!==null || type==='object' && !plain(value) || type==='array' && !Array.isArray(value)
    || type==='string' && typeof value!=='string' || type==='boolean' && typeof value!=='boolean'
    || type==='integer' && !Number.isSafeInteger(value) || type==='number' && (typeof value!=='number'||!Number.isFinite(value))) fail();
  if(typeof value==='string' && (value.length>(schema.maxLength??8192) || value.length<(schema.minLength??0))) fail();
  if(typeof value==='number' && (value<(schema.minimum??-Infinity) || value>(schema.maximum??Infinity)
    || value<=(schema.exclusiveMinimum??-Infinity) || value>=(schema.exclusiveMaximum??Infinity))) fail();
  if(Array.isArray(value)) {
    if(value.length>(schema.maxItems??100)||value.length<(schema.minItems??0)) fail();
    if(schema.uniqueItems && new Set(value.map(item=>canonicalJson(item))).size!==value.length) fail();
    for(const child of value) validateSchema(child,schema.items??{},depth+1);
  }
  if(plain(value)) {
    if(Object.keys(value).length>100) fail();
    for(const key of schema.required??[]) if(!Object.hasOwn(value,key)) fail();
    for(const [k,v] of Object.entries(value)) {
      if(forbidden.has(k)) fail();
      if(Object.hasOwn(schema.properties??{},k)) validateSchema(v,schema.properties[k],depth+1);
      else if(schema.additionalProperties===false) fail();
      else validateSchema(v,plain(schema.additionalProperties)?schema.additionalProperties:{},depth+1);
    }
  }
}
export function readPolicies(env) {
  if(!env?.NEW_RELIC_MCP_POLICIES) return {};
  try {
    const policies=JSON.parse(env.NEW_RELIC_MCP_POLICIES);
    if(!plain(policies)||Object.keys(policies).length>500) fail('invalid_policy_configuration');
    for(const [name,p] of Object.entries(policies)) {
      if(!/^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(name)||!plain(p)||!/^[a-f0-9]{64}$/.test(p.schemaHash)
        || !['read','write','destructive'].includes(p.operation) || !['core_compute','advanced_compute','unknown'].includes(p.billing)
        || typeof p.preview!=='boolean' || !['account','identity'].includes(p.scope)) fail('invalid_policy_configuration');
      if(p.scope==='account' && (!Array.isArray(p.accountFields)||!p.accountFields.length||p.accountFields.some(k=>!/^account_?ids?$/i.test(k)))) fail('invalid_policy_configuration');
    }
    return policies;
  } catch { fail('invalid_policy_configuration'); }
}
export async function capabilityCatalog(tools,env,usageConsents={}) {
  const policies=readPolicies(env);
  const names=new Set();
  const rows=[];
  for(const tool of tools) {
    if(!plain(tool)||typeof tool.name!=='string'||!/^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(tool.name)||names.has(tool.name)) fail('invalid_catalog');
    names.add(tool.name);
    const policy=policies[tool.name];
    let reason=null;
    let fingerprint=null;
    try {
      // Keep a stable fingerprint even when the schema uses a keyword that
      // this adapter does not support. The catalog can then show the actual
      // schema for review without making it executable.
      fingerprint=await schemaFingerprint(tool);
      checkSchema(tool.inputSchema);
      if(tool.outputSchema) checkSchema(tool.outputSchema);
    } catch { reason='unsupported_schema'; }
    if(!reason) {
      if(!policy) reason='policy_not_reviewed';
      else if(policy.schemaHash!==fingerprint) reason='schema_changed_review_required';
      else if(policy.operation!=='read') reason='operation_approval_not_implemented';
      else if(policy.billing==='unknown') reason='billing_unverified';
      else if(policy.billing==='core_compute' && usageConsents.core_compute!==true) reason='usage_consent_required';
      else if(policy.billing==='advanced_compute' && usageConsents.advanced_compute!==true) reason='advanced_compute_consent_required';
      else if(policy.preview && usageConsents.preview!==true) reason='preview_consent_required';
    }
    rows.push({name:tool.name,description:String(tool.description??'').slice(0,1000),inputSchema:tool.inputSchema,
      schemaHash:fingerprint,available:reason===null,reason,operation:policy?.operation??'unknown',
      billing:policy?.billing??'unknown',preview:policy?.preview??null,scope:policy?.scope??'unknown'});
  }
  return rows;
}
export async function reviewReadTool(session, env, name, args, usageConsents={}) {
  if(typeof name!=='string'||!plain(args)) fail();
  const row=(await capabilityCatalog(session.tools,env,usageConsents)).find(t=>t.name===name);
  if(!row) fail('tool_not_available');
  if(!row.available) fail(row.reason ?? 'tool_not_available');
  const policy=readPolicies(env)[name];
  const definition=session.tools.find(t=>t.name===name);
  validateSchema(args,definition.inputSchema);
  return {definition,policy};
}
export async function authorizeReadTool(session, env, name, args, accountId, allowedAccountIds, usageConsents={}) {
  const {definition,policy}=await reviewReadTool(session,env,name,args,usageConsents);
  if(policy.scope==='account') {
    if(!accountId || !allowedAccountIds.includes(String(accountId))) fail('account_not_authorized');
    for(const key of policy.accountFields) {
      const value=args[key];
      if(value===undefined || (Array.isArray(value)?value.length!==1||String(value[0])!==String(accountId):String(value)!==String(accountId))) fail('account_mismatch');
    }
  }
  return definition;
}
export function validateToolResult(result,definition) {
  if(!plain(result)||!Array.isArray(result.content)||result.content.length>100) fail('invalid_response');
  for(const item of result.content) {
    // Do not relay resource links, embedded resources, images, or arbitrary remote fetch targets.
    if(!plain(item)||item.type!=='text'||typeof item.text!=='string') fail('unsupported_response_content');
  }
  if(definition.outputSchema) validateSchema(result.structuredContent,definition.outputSchema);
  const safe = {content: result.content.map(item => ({type: 'text', text: item.text}))};
  if(definition.outputSchema) safe.structuredContent = result.structuredContent;
  return safe;
}
