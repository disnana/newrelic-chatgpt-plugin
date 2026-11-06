// Fail-closed policy for the schema-driven official MCP adapter.
// Provider descriptions and readOnlyHint are data, never authorization.
export class McpPolicyError extends Error {
  constructor(code, message) { super(message); this.name = 'McpPolicyError'; this.code = code; }
}
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const forbidden = new Set(['__proto__', 'prototype', 'constructor']);
const supported = new Set(['type','properties','required','additionalProperties','items','enum','const','anyOf','oneOf','allOf','minimum','maximum','exclusiveMinimum','exclusiveMaximum','minLength','maxLength','minItems','maxItems','uniqueItems','description','title','default','$schema','examples','deprecated']);
export function canonicalJson(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (plain(value)) return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
  return JSON.stringify(value);
}
export async function schemaFingerprint(tool) {
  const data = new TextEncoder().encode(canonicalJson({name:tool.name,inputSchema:tool.inputSchema,outputSchema:tool.outputSchema ?? null,annotations:tool.annotations ?? null,metadata:tool._meta ?? null}));
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', data))].map(v=>v.toString(16).padStart(2,'0')).join('');
}
function fail(code='invalid_arguments') { throw new McpPolicyError(code, 'MCP schema / policy validation failed: ' + code); }
export function checkSchema(schema, depth=0) {
  if (depth > 12 || !plain(schema) || Object.keys(schema).some(k=>!supported.has(k))) fail('unsupported_schema');
  for (const key of ['minimum','maximum','exclusiveMinimum','exclusiveMaximum']) if(schema[key]!==undefined && (typeof schema[key]!=='number'||!Number.isFinite(schema[key]))) fail('unsupported_schema');
  for (const key of ['minLength','maxLength','minItems','maxItems']) if(schema[key]!==undefined && (!Number.isSafeInteger(schema[key])||schema[key]<0)) fail('unsupported_schema');
  if(schema.uniqueItems!==undefined && typeof schema.uniqueItems!=='boolean') fail('unsupported_schema');
  if(schema.enum!==undefined && (!Array.isArray(schema.enum)||!schema.enum.length||schema.enum.length>100)) fail('unsupported_schema');
  if(schema.required && new Set(schema.required).size!==schema.required.length) fail('unsupported_schema');
  if (schema.type !== undefined && !['object','array','string','integer','number','boolean','null'].includes(schema.type)) fail('unsupported_schema');
  if (schema.properties) {
    if (!plain(schema.properties) || Object.keys(schema.properties).length > 100) fail('unsupported_schema');
    for (const [k,v] of Object.entries(schema.properties)) { if (forbidden.has(k)) fail('unsafe_schema'); checkSchema(v, depth+1); }
  }
  if (schema.required && (!Array.isArray(schema.required) || schema.required.some(k=>typeof k!=='string'||forbidden.has(k)))) fail('unsafe_schema');
  if (schema.additionalProperties !== undefined && typeof schema.additionalProperties !== 'boolean') checkSchema(schema.additionalProperties,depth+1);
  if (schema.items) checkSchema(schema.items,depth+1);
  for (const key of ['anyOf','oneOf','allOf']) if (schema[key]) {
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
    if(schema.uniqueItems && new Set(value.map(canonicalJson)).size!==value.length) fail();
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
        || !['read','write','destructive'].includes(p.operation) || !['free','billable','unknown'].includes(p.billing)
        || typeof p.preview!=='boolean' || !['account','identity'].includes(p.scope)) fail('invalid_policy_configuration');
      if(p.scope==='account' && (!Array.isArray(p.accountFields)||!p.accountFields.length||p.accountFields.some(k=>!/^account_?ids?$/i.test(k)))) fail('invalid_policy_configuration');
    }
    return policies;
  } catch { fail('invalid_policy_configuration'); }
}
export async function capabilityCatalog(tools,env) {
  const policies=readPolicies(env);
  const names=new Set();
  const rows=[];
  for(const tool of tools) {
    if(!plain(tool)||typeof tool.name!=='string'||!/^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(tool.name)||names.has(tool.name)) fail('invalid_catalog');
    names.add(tool.name);
    const fingerprint=await schemaFingerprint(tool), policy=policies[tool.name];
    let reason=null;
    try { checkSchema(tool.inputSchema); if(tool.outputSchema) checkSchema(tool.outputSchema); } catch { reason='unsupported_schema'; }
    if(!policy) reason='policy_not_reviewed';
    else if(policy.schemaHash!==fingerprint) reason='schema_changed_review_required';
    else if(policy.operation!=='read') reason='operation_approval_not_implemented';
    else if(policy.billing!=='free') reason=policy.billing==='billable'?'billable_disabled':'billing_unverified';
    else if(policy.preview && env.NEW_RELIC_ENABLE_PREVIEW!=='true') reason='preview_opt_in_required';
    rows.push({name:tool.name,description:String(tool.description??'').slice(0,1000),inputSchema:tool.inputSchema,
      schemaHash:fingerprint,available:reason===null,reason,operation:policy?.operation??'unknown',
      billing:policy?.billing??'unknown',preview:policy?.preview??null,scope:policy?.scope??'unknown'});
  }
  return rows;
}
export async function authorizeReadTool(session, env, name, args, accountId, allowedAccountIds) {
  if(typeof name!=='string'||!plain(args)) fail();
  const row=(await capabilityCatalog(session.tools,env)).find(t=>t.name===name);
  if(!row) fail('tool_not_available');
  if(!row.available) fail(row.reason);
  const policy=readPolicies(env)[name];
  const definition=session.tools.find(t=>t.name===name);
  validateSchema(args,definition.inputSchema);
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
