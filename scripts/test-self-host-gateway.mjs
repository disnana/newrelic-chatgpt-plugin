import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { createSelfHostGateway, importGatewaySigningKey } from '../examples/self-host-gateway/gateway.mjs';

globalThis.crypto ||= webcrypto;
globalThis.fetch = async () => { throw new Error('Live network calls are disabled in this test.'); };

const externalOrigin = 'https://monitor.example.test';
const issuer = 'https://auth.example.test/';
const audience = 'newrelic-chatgpt-mcp';
const owner = 'synthetic-owner';
const member = 'synthetic-member';
const time = 1_800_000_000_000;
const keys = await crypto.subtle.generateKey({
  name: 'RSASSA-PKCS1-v1_5',
  modulusLength: 2048,
  publicExponent: Uint8Array.of(1, 0, 1),
  hash: 'SHA-256',
}, true, ['sign', 'verify']);
const workerPath = resolve(fileURLToPath(new URL('..', import.meta.url)), 'dist/server/index.js');
const newRelicWorker = (await import(pathToFileURL(workerPath).href + '?gateway-test=' + Date.now())).default;
const pinnedPublicKey = Buffer.from(await crypto.subtle.exportKey('spki', keys.publicKey)).toString('base64url');
const privateKeyBytes = await crypto.subtle.exportKey('pkcs8', keys.privateKey);
const importedSigningKey = await importGatewaySigningKey(Buffer.from(privateKeyBytes).toString('base64url'));
assert.equal(importedSigningKey.type, 'private');
assert.deepEqual(importedSigningKey.usages, ['sign']);
await assert.rejects(() => importGatewaySigningKey('not-a-private-key'), /could not be imported/);

function decode(segment) {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

const calls = { browserAuth: [], mcpAuth: [], csrf: [], backend: [] };
let browserPrincipal = { subject: owner, csrfContext: 'synthetic-session-context' };
let mcpPrincipal = { subject: owner };
let csrfResult = true;
let browserAuthThrows = false;
let mcpAuthThrows = false;
let csrfThrows = false;
let backendResult = async () => Response.json({ ok: true });

const backend = {
  async fetch(request) {
    calls.backend.push(request);
    return backendResult(request);
  },
};

const gateway = createSelfHostGateway({
  externalOrigin,
  issuer,
  audience,
  keyId: 'gateway-key-1',
  allowedSubjects: [owner, member],
  signingKey: keys.privateKey,
  authenticateBrowser: async (input) => {
    calls.browserAuth.push(input);
    if (browserAuthThrows) throw new Error('synthetic-private-auth-error');
    return browserPrincipal;
  },
  authenticateMcp: async (input) => {
    calls.mcpAuth.push(input);
    if (mcpAuthThrows) throw new Error('synthetic-private-auth-error');
    return mcpPrincipal;
  },
  verifyBrowserCsrf: async (input) => {
    calls.csrf.push(input);
    if (csrfThrows) throw new Error('synthetic-private-csrf-error');
    return csrfResult;
  },
  backend,
  now: () => time,
});

function browserRequest(path, init = {}) {
  const headers = new Headers(init.headers || {});
  if (!headers.has('origin')) headers.set('origin', externalOrigin);
  if (!headers.has('sec-fetch-site')) headers.set('sec-fetch-site', 'same-origin');
  return new Request(externalOrigin + path, { ...init, headers });
}

function resetState() {
  calls.browserAuth.length = 0;
  calls.mcpAuth.length = 0;
  calls.csrf.length = 0;
  calls.backend.length = 0;
  browserPrincipal = { subject: owner, csrfContext: 'synthetic-session-context' };
  mcpPrincipal = { subject: owner };
  csrfResult = true;
  browserAuthThrows = false;
  mcpAuthThrows = false;
  csrfThrows = false;
  backendResult = async () => Response.json({ ok: true });
}

async function forwardedToken(request) {
  const authorization = request.headers.get('authorization');
  assert.match(authorization || '', /^Bearer [A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9_-]+$/);
  const token = authorization.slice('Bearer '.length);
  const [encodedHeader, encodedClaims, encodedSignature] = token.split('.');
  const header = decode(encodedHeader);
  const claims = decode(encodedClaims);
  const valid = await crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    keys.publicKey,
    Buffer.from(encodedSignature, 'base64url'),
    new TextEncoder().encode(encodedHeader + '.' + encodedClaims),
  );
  assert.equal(valid, true, 'forwarded assertion verifies against the pinned public key');
  assert.deepEqual(header, { alg: 'RS256', typ: 'JWT', kid: 'gateway-key-1' });
  assert.equal(claims.iss, issuer);
  assert.equal(claims.aud, audience);
  assert.equal(claims.sub, owner);
  assert.equal(claims.channel, new URL(request.url).pathname === '/mcp' ? 'mcp' : 'browser');
  assert.equal(claims.iat, Math.floor(time / 1000));
  assert.equal(claims.exp - claims.iat, 60, 'assertion lifetime is 60 seconds');
  assert.match(claims.jti, /^[A-Za-z0-9_-]{20,32}$/);
  if (new URL(request.url).pathname.startsWith('/api/operation-approvals/')) {
    assert.equal(claims.sid, browserPrincipal.sessionId, 'approval assertion binds the stable browser session');
  } else {
    assert.equal(claims.sid, undefined, 'ordinary assertions do not carry a stable session binding');
  }
  return token;
}

// Configuration errors fail closed before a handler can be served.
assert.throws(() => createSelfHostGateway({}), /trusted browser\/MCP auth adapters/);
assert.throws(() => createSelfHostGateway({
  externalOrigin, issuer, audience, keyId: 'k', allowedSubjects: [owner],
  signingKey: keys.publicKey, authenticateBrowser: async () => ({ subject: owner }),
  authenticateMcp: async () => ({ subject: owner }), verifyBrowserCsrf: async () => true, backend,
}), /trusted browser\/MCP auth adapters/);
const weakKeys = await crypto.subtle.generateKey({
  name: 'RSASSA-PKCS1-v1_5', modulusLength: 1024, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256',
}, true, ['sign', 'verify']);
assert.throws(() => createSelfHostGateway({
  externalOrigin, issuer, audience, keyId: 'k', allowedSubjects: [owner],
  signingKey: weakKeys.privateKey, authenticateBrowser: async () => ({ subject: owner }),
  authenticateMcp: async () => ({ subject: owner }), verifyBrowserCsrf: async () => true, backend,
}), /trusted browser\/MCP auth adapters/);

// MCP authorization sees only the bearer credential, never browser cookies or identity headers.
resetState();
mcpPrincipal = null;
const missingMcpAuth = await gateway.fetch(new Request(externalOrigin + '/mcp', {
  method: 'POST',
  headers: { cookie: 'synthetic-session=secret', 'oai-authenticated-user-id': 'forged', 'content-type': 'application/json' },
  body: '{}',
}));
assert.equal(missingMcpAuth.status, 401);
assert.equal(missingMcpAuth.headers.get('www-authenticate'), 'Bearer realm="newrelic-chatgpt-mcp"');
assert.equal(missingMcpAuth.headers.get('location'), null, 'MCP auth failure is never redirected to browser login');
assert.equal(JSON.stringify(calls.mcpAuth[0]).includes('synthetic-session'), false);
assert.equal(calls.backend.length, 0);

// A valid browser flow replaces caller-controlled credentials and identity headers.
resetState();
backendResult = async (request) => {
  assert.equal(request.headers.get('authorization')?.startsWith('Bearer '), true);
  for (const name of ['cookie', 'oai-authenticated-user-id', 'x-forwarded-for', 'x-forwarded-host', 'forwarded', 'x-authenticated-user']) {
    assert.equal(request.headers.has(name), false, `${name} is not forwarded`);
  }
  assert.equal(request.headers.get('x-untrusted'), null, 'unknown headers are not forwarded');
  assert.equal(request.headers.get('origin'), externalOrigin);
  assert.equal(request.url, externalOrigin + '/oauth/start?region=eu');
  await forwardedToken(request);
  return new Response('redirect', { status: 302, headers: { location: 'https://oauth2.service.newrelic.com/oauth2/auth?state=synthetic' } });
};
const redirect = await gateway.fetch(browserRequest('/oauth/start?region=eu', {
  headers: {
    cookie: 'synthetic-session=secret',
    authorization: 'Bearer caller-controlled',
    'oai-authenticated-user-id': 'forged',
    'x-forwarded-for': '198.51.100.99',
    'x-forwarded-host': 'attacker.invalid',
    forwarded: 'for=attacker.invalid',
    'x-authenticated-user': 'attacker',
    'x-untrusted': 'discard me',
  },
}));
assert.equal(redirect.status, 302);
assert.equal(redirect.headers.get('location'), 'https://oauth2.service.newrelic.com/oauth2/auth?state=synthetic');
assert.equal(redirect.headers.get('cache-control'), 'no-store');
assert.equal(calls.browserAuth.length, 1);
assert.equal(calls.csrf.length, 1, 'OAuth start GET is protected by browser CSRF verification');
assert.equal(calls.csrf[0].path, '/oauth/start');
assert.equal(calls.csrf[0].subject, owner);
assert.equal(calls.csrf[0].context, 'synthetic-session-context');
assert.equal(calls.backend.length, 1, 'backend invoked once');

// Side-effecting GETs (account listing and OAuth start) are subject to CSRF.
for (const [path, method, body] of [
  ['/api/status', 'GET'], ['/api/capabilities', 'GET'], ['/api/accounts', 'GET'],
  ['/api/usage-consent', 'GET'], ['/api/usage-consent', 'POST', '{}'],
  ['/oauth/start?region=us', 'GET'], ['/oauth/callback?state=synthetic&code=synthetic', 'GET'],
  ['/api/oauth/manual-complete', 'POST', '{}'], ['/api/select-account', 'POST', '{}'], ['/api/disconnect', 'POST', '{}'],
]) {
  resetState();
  csrfResult = false;
  const response = await gateway.fetch(browserRequest(path, { method, ...(body === undefined ? {} : { body }) }));
  assert.equal(response.status, 403, path);
  assert.equal(calls.backend.length, 0, path + ' cannot reach the private Worker without CSRF proof');
  assert.equal(calls.csrf.length, 1);
}

// Cross-site requests and mismatched origins are rejected before any auth/backend work.
for (const headers of [
  { origin: 'https://attacker.invalid', 'sec-fetch-site': 'cross-site' },
  { origin: externalOrigin, 'sec-fetch-site': 'cross-site' },
]) {
  resetState();
  const response = await gateway.fetch(new Request(externalOrigin + '/api/accounts', { headers }));
  assert.equal(response.status, 403);
  assert.equal(calls.browserAuth.length, 0);
  assert.equal(calls.backend.length, 0);
}
resetState();
const externalLanding = await gateway.fetch(new Request(externalOrigin + '/', { headers: {
  origin: 'https://chatgpt.com',
  'sec-fetch-site': 'cross-site',
  'sec-fetch-mode': 'navigate',
  'sec-fetch-dest': 'document',
} }));
assert.equal(externalLanding.status, 200, 'authenticated top-level navigation to the static landing page is allowed');
assert.equal(calls.csrf.length, 0, 'the landing page is read-only');
assert.equal(calls.backend.length, 1);
resetState();
const crossSiteOAuthStart = await gateway.fetch(new Request(externalOrigin + '/oauth/start', { headers: {
  'sec-fetch-site': 'cross-site',
  'sec-fetch-mode': 'navigate',
  'sec-fetch-dest': 'document',
} }));
assert.equal(crossSiteOAuthStart.status, 403, 'cross-site navigation cannot trigger side-effecting OAuth start');
assert.equal(calls.backend.length, 0);

// Browser authentication and CSRF adapter exceptions are treated as denial, without reflecting errors.
resetState();
browserPrincipal = null;
const unauthenticated = await gateway.fetch(browserRequest('/'));
assert.equal(unauthenticated.status, 401);
assert.equal(await unauthenticated.text(), 'Authentication required.');
resetState();
csrfResult = false;
const csrfDenied = await gateway.fetch(browserRequest('/api/accounts'));
assert.equal(csrfDenied.status, 403);
assert.equal(calls.backend.length, 0);
resetState();
browserAuthThrows = true;
assert.equal((await gateway.fetch(browserRequest('/'))).status, 401);
assert.equal(calls.backend.length, 0);
resetState();
csrfThrows = true;
assert.equal((await gateway.fetch(browserRequest('/api/accounts'))).status, 403);
assert.equal(calls.backend.length, 0);
resetState();
mcpAuthThrows = true;
const mcpAuthError = await gateway.fetch(new Request(externalOrigin + '/mcp', {
  method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer synthetic' }, body: '{}',
}));
assert.equal(mcpAuthError.status, 401);
assert.equal(calls.backend.length, 0);

// MCP requests use the MCP adapter and still receive a short-lived gateway assertion.
resetState();
const mcpResponse = await gateway.fetch(new Request(externalOrigin + '/mcp', {
  method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer synthetic-mcp-client-token' }, body: '{}',
}));
assert.equal(mcpResponse.status, 200);
assert.equal(calls.mcpAuth.length, 1);
assert.equal(calls.browserAuth.length, 0);
assert.equal(calls.backend.length, 1);
await forwardedToken(calls.backend[0]);
assert.equal(decode(calls.backend[0].headers.get('authorization').slice('Bearer '.length).split('.')[1]).channel, 'mcp');

// Exercise the actual bundled Worker verifier behind the gateway. The ping tool
// is local-only and does not access New Relic, D1, or an account.
resetState();
const workerEnv = {
  NEW_RELIC_AUTH_MODE: 'signed_proxy',
  NEW_RELIC_AUTH_JWT_PUBLIC_KEY: pinnedPublicKey,
  NEW_RELIC_AUTH_JWT_KID: 'gateway-key-1',
  NEW_RELIC_AUTH_ISSUER: issuer,
  NEW_RELIC_AUTH_AUDIENCE: audience,
  NEW_RELIC_AUTH_ALLOWED_ORIGIN: externalOrigin,
  NEW_RELIC_AUTH_ALLOWED_SUBJECTS: JSON.stringify([owner, member]),
};
const integrationGateway = createSelfHostGateway({
  externalOrigin, issuer, audience, keyId: 'gateway-key-1', allowedSubjects: [owner, member],
  signingKey: keys.privateKey,
  authenticateBrowser: async () => ({ subject: owner }),
  authenticateMcp: async (input) => input.authorization === 'Bearer synthetic-mcp-client-token' ? { subject: owner } : null,
  verifyBrowserCsrf: async () => true,
  backend: { fetch: request => newRelicWorker.fetch(request, workerEnv) },
  now: () => Date.now(),
});
const integratedPing = await integrationGateway.fetch(new Request(externalOrigin + '/mcp', {
  method: 'POST', headers: {
    origin: externalOrigin,
    'sec-fetch-site': 'same-origin',
    'content-type': 'application/json',
    authorization: 'Bearer synthetic-mcp-client-token',
  },
  body: JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'ping', arguments: {} } }),
}));
assert.equal(integratedPing.status, 200, 'the bundled Worker accepts the reference gateway assertion');
const integratedPayload = await integratedPing.json();
assert.equal(integratedPayload.result.structuredContent.ok, true);
assert.equal(integratedPayload.result.content[0].text, 'pong');

// Subject allowlisting is enforced on both adapters; distinct subjects stay distinct.
resetState();
mcpPrincipal = { subject: 'not-allowlisted' };
const outsideAllowlist = await gateway.fetch(new Request(externalOrigin + '/mcp', {
  method: 'POST', headers: { authorization: 'Bearer synthetic-client', 'content-type': 'application/json' }, body: '{}',
}));
assert.equal(outsideAllowlist.status, 401);
assert.equal(calls.backend.length, 0);
resetState();
browserPrincipal = { subject: member, csrfContext: 'member-session' };
backendResult = async (request) => {
  const token = request.headers.get('authorization').slice('Bearer '.length);
  assert.equal(decode(token.split('.')[1]).sub, member);
  return Response.json({ ok: true });
};
assert.equal((await gateway.fetch(browserRequest('/'))).status, 200);

// Approval-only routes require an authenticated stable browser session and
// forward the worker's CSRF header, but never forward a browser cookie.
resetState();
browserPrincipal = {
  subject: owner,
  csrfContext: 'synthetic-session-context',
  sessionId: 'stable-browser-session-identifier-0123456789',
};
backendResult = async (request) => {
  assert.equal(request.headers.get('cookie'), null, 'browser cookies remain at the gateway');
  assert.equal(request.headers.get('x-approval-csrf'), 'synthetic-approval-csrf');
  await forwardedToken(request);
  return Response.json({ ok: true });
};
const approvalSessionResponse = await gateway.fetch(browserRequest('/api/operation-approvals/session', {
  method: 'POST',
  headers: { cookie: 'auth-session=secret', 'x-approval-csrf': 'synthetic-approval-csrf', 'content-type': 'application/json' },
  body: '{}',
}));
assert.equal(approvalSessionResponse.status, 200);
assert.equal(calls.backend.length, 1);
resetState();
browserPrincipal = { subject: owner, csrfContext: 'synthetic-session-context' };
const approvalWithoutStableSession = await gateway.fetch(browserRequest('/api/operation-approvals/session', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
}));
assert.equal(approvalWithoutStableSession.status, 401);
assert.equal(calls.backend.length, 0, 'approval never falls back to subject or jti as a session binding');

// Unsupported routes/methods, wrong hosts, and oversized bodies never reach the backend.
for (const [request, expected] of [
  [new Request(externalOrigin + '/api/unknown'), 404],
  [new Request(externalOrigin + '/mcp', { method: 'GET' }), 405],
  [new Request('https://attacker.invalid/'), 421],
  [new Request(externalOrigin + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: 'x'.repeat(16 * 1024 + 1) }), 413],
]) {
  resetState();
  const response = await gateway.fetch(request);
  assert.equal(response.status, expected);
  assert.equal(calls.backend.length, 0);
}
resetState();
const longUrl = await gateway.fetch(new Request(externalOrigin + '/?q=' + 'x'.repeat(9000)));
assert.equal(longUrl.status, 414);
assert.equal(calls.backend.length, 0);
resetState();
const longHeader = await gateway.fetch(new Request(externalOrigin + '/mcp', {
  method: 'POST', headers: { 'content-type': 'application/json', 'mcp-session-id': 'x'.repeat(20 * 1024) }, body: '{}',
}));
assert.equal(longHeader.status, 431);
assert.equal(calls.mcpAuth.length, 0);
assert.equal(calls.backend.length, 0);
resetState();
let bodyCanceled = false;
const oversizeStream = new ReadableStream({
  start(controller) { controller.enqueue(new Uint8Array(16 * 1024 + 1)); },
  cancel() { bodyCanceled = true; },
});
const streamedOversize = await gateway.fetch(new Request(externalOrigin + '/mcp', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: oversizeStream, duplex: 'half',
}));
assert.equal(streamedOversize.status, 413);
assert.equal(bodyCanceled, true);
assert.equal(calls.backend.length, 0);

// No backend call follows auth, signing, or backend transport failures; errors remain generic.
resetState();
backendResult = async () => new Response('redirect', { status: 302, headers: { location: 'https://attacker.invalid/steal' } });
const badRedirect = await gateway.fetch(browserRequest('/'));
assert.equal(badRedirect.status, 502);
assert.equal(badRedirect.headers.get('location'), null);
resetState();
backendResult = async () => new Response('private response', { status: 200, headers: {
  'set-cookie': 'private=secret', 'access-control-allow-origin': '*',
} });
const sanitized = await gateway.fetch(browserRequest('/'));
assert.equal(sanitized.headers.get('set-cookie'), null);
assert.equal(sanitized.headers.get('access-control-allow-origin'), null);
assert.equal(await sanitized.text(), 'private response');
resetState();
backendResult = async () => { throw new Error('synthetic-private-error'); };
const backendDown = await gateway.fetch(browserRequest('/'));
assert.equal(backendDown.status, 502);
assert.equal(await backendDown.text(), 'Private application is unavailable.');

// A backend must not reflect the assertion through response headers or body.
resetState();
let assertionToLeak = '';
backendResult = async (request) => {
  assertionToLeak = request.headers.get('authorization').slice('Bearer '.length);
  return new Response(assertionToLeak, { status: 200 });
};
const leakedBody = await gateway.fetch(browserRequest('/'));
assert.equal(leakedBody.status, 502);
assert.equal(await leakedBody.text(), 'Private application returned an invalid response.');
resetState();
backendResult = async (request) => {
  assertionToLeak = request.headers.get('authorization').slice('Bearer '.length);
  return new Response('ok', { status: 200, headers: { 'x-debug': assertionToLeak } });
};
const leakedHeader = await gateway.fetch(browserRequest('/'));
assert.equal(leakedHeader.status, 502);
assert.equal(leakedHeader.headers.get('x-debug'), null);
resetState();
backendResult = async (request) => {
  assertionToLeak = request.headers.get('authorization').slice('Bearer '.length);
  return new Response('ok', { status: 200, statusText: assertionToLeak });
};
const leakedStatusText = await gateway.fetch(browserRequest('/'));
assert.equal(leakedStatusText.status, 200);
assert.equal(leakedStatusText.statusText.includes(assertionToLeak), false);
resetState();
backendResult = async () => new Response('x'.repeat(20 * 1024), { status: 200, headers: { 'x-large': 'x'.repeat(20 * 1024) } });
const oversizedBackendHeaders = await gateway.fetch(browserRequest('/'));
assert.equal(oversizedBackendHeaders.status, 502);
resetState();
backendResult = async () => new Response('x'.repeat(2 * 1024 * 1024 + 1), { status: 200 });
const oversizedBackendBody = await gateway.fetch(browserRequest('/'));
assert.equal(oversizedBackendBody.status, 502);

console.log('Self-host gateway tests passed: adapter boundary, CSRF, assertion signing, header stripping, body limits, route allowlist, redirect and error safety');
