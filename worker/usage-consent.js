const CONSENT_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const CAPABILITIES = Object.freeze(["core_compute", "advanced_compute", "preview"]);

function db(env) {
  if (!env?.DB || typeof env.DB.prepare !== "function") {
    throw new Error("D1 database binding DB is not configured.");
  }
  return env.DB;
}

/** @returns {Record<string, {enabled: boolean, expiresAt: number | null}>} */
function emptyState() {
  return Object.fromEntries(CAPABILITIES.map((capability) => [capability, {
    enabled: false,
    expiresAt: null,
  }]));
}

export async function getUsageConsents(env, userId, now = Date.now()) {
  const state = emptyState();
  if (!userId) return state;
  const rows = await db(env).prepare(
    "SELECT capability, expires_at FROM nr_usage_consents WHERE user_id = ?",
  ).bind(userId).all();
  for (const row of rows?.results || []) {
    if (!CAPABILITIES.includes(row.capability)) continue;
    const expiresAt = Number(row.expires_at);
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= now) continue;
    state[row.capability] = { enabled: true, expiresAt };
  }
  return state;
}

export async function updateUsageConsents(env, userId, choices, now = Date.now()) {
  if (typeof userId !== "string" || !userId || !isValidUsageConsentChoices(choices)) {
    throw new Error("Invalid usage consent choices.");
  }
  if (!Number.isSafeInteger(now) || now < 0 || now > Number.MAX_SAFE_INTEGER - CONSENT_TTL_MS) {
    throw new Error("Invalid usage consent timestamp.");
  }
  const database = db(env);
  const expiresAt = now + CONSENT_TTL_MS;
  const statements = CAPABILITIES.map((capability) => choices[capability]
    ? database.prepare(
      "INSERT INTO nr_usage_consents (user_id, capability, granted_at, expires_at) VALUES (?, ?, ?, ?) "
      + "ON CONFLICT(user_id, capability) DO UPDATE SET granted_at = excluded.granted_at, expires_at = excluded.expires_at",
    ).bind(userId, capability, now, expiresAt)
    : database.prepare("DELETE FROM nr_usage_consents WHERE user_id = ? AND capability = ?")
      .bind(userId, capability));
  await database.batch(statements);
  return getUsageConsents(env, userId, now);
}

export function isValidUsageConsentChoices(choices) {
  return choices !== null && typeof choices === "object" && !Array.isArray(choices)
    && Object.keys(choices).length === CAPABILITIES.length
    && CAPABILITIES.every((capability) => typeof choices[capability] === "boolean")
    && Object.keys(choices).every((capability) => CAPABILITIES.includes(capability));
}

export const USAGE_CONSENT_TTL_MS_VALUE = CONSENT_TTL_MS;
export const USAGE_CONSENT_CAPABILITIES = CAPABILITIES;
