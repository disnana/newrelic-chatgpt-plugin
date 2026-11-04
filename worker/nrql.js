const MAX_QUERY_LENGTH = 6000;
const MAX_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_RESULTS = 100;

export class NrqlValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "NrqlValidationError";
  }
}

export function filterMetricNames(data, search, limit) {
  const metrics = data?.result?.dimensional_metrics;
  const timeslice = data?.result?.timeslice_metrics;
  if (!Array.isArray(metrics) || !Array.isArray(timeslice)) throw new NrqlValidationError("メトリクス一覧の形式を確認できませんでした。");
  const matches = [...new Set([...metrics, ...timeslice].filter((name) => typeof name === "string" && name.toLowerCase().includes(search.toLowerCase())))];
  return { metrics: matches.slice(0, limit), matchingReturnedCount: matches.length, truncated: matches.length > limit, note: "取得できた一覧内の一致です。上流の一覧が完全とは限りません。" };
}

function readOnlyBase(query) {
  if (typeof query !== "string" || !query.trim()) {
    throw new NrqlValidationError("NRQLを指定してください。");
  }
  const value = query.trim();
  if (value.length > MAX_QUERY_LENGTH) {
    throw new NrqlValidationError("NRQLは6000文字以内にしてください。");
  }
  if (/[;\r\n]|--|\/\*|\*\//.test(value)) {
    throw new NrqlValidationError("複数文やコメントを含むNRQLは実行できません。");
  }
  if (!/^SELECT\b/i.test(value)) {
    throw new NrqlValidationError("読み取り専用のSELECT NRQLだけ実行できます。");
  }
  // A full NRQL parser is not available here: fail closed on syntax for which
  // the outer time and result limits cannot be reliably enforced.
  let masked = "";
  for (let i = 0; i < value.length; i++) {
    const quote = value[i];
    if (quote !== "'" && quote !== '"' && quote !== '`') { masked += quote; continue; }
    let content = "";
    let closed = false;
    masked += " ";
    while (++i < value.length) {
      const char = value[i];
      if (char === "\\" && i + 1 < value.length) { content += value[++i]; masked += "  "; continue; }
      if (char === quote) {
        if (value[i + 1] === quote) { content += quote; masked += "  "; i++; continue; }
        masked += " "; closed = true; break;
      }
      content += char; masked += " ";
    }
    if (!closed || /\b(?:SELECT|SINCE|UNTIL|LIMIT|COMPARE|WITH)\b/i.test(content)) {
      throw new NrqlValidationError("時間・件数の制限を検証できないNRQLです。");
    }
  }
  if ((masked.match(/\bSELECT\b/gi) || []).length !== 1
    || /\b(?:JOIN|COMPARE\s+WITH|WITH|UNION)\b/i.test(masked)
    || /\bLIMIT\s+MAX\b/i.test(masked)
    || [/\bSINCE\b/gi, /\bUNTIL\b/gi, /\bLIMIT\b/gi].some((pattern) => (masked.match(pattern) || []).length > 1)) {
    throw new NrqlValidationError("入れ子や複数の時間・件数条件を含むNRQLは使用できません。");
  }
  return value;
}

function relativeTimestamp(spec, now) {
  const value = String(spec || "").trim().replace(/^['"]|['"]$/g, "");
  const relative = value.match(/^(?:last\s+)?(\d+)\s+(seconds?|minutes?|hours?|days?|weeks?)\s+ago$/i);
  if (relative) {
    const unit = relative[2].toLowerCase().replace(/s$/, "");
    const multiplier = {
      second: 1000,
      minute: 60000,
      hour: 3600000,
      day: 86400000,
      week: 604800000,
    }[unit];
    return now - Number(relative[1]) * multiplier;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function timeClause(query, keyword) {
  const match = keyword === "SINCE"
    ? query.match(/\bSINCE\s+(.+?)(?=\s+(?:UNTIL|FACET|LIMIT|TIMESERIES|ORDER\s+BY)\b|$)/i)
    : query.match(/\bUNTIL\s+(.+?)(?=\s+(?:FACET|LIMIT|TIMESERIES|ORDER\s+BY)\b|$)/i);
  return match?.[1]?.trim() || null;
}

function enforceTimeRange(query, now) {
  let updated = query;
  let since = timeClause(updated, "SINCE");
  const until = timeClause(updated, "UNTIL");
  if (!since && until) {
    throw new NrqlValidationError("UNTILを使う場合はSINCEも指定してください。");
  }
  if (!since) {
    since = "30 minutes ago";
    updated += " SINCE " + since;
  }
  const start = relativeTimestamp(since, now);
  const end = until ? relativeTimestamp(until, now) : now;
  if (!Number.isFinite(start) || !Number.isFinite(end)) {
    throw new NrqlValidationError("期間を読み取れません。NRQLのSINCE/UNTILは最大7日以内の日時または相対時間で指定してください。");
  }
  if (end <= start || start > now + 5 * 60 * 1000) {
    throw new NrqlValidationError("NRQLの時間範囲が正しくありません。");
  }
  if (end - start > MAX_WINDOW_MS) {
    throw new NrqlValidationError("NRQLは最大7日間まで実行できます。");
  }
  return updated;
}

function capLimit(query) {
  const match = query.match(/\bLIMIT\s+(\d+)\b/i);
  if (!match) return query + " LIMIT " + MAX_RESULTS;
  const requested = Number(match[1]);
  if (requested < 1) throw new NrqlValidationError("LIMITは1以上で指定してください。");
  if (requested <= MAX_RESULTS) return query;
  return query.replace(match[0], "LIMIT " + MAX_RESULTS);
}

export function normalizeNrql(input, now = Date.now()) {
  const base = readOnlyBase(input);
  return capLimit(enforceTimeRange(base, now));
}

function explicitTime(value, label) {
  if (typeof value !== "string" || !value.trim()) {
    throw new NrqlValidationError(label + "の開始・終了時刻が必要です。");
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new NrqlValidationError(label + "の時刻はISO 8601形式で指定してください。");
  }
  return timestamp;
}

function removeTimeClause(query) {
  const marker = /\s+SINCE\b/i.exec(query);
  if (!marker) {
    if (/\bUNTIL\b/i.test(query)) {
      throw new NrqlValidationError("UNTILを使う場合はSINCEも指定してください。");
    }
    return query;
  }
  const prefix = query.slice(0, marker.index);
  const suffix = query.slice(marker.index);
  const keep = /\s+(?:FACET|LIMIT|TIMESERIES|ORDER\s+BY)\b/i.exec(suffix);
  return (prefix + (keep ? suffix.slice(keep.index) : "")).trim();
}

export function buildComparisonNrql(input, startValue, endValue, now = Date.now()) {
  const base = readOnlyBase(input);
  const start = explicitTime(startValue, "比較期間");
  const end = explicitTime(endValue, "比較期間");
  if (end <= start || start > now + 5 * 60 * 1000) {
    throw new NrqlValidationError("比較期間の開始時刻と終了時刻が正しくありません。");
  }
  if (end - start > MAX_WINDOW_MS) {
    throw new NrqlValidationError("比較する各期間は最大7日間です。");
  }
  const query = removeTimeClause(base)
    + " SINCE '" + new Date(start).toISOString()
    + "' UNTIL '" + new Date(end).toISOString() + "'";
  return capLimit(query);
}

export function validateLogFilter(input) {
  if (input === undefined || input === null || input === "") return "";
  if (typeof input !== "string" || input.length > 1200) {
    throw new NrqlValidationError("ログの絞り込み条件は1200文字以内で指定してください。");
  }
  if (/[;]|--|\/\*|\*\//.test(input)
    || /\b(?:SELECT|FROM|SINCE|UNTIL|FACET|LIMIT|TIMESERIES|JOIN|DELETE|UPDATE|INSERT|DROP|CREATE)\b/i.test(input)) {
    throw new NrqlValidationError("ログの絞り込み条件にNRQLの構文や複数文は含められません。");
  }
  return input.trim();
}

export function validateLogWindow(input) {
  if (input === undefined || input === null || input === "") return "30 minutes ago";
  if (typeof input !== "string" || input.length > 60) {
    throw new NrqlValidationError("ログ検索の期間は最大7日以内で指定してください。");
  }
  const normalized = input.trim().replace(/^last\s+/i, "").replace(/\s+ago$/i, "") + " ago";
  const match = normalized.match(/^(\d+)\s+(seconds?|minutes?|hours?|days?|weeks?)\s+ago$/i);
  if (!match) {
    throw new NrqlValidationError("ログ検索の期間は「30 minutes ago」のように指定してください。");
  }
  if (Number(match[1]) < 1) {
    throw new NrqlValidationError("ログ検索の期間は1以上で指定してください。");
  }
  const span = relativeTimestamp(normalized, Date.now());
  if (Date.now() - span > MAX_WINDOW_MS) {
    throw new NrqlValidationError("ログ検索は最大7日間までです。");
  }
  return normalized;
}
