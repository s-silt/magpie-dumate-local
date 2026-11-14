// Magpie / OpenCode provider plugin: 百度搭子 DuMate (provider id "dumate-local").
//
// Independent implementation. Endpoints, response shapes and model metadata are
// taken from the MIT-licensed reference
//   https://github.com/R227BOUT/magpie-dumate (commit 1d950b324b971fa162183d8114ce38a9ea411559)
// and from https://usemagpie.ai/docs/plugins. See README.md -> 来源与归属.
//
// Flow: the user pastes their own Baidu console Cookie header -> the cookie is
// exchanged (console origin only) for a short-lived gateway token -> the token
// is sent to exactly one URL, the gateway's chat/completions.

import { createHash } from "node:crypto"

const PROVIDER = "dumate-local"
const VERSION = "0.1.0"
const USER_AGENT = `magpie-dumate-local/${VERSION}`

const CONSOLE_ORIGIN = "https://console.bce.baidu.com"
const GATEWAY_BASE = "https://dumate-svc.baidu.com/gateway/apis/v1"
const CHAT_URL = `${GATEWAY_BASE}/chat/completions`
const LOGIN_PAGE = "https://login.bce.baidu.com/?from=oa_dumate&redirect=https%3A%2F%2Fconsole.bce.baidu.com%2F"
// A console 3xx to one of these hosts is read as "session expired".
const LOGIN_HOSTS = new Set(["login.bce.baidu.com", "passport.baidu.com"])

const USER_INFO_PATH = "/api/dumate/user/info"
const TOKEN_PATH = "/api/dumate/app/token/get"
const QUOTA_PATH =
  "/api/dumate/points/quota_overview?timezone=Asia%2FShanghai&clientType=desktop&ignoreLoginBonus=true"

const CONSOLE_TIMEOUT_MS = 20_000
const MAX_COOKIE_LENGTH = 16 * 1024
const MAX_CONSOLE_BODY = 1024 * 1024
const TOKEN_CACHE_SIZE = 8
const TOKEN_MAX_AGE_MS = 60 * 60 * 1000 // never trust a cached token longer than this
const TOKEN_FALLBACK_AGE_MS = 10 * 60 * 1000 // when expired_at can't be read
const TOKEN_MARGIN_MS = 60 * 1000

// Model metadata comes from the reference repository, not from measurements:
// - model-text: 192000 / 128000 as in the reference's index.mjs FALLBACK_MODELS.
//   (Its models.default.json lists 1000000 / 384000 with image input; the smaller
//   figures and text-only input are kept here as the conservative reading.)
// - deepseek-v41-flash: models.default.json at the pinned commit. Listed there as
//   a reference catalog, "NOT a promise that the account can call every model".
const MODELS = {
  "model-text": {
    name: "DuMate Auto (model-text)",
    limit: { context: 192_000, output: 128_000 },
    tool_call: true,
    reasoning: false,
    attachment: false,
    modalities: { input: ["text"], output: ["text"] },
  },
  "deepseek-v41-flash": {
    name: "deepseek-v41-flash",
    limit: { context: 1_000_000, output: 384_000 },
    tool_call: true,
    reasoning: true,
    attachment: true,
    modalities: { input: ["text", "image"], output: ["text"] },
    // Per the reference's reasoning.mjs the upstream only knows thinking on/off:
    // "low" and "high" are the same strength, so "low" is not offered as a level.
    variants: { none: {}, high: {}, max: {} },
  },
}

// ---- Errors ------------------------------------------------------------------

// Every message a user can see is one of these fixed strings. Upstream text and
// credentials are never copied into an error.
const MESSAGES = {
  expired: "百度控制台会话已失效，请重新登录",
  rate_limited: "百度控制台限流，请稍后再试",
  unavailable: "百度控制台暂时不可用，请稍后再试",
}

function consoleError(kind) {
  const error = new Error(MESSAGES[kind])
  error.kind = kind
  if (kind === "expired") error.signIn = "expired"
  return error
}

function errorResponse(status, message, signIn = "kept", retryAfter) {
  const type = status === 401 ? "authentication_error" : status === 429 ? "rate_limit_error" : status === 400 ? "invalid_request_error" : "api_error"
  return new Response(JSON.stringify({ error: { message, type } }), {
    status,
    headers: {
      "content-type": "application/json",
      "x-magpie-sign-in": signIn,
      ...(retryAfter ? { "retry-after": retryAfter } : {}),
    },
  })
}

// ---- Cookie input ------------------------------------------------------------

const COOKIE_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/
// Printable ASCII without ';' and '"', or a double-quoted value that may hold spaces.
const COOKIE_VALUE = /^(?:[\x21\x23-\x3A\x3C-\x7E]*|"[\x20\x21\x23-\x3A\x3C-\x7E]*")$/

// Accepts one Cookie request-header value ("a=1; b=2", optionally prefixed with
// "Cookie:"). Returns { cookie } normalised, or { error } that never echoes input.
function parseCookie(raw) {
  if (typeof raw !== "string") return { error: "请粘贴 Cookie 请求头的值" }
  if (/[\r\n]/.test(raw)) return { error: "Cookie 不能包含换行，请只粘贴 Cookie 这一行的值" }
  const text = raw.trim().replace(/^cookie:[ \t]*/i, "")
  if (!text) return { error: "请粘贴 Cookie 请求头的值" }
  if (text.length > MAX_COOKIE_LENGTH) return { error: "Cookie 过长" }
  if (/[^\x20-\x7E]/.test(text)) return { error: "Cookie 含有非法字符" }

  const pairs = []
  let sessions = 0
  for (const part of text.split(";")) {
    const pair = part.trim()
    if (!pair) continue
    const eq = pair.indexOf("=")
    const name = pair.slice(0, eq)
    const value = pair.slice(eq + 1) // keeps any further '=' in the value
    if (eq <= 0 || !COOKIE_NAME.test(name) || !COOKIE_VALUE.test(value)) {
      return { error: "Cookie 格式不正确，应为 name=value; name2=value2" }
    }
    if (name === "bce-sessionid") {
      sessions++
      if (!value.replace(/"/g, "")) return { error: "bce-sessionid 为空" }
    }
    pairs.push(`${name}=${value}`)
  }
  if (sessions === 0) return { error: "Cookie 缺少 bce-sessionid（请从开发者工具 Network 的请求头复制，不是 document.cookie）" }
  if (sessions > 1) return { error: "Cookie 中 bce-sessionid 重复" }
  return { cookie: pairs.join("; ") }
}

const cookieOf = (auth) => (auth?.type === "oauth" && typeof auth.refresh === "string" ? parseCookie(auth.refresh).cookie : undefined)

// ---- Small helpers -----------------------------------------------------------

const discard = (res) => res.body?.cancel().catch(() => {})

function raceAbort(promise, signal) {
  if (!signal) return promise
  if (signal.aborted) return Promise.reject(signal.reason)
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(signal.reason)
    signal.addEventListener("abort", onAbort, { once: true })
    promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort))
  })
}

// expired_at as epoch seconds, epoch milliseconds or a date string.
function tokenDeadline(expiredAt, now) {
  let at = NaN
  if (typeof expiredAt === "string" && /^\d+$/.test(expiredAt)) expiredAt = Number(expiredAt)
  if (typeof expiredAt === "number") at = expiredAt < 1e12 ? expiredAt * 1000 : expiredAt
  else if (typeof expiredAt === "string" && expiredAt) at = Date.parse(expiredAt)
  if (!Number.isFinite(at)) return now + TOKEN_FALLBACK_AGE_MS
  return Math.min(at - TOKEN_MARGIN_MS, now + TOKEN_MAX_AGE_MS)
}

function points(value) {
  const n = typeof value === "string" && value.trim() ? Number(value) : value
  return typeof n === "number" && Number.isFinite(n) && n >= 0 ? n : undefined
}

const fixed = (n) => n.toFixed(2).replace(/\.?0+$/, "")

// deepseek-v41-flash only. Basis: reasoning.mjs of the reference (contributed by
// RanceLee), which says the upstream understands thinking on/off, that "low" and
// "high" are one and the same strength, and sends these fields. Nothing here
// claims distinct upstream budgets. Any other model or effort passes untouched.
function normalizeReasoning(body) {
  let request
  try {
    request = JSON.parse(typeof body === "string" ? body : new TextDecoder().decode(body))
  } catch {
    return body
  }
  const effort = request?.reasoning_effort
  if (request?.model !== "deepseek-v41-flash" || !["none", "low", "high", "max"].includes(effort)) return body
  const enabled = effort !== "none"
  if (!enabled) delete request.reasoning_effort
  else if (effort === "low") request.reasoning_effort = "high"
  request.thinking = { ...request.thinking, type: enabled ? "enabled" : "disabled" }
  request.enable_thinking = enabled
  return JSON.stringify(request)
}

// ---- Plugin factory ----------------------------------------------------------

// options.fetch / options.now are for tests; production uses globalThis.fetch.
function createPlugin(options = {}) {
  const fetchImpl = options.fetch ?? ((...args) => globalThis.fetch(...args))
  const now = options.now ?? Date.now

  // Gateway tokens, per plugin instance, keyed by a hash of the cookie so the
  // cache holds no second copy of it. Bounded, and entries die with the token.
  const tokens = new Map() // key -> { token, until }
  const refreshing = new Map() // key -> Promise<token>
  const keyOf = (cookie) => createHash("sha256").update(cookie).digest("hex")

  // The only function that sends the cookie. The URL is built from constants.
  async function consoleGet(path, cookie, signal) {
    const timeout = AbortSignal.timeout(CONSOLE_TIMEOUT_MS)
    let res
    let text
    try {
      res = await fetchImpl(`${CONSOLE_ORIGIN}${path}`, {
        method: "GET",
        headers: new Headers({
          cookie,
          accept: "application/json",
          referer: `${CONSOLE_ORIGIN}/`,
          "user-agent": USER_AGENT,
        }),
        redirect: "manual", // never carry the cookie to another address
        signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
      })
      if (res.status >= 300 && res.status < 400) {
        discard(res)
        let host = ""
        try {
          host = new URL(res.headers.get("location") ?? "", CONSOLE_ORIGIN).hostname
        } catch {
          // an unreadable Location is not proof of an expired session
        }
        throw consoleError(LOGIN_HOSTS.has(host) ? "expired" : "unavailable")
      }
      if (res.status === 401) throw (discard(res), consoleError("expired"))
      if (res.status === 429) throw (discard(res), consoleError("rate_limited"))
      text = await res.text()
    } catch (error) {
      throw error?.kind ? error : consoleError("unavailable") // network, timeout, abort
    }
    let payload
    try {
      payload = text.length <= MAX_CONSOLE_BODY ? JSON.parse(text) : undefined
    } catch {
      // not JSON
    }
    if (res.ok && payload?.code === 0 && payload.result && typeof payload.result === "object") return payload.result
    // The reference reads a business error that talks about signing in as an
    // expired session; anything else leaves the sign-in alone.
    const says = typeof payload?.message === "string" ? payload.message : ""
    throw consoleError(res.status < 500 && /登录|login/i.test(says) ? "expired" : "unavailable")
  }

  // Cached token for this cookie. `stale` is a token the gateway just refused:
  // it is dropped, and callers that were refused together share one refresh.
  function gatewayToken(cookie, signal, stale) {
    const key = keyOf(cookie)
    const hit = tokens.get(key)
    if (hit && hit.token !== stale && now() < hit.until) {
      tokens.delete(key)
      tokens.set(key, hit) // most recently used goes last
      return raceAbort(Promise.resolve(hit.token), signal)
    }
    tokens.delete(key)
    let pending = refreshing.get(key)
    if (!pending) {
      // One caller giving up must not cancel the refresh the others wait for,
      // so the refresh itself only has its own timeout.
      pending = consoleGet(TOKEN_PATH, cookie)
        .then((result) => {
          const token = result.token
          if (typeof token !== "string" || !/^[\x21-\x7E]{1,4096}$/.test(token)) throw consoleError("unavailable")
          for (const [k, v] of tokens) if (now() >= v.until) tokens.delete(k)
          while (tokens.size >= TOKEN_CACHE_SIZE) tokens.delete(tokens.keys().next().value)
          tokens.set(key, { token, until: tokenDeadline(result.expired_at, now()) })
          return token
        })
        .finally(() => refreshing.delete(key))
      pending.catch(() => {}) // every waiter may have aborted
      refreshing.set(key, pending)
    }
    return raceAbort(pending, signal)
  }

  // What goes back to Magpie: status and body as they came, and only headers
  // that are safe to show (no Set-Cookie, no upstream internals).
  function relay(res) {
    const headers = new Headers()
    for (const name of ["content-type", "cache-control", "retry-after"]) {
      const value = res.headers.get(name)
      if (value) headers.set(name, value)
    }
    if (res.status >= 300 && res.status < 400) {
      discard(res)
      return errorResponse(502, "DuMate 网关返回重定向，已拒绝跟随")
    }
    if (res.status === 401) {
      // The cookie just produced a fresh token, so the session itself is not
      // known to be expired: keep the sign-in.
      discard(res)
      return errorResponse(401, "DuMate 网关拒绝了刚刷新的令牌，请稍后再试")
    }
    if (res.status >= 400) {
      discard(res)
      const message = res.status === 429 ? "DuMate 网关限流，请稍后再试" : `DuMate 网关返回 HTTP ${res.status}`
      return errorResponse(res.status, message, "kept", headers.get("retry-after"))
    }
    return new Response(res.body, { status: res.status, headers }) // streamed, not buffered
  }

  async function chat(cookie, input, init) {
    const request = typeof Request !== "undefined" && input instanceof Request ? input : undefined
    const url = request ? request.url : input instanceof URL ? input.href : typeof input === "string" ? input : ""
    const method = String(init?.method ?? request?.method ?? "").toUpperCase()
    // Exactly this URL: no other origin, path, query, fragment or userinfo.
    if (url !== CHAT_URL || method !== "POST") return errorResponse(400, "dumate-local 只允许 POST 官方 chat/completions 接口")
    if (!cookie) return errorResponse(401, "尚未登录 dumate-local，请先运行 magpie plugin login dumate-local", "expired")

    const signal = init?.signal ?? request?.signal ?? undefined
    let body = init?.body
    if (body == null && request) body = await request.clone().text()
    if (typeof body !== "string" && !(body instanceof ArrayBuffer) && !ArrayBuffer.isView(body)) {
      return errorResponse(400, "dumate-local 只接受 JSON 文本请求体")
    }
    body = normalizeReasoning(body)

    let stale
    for (let attempt = 0; ; attempt++) {
      let token
      try {
        token = await gatewayToken(cookie, signal, stale)
      } catch (error) {
        if (signal?.aborted) throw signal.reason
        if (error?.kind === "expired") return errorResponse(401, MESSAGES.expired, "expired")
        return errorResponse(error?.kind === "rate_limited" ? 429 : 502, MESSAGES[error?.kind] ?? MESSAGES.unavailable)
      }
      let res
      try {
        // Fresh headers: nothing the client sent (Authorization, Cookie, ...) goes on.
        res = await fetchImpl(CHAT_URL, {
          method: "POST",
          headers: new Headers({
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
            accept: "application/json, text/event-stream",
            "user-agent": USER_AGENT,
          }),
          body,
          redirect: "manual", // never carry the token to another address
          signal,
        })
      } catch {
        if (signal?.aborted) throw signal.reason
        return errorResponse(502, "无法连接 DuMate 网关")
      }
      if (res.status === 401 && attempt === 0) {
        discard(res)
        stale = token // refresh once, then try once more
        continue
      }
      return relay(res)
    }
  }

  async function login(cookie, signal) {
    let info
    try {
      info = await consoleGet(USER_INFO_PATH, cookie, signal)
    } catch (error) {
      return { type: "failed", error: `Cookie 验证失败：${MESSAGES[error?.kind] ?? MESSAGES.unavailable}` }
    }
    const accountId = String(info.bceAccountId ?? "")
    if (!/^[\w.@-]{1,128}$/.test(accountId)) return { type: "failed", error: "Cookie 验证失败：百度未返回账号 ID" }
    // The cookie is the long-lived credential, so it is kept as `refresh` (Magpie
    // saves an OAuth sign-in when `refresh` is set). `access` holds no secret:
    // the gateway token lives in memory only. expires 0 = Magpie never renews.
    return { type: "success", refresh: cookie, access: PROVIDER, expires: 0, accountId }
  }

  async function usage(getAuth) {
    try {
      const cookie = cookieOf(await getAuth())
      if (!cookie) return { error: "尚未登录", windows: [], signIn: "kept" }
      const overview = await consoleGet(QUOTA_PATH, cookie)
      const total = points(overview.totalPoints)
      const used = points(overview.usedPoints)
      if (total === undefined || used === undefined) return { error: "无法识别积分数据", windows: [], signIn: "kept" }
      const left = Math.max(0, total - used)
      return {
        balance: `${fixed(left)} 积分`,
        windows: [
          {
            name: "积分",
            ...(total > 0 ? { used: (100 * used) / total } : {}), // unknown share is left out, not 0
            amount: used,
            limit: total,
            unit: "积分",
            display: `${fixed(used)} / ${fixed(total)}`,
          },
        ],
        signIn: "kept",
      }
    } catch (error) {
      const expired = error?.kind === "expired"
      return { error: MESSAGES[error?.kind] ?? "积分查询失败", windows: [], signIn: expired ? "expired" : "kept" }
    }
  }

  return async function DumateLocalPlugin() {
    return {
      config: async (config) => {
        config.provider ??= {}
        config.provider[PROVIDER] ??= {
          name: "百度搭子 DuMate (local)",
          npm: "@ai-sdk/openai-compatible",
          api: GATEWAY_BASE,
          models: structuredClone(MODELS),
        }
      },
      auth: {
        provider: PROVIDER,
        methods: [
          {
            type: "oauth",
            label: "粘贴百度控制台 Cookie",
            prompts: [
              {
                type: "password", // typed unseen
                key: "cookie",
                message: `Cookie 请求头的值（先自行在 ${LOGIN_PAGE} 登录，再从 console.bce.baidu.com 的开发者工具 Network 请求头复制，需含 bce-sessionid）`,
                placeholder: "bce-sessionid=…; …",
                validate: (value) => parseCookie(value).error,
              },
            ],
            async authorize(inputs, context) {
              const parsed = parseCookie(inputs?.cookie)
              if (parsed.error) return { type: "failed", error: parsed.error }
              return {
                url: "",
                instructions: "正在向百度控制台验证该会话…",
                method: "auto",
                callback: (...args) => login(parsed.cookie, args.find((arg) => arg?.signal)?.signal ?? context?.signal),
              }
            },
          },
        ],
        async loader(getAuth) {
          const cookie = cookieOf(await getAuth())
          return {
            baseURL: GATEWAY_BASE,
            apiKey: PROVIDER, // a placeholder; the real token is set in fetch
            fetch: (input, init) => chat(cookie, input, init),
          }
        },
        usage,
      },
    }
  }
}

// Only plugin functions may be exported as functions: Magpie calls every
// exported function as a plugin. Both names are the same function.
export const DumateLocalPlugin = createPlugin()
export default DumateLocalPlugin

// For tests.
export const _internal = { createPlugin, parseCookie, normalizeReasoning, tokenDeadline, CHAT_URL, CONSOLE_ORIGIN }
