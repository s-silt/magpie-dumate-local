// Offline tests: every request goes to a mock fetch. All credentials are made up.
import assert from "node:assert/strict"
import { test } from "node:test"
import * as entry from "../index.mjs"

const { createPlugin, parseCookie, normalizeReasoning, tokenDeadline, CHAT_URL, CONSOLE_ORIGIN } = entry._internal

const COOKIE_A = "bce-sessionid=fake-session-A; bce-user-info=ZmFrZQ=="
const COOKIE_B = "bce-sessionid=fake-session-B; other=1"
const TOKEN_URL = `${CONSOLE_ORIGIN}/api/dumate/app/token/get`
const INFO_URL = `${CONSOLE_ORIGIN}/api/dumate/user/info`
const BODY = JSON.stringify({ model: "model-text", stream: false, messages: [{ role: "user", content: "hi" }] })

const json = (value, init) => new Response(JSON.stringify(value), { headers: { "content-type": "application/json" }, ...init })
const tokenReply = (token) => json({ code: 0, result: { token, expired_at: Date.now() + 3_600_000 } })

// handler(url, init, calls) -> Response. Records every outgoing request.
async function setup(handler, cookie = COOKIE_A) {
  const calls = []
  const fetch = async (url, init) => {
    assert.equal(typeof url, "string")
    const call = { url, init, headers: Object.fromEntries(init.headers) }
    calls.push(call)
    return handler(url, init, calls)
  }
  const hooks = await createPlugin({ fetch })()
  const account = (value) => hooks.auth.loader(async () => ({ type: "oauth", refresh: value, access: "dumate-local", expires: 0 }))
  const loaded = await account(cookie)
  const post = (init = {}) => loaded.fetch(CHAT_URL, { method: "POST", body: BODY, ...init })
  const to = (url) => calls.filter((call) => call.url === url)
  return { calls, hooks, account, loaded, post, to }
}

test("module exports only plugin functions and declares the provider", async () => {
  assert.equal(entry.default, entry.DumateLocalPlugin)
  const functions = Object.entries(entry).filter(([, value]) => typeof value === "function")
  assert.deepEqual(functions.map(([name]) => name).sort(), ["DumateLocalPlugin", "default"])

  const hooks = await entry.default({})
  assert.equal(hooks.auth.provider, "dumate-local")
  const config = {}
  await hooks.config(config)
  const provider = config.provider["dumate-local"]
  assert.equal(provider.npm, "@ai-sdk/openai-compatible")
  assert.equal(provider.api, "https://dumate-svc.baidu.com/gateway/apis/v1")
  assert.deepEqual(provider.models["model-text"].limit, { context: 192000, output: 128000 })
  assert.deepEqual(provider.models["deepseek-v41-flash"].limit, { context: 1000000, output: 384000 })

  const own = { provider: { "dumate-local": { name: "mine" } } }
  await hooks.config(own)
  assert.deepEqual(own.provider["dumate-local"], { name: "mine" }, "a user's own provider entry is kept")
})

test("parseCookie accepts one Cookie header value and nothing else", () => {
  assert.equal(parseCookie(COOKIE_A).cookie, COOKIE_A)
  assert.equal(parseCookie(`  Cookie: ${COOKIE_A} ;`).cookie, COOKIE_A, "prefix and trailing ';' are fine")
  assert.equal(parseCookie("a=b=c==; bce-sessionid=x=y").cookie, "a=b=c==; bce-sessionid=x=y", "'=' in values is kept")
  assert.equal(parseCookie('bce-sessionid=s; q="a b:c"').cookie, 'bce-sessionid=s; q="a b:c"')

  const rejected = [
    undefined,
    "",
    "Cookie:",
    "a=1; b=2", // no session
    "bce-sessionid=",
    'bce-sessionid=""',
    "bce-sessionid=a; bce-sessionid=b",
    "bce-sessionid=a\r\nAuthorization: Bearer x",
    "bce-sessionid=a\nX-Evil: 1",
    "bce-sessionid=a\n",
    "bce-sessionid=a; Authorization: Bearer x",
    "bce-sessionid=a; =novalue",
    "bce-sessionid=a b",
    "bce-sessionid=a; 名=值",
    "bce-sessionid=a\u0000",
    `bce-sessionid=${"a".repeat(20000)}`,
  ]
  for (const input of rejected) {
    const result = parseCookie(input)
    assert.ok(result.error, `rejects ${JSON.stringify(String(input).slice(0, 40))}`)
    assert.equal(result.cookie, undefined)
    assert.ok(!result.error.includes("Bearer") && !result.error.includes("X-Evil"), "input is not echoed")
  }
})

test("login validates the pasted cookie against user/info only", async () => {
  const { hooks, calls } = await setup((url) => {
    assert.equal(url, INFO_URL)
    return json({ code: 0, result: { bceAccountId: "acct-123", displayName: "someone" } })
  })
  const [method] = hooks.auth.methods
  assert.equal(method.type, "oauth")
  assert.equal(method.prompts[0].type, "password")
  assert.equal(method.prompts[0].validate(COOKIE_A), undefined)
  assert.ok(method.prompts[0].validate("nope"))

  const started = await method.authorize({ cookie: `Cookie: ${COOKIE_A}` })
  assert.equal(started.method, "auto")
  assert.equal(calls.length, 0, "nothing is sent before the callback")
  assert.deepEqual(await started.callback(), {
    type: "success",
    refresh: COOKIE_A,
    access: "dumate-local",
    expires: 0,
    accountId: "acct-123",
  })
  assert.equal(calls.length, 1)
  assert.equal(calls[0].init.method, "GET")
  assert.equal(calls[0].init.redirect, "manual")
  assert.equal(calls[0].headers.cookie, COOKIE_A)
  assert.equal(calls[0].headers.authorization, undefined)

  assert.equal((await method.authorize({ cookie: "a=1" })).type, "failed")
  assert.equal(calls.length, 1, "an invalid cookie is never sent")
})

test("login failures never show upstream text or the cookie", async () => {
  const replies = [
    json({ code: 401, message: `登录凭证已过期 secret-upstream-detail ${COOKIE_A}` }),
    json({ code: 0, result: {} }), // no bceAccountId
    new Response("<html>secret-upstream-detail</html>", { status: 500 }),
    new Response(null, { status: 302, headers: { location: "https://login.bce.baidu.com/?x=1" } }),
  ]
  const { hooks } = await setup(() => replies.shift())
  for (let i = 0; i < 4; i++) {
    const started = await hooks.auth.methods[0].authorize({ cookie: COOKIE_A })
    const result = await started.callback()
    assert.equal(result.type, "failed")
    assert.ok(!/secret-upstream-detail|fake-session/.test(JSON.stringify(result)))
  }
})

test("chat sends only the gateway token and its own headers", async () => {
  const { calls, post, to } = await setup((url) =>
    url === TOKEN_URL
      ? tokenReply("gw-token-1")
      : json({ id: "x", choices: [] }, { headers: { "content-type": "application/json", "set-cookie": "leak=1", "x-upstream-internal": "leak" } }),
  )
  const res = await post({
    headers: { authorization: "Bearer magpie-client-key", cookie: "client=1", "x-api-key": "k", "x-evil": "1" },
  })
  assert.equal(res.status, 200)
  assert.deepEqual(await res.json(), { id: "x", choices: [] })
  assert.deepEqual([...res.headers.keys()], ["content-type"], "Set-Cookie and upstream internals are dropped")

  assert.deepEqual(calls.map((call) => call.url), [TOKEN_URL, CHAT_URL])
  const [tokenCall] = to(TOKEN_URL)
  assert.equal(tokenCall.headers.cookie, COOKIE_A)
  assert.equal(tokenCall.init.redirect, "manual")
  const [chatCall] = to(CHAT_URL)
  assert.deepEqual(Object.keys(chatCall.headers).sort(), ["accept", "authorization", "content-type", "user-agent"])
  assert.equal(chatCall.headers.authorization, "Bearer gw-token-1")
  assert.equal(chatCall.init.method, "POST")
  assert.equal(chatCall.init.redirect, "manual")
  assert.equal(chatCall.init.body, BODY, "the body is passed as it came")
})

test("a Request input works like a string one", async () => {
  const { loaded, to } = await setup((url) => (url === TOKEN_URL ? tokenReply("gw-token-1") : json({ ok: true })))
  const res = await loaded.fetch(new Request(CHAT_URL, { method: "POST", body: BODY, headers: { cookie: "client=1", authorization: "Bearer c" } }))
  assert.equal(res.status, 200)
  const [chatCall] = to(CHAT_URL)
  assert.equal(chatCall.init.body, BODY)
  assert.equal(chatCall.headers.authorization, "Bearer gw-token-1")
  assert.equal(chatCall.headers.cookie, undefined)
})

test("SSE is readable before the last chunk arrives", async () => {
  let upstream
  const stream = new ReadableStream({ start: (controller) => (upstream = controller) })
  const { post } = await setup((url) =>
    url === TOKEN_URL ? tokenReply("gw-token-1") : new Response(stream, { headers: { "content-type": "text/event-stream" } }),
  )
  const encoder = new TextEncoder()
  const decoder = new TextDecoder()
  const res = await post()
  assert.equal(res.headers.get("content-type"), "text/event-stream")
  const reader = res.body.getReader()

  upstream.enqueue(encoder.encode('data: {"n":1}\n\n'))
  assert.equal(decoder.decode((await reader.read()).value), 'data: {"n":1}\n\n', "first event is out while the stream is open")
  upstream.enqueue(encoder.encode("data: [DONE]\n\n"))
  upstream.close()
  assert.equal(decoder.decode((await reader.read()).value), "data: [DONE]\n\n")
  assert.equal((await reader.read()).done, true)
})

test("only POST to the exact chat URL is allowed", async () => {
  const { loaded, calls } = await setup(() => assert.fail("nothing may be sent"))
  const post = { method: "POST", body: BODY }
  const refused = [
    ["https://evil.example/gateway/apis/v1/chat/completions", post],
    ["http://dumate-svc.baidu.com/gateway/apis/v1/chat/completions", post],
    ["https://dumate-svc.baidu.com.evil.example/gateway/apis/v1/chat/completions", post],
    ["https://user:pw@dumate-svc.baidu.com/gateway/apis/v1/chat/completions", post],
    ["https://dumate-svc.baidu.com:8443/gateway/apis/v1/chat/completions", post],
    [`${CHAT_URL}?x=1`, post],
    [`${CHAT_URL}/`, post],
    [`${CHAT_URL}#f`, post],
    ["https://dumate-svc.baidu.com/gateway/apis/v1/models", post],
    ["https://dumate-svc.baidu.com/gateway/apis/v1/embeddings", post],
    [`${CONSOLE_ORIGIN}/api/dumate/user/info`, post],
    [TOKEN_URL, post],
    [CHAT_URL, { method: "GET" }],
    [CHAT_URL, { body: BODY }], // no method
    [new Request(`${CHAT_URL}?x=1`, post), undefined],
    [new Request(TOKEN_URL), undefined],
    [new URL(`${CHAT_URL}?x=1`), post],
    [undefined, post],
  ]
  for (const [input, init] of refused) {
    const res = await loaded.fetch(input, init)
    assert.equal(res.status, 400, String(input?.url ?? input))
    assert.equal(res.headers.get("x-magpie-sign-in"), "kept")
  }
  assert.equal(calls.length, 0)
})

test("a gateway redirect is not followed", async () => {
  const { post, to } = await setup((url) =>
    url === TOKEN_URL ? tokenReply("gw-token-1") : new Response(null, { status: 307, headers: { location: "https://evil.example/" } }),
  )
  const res = await post()
  assert.equal(res.status, 502)
  assert.equal(res.headers.get("x-magpie-sign-in"), "kept")
  assert.equal(res.headers.get("location"), null)
  assert.equal(to(CHAT_URL).length, 1)
})

test("a 401 refreshes the token once and retries once", async () => {
  let issued = 0
  const { post, to } = await setup((url, init) => {
    if (url === TOKEN_URL) return tokenReply(`gw-token-${++issued}`)
    return init.headers.get("authorization") === "Bearer gw-token-1" ? json({ error: "stale" }, { status: 401 }) : json({ ok: true })
  })
  const res = await post()
  assert.equal(res.status, 200)
  assert.deepEqual(to(CHAT_URL).map((call) => call.headers.authorization), ["Bearer gw-token-1", "Bearer gw-token-2"])
  assert.equal(to(TOKEN_URL).length, 2)

  assert.equal((await post()).status, 200)
  assert.equal(to(TOKEN_URL).length, 2, "the refreshed token is cached")
})

test("a second 401 keeps the sign-in; an expired cookie marks it", async () => {
  const always401 = await setup((url) => (url === TOKEN_URL ? tokenReply("gw-token-1") : json({ error: "no" }, { status: 401 })))
  let res = await always401.post()
  assert.equal(res.status, 401)
  assert.equal(res.headers.get("x-magpie-sign-in"), "kept")
  assert.equal(always401.to(CHAT_URL).length, 2, "one retry, no more")

  const expired = await setup(() => json({ code: 1, message: "登录凭证已过期，请重新登录" }))
  res = await expired.post()
  assert.equal(res.status, 401)
  assert.equal(res.headers.get("x-magpie-sign-in"), "expired")
  assert.equal(expired.to(CHAT_URL).length, 0)

  for (const [reply, status] of [
    [() => new Response("busy", { status: 429 }), 429],
    [() => new Response("oops", { status: 503 }), 502],
    [() => Promise.reject(new Error("ECONNRESET secret-upstream-detail")), 502],
    [() => new Response(null, { status: 302, headers: { location: "https://elsewhere.example/" } }), 502],
  ]) {
    const down = await setup(reply)
    res = await down.post()
    assert.equal(res.status, status)
    assert.equal(res.headers.get("x-magpie-sign-in"), "kept", "network trouble and rate limits keep the sign-in")
    assert.ok(!/secret-upstream-detail|fake-session/.test(await res.text()))
  }

  const signedOut = await setup(() => assert.fail("nothing may be sent"), undefined)
  res = await (await signedOut.hooks.auth.loader(async () => undefined)).fetch(CHAT_URL, { method: "POST", body: BODY })
  assert.equal(res.status, 401)
  assert.equal(res.headers.get("x-magpie-sign-in"), "expired")
})

test("a 429 is returned once, without a retry", async () => {
  const { post, to } = await setup((url) =>
    url === TOKEN_URL
      ? tokenReply("gw-token-1")
      : json({ error: { message: "rate limited" } }, { status: 429, headers: { "content-type": "application/json", "retry-after": "7", "set-cookie": "leak=1" } }),
  )
  const res = await post()
  assert.equal(res.status, 429)
  assert.equal(res.headers.get("retry-after"), "7")
  assert.equal(res.headers.get("set-cookie"), null)
  assert.equal(res.headers.get("x-magpie-sign-in"), "kept")
  assert.deepEqual(await res.json(), { error: { message: "DuMate 网关限流，请稍后再试", type: "rate_limit_error" } })
  assert.equal(to(CHAT_URL).length, 1)
  assert.equal(to(TOKEN_URL).length, 1)
})

test("an upstream error cannot echo the token, cookie or internal detail", async () => {
  const { post } = await setup((url) =>
    url === TOKEN_URL ? tokenReply("gw-token-1") : new Response("bad token Bearer gw-token-1; bce-sessionid=some-session; trace=internal", { status: 500 }),
  )
  const res = await post()
  assert.equal(res.status, 500)
  assert.deepEqual(await res.json(), { error: { message: "DuMate 网关返回 HTTP 500", type: "api_error" } })
})

test("concurrent requests share one token fetch; accounts stay apart", async () => {
  let release
  const gate = new Promise((resolve) => (release = resolve))
  const { post, account, to, calls } = await setup(async (url, init) => {
    if (url !== TOKEN_URL) return json({ ok: true })
    await gate
    return tokenReply(init.headers.get("cookie") === COOKIE_A ? "gw-token-A" : "gw-token-B")
  })
  const other = await account(COOKIE_B)
  const pending = [post(), post(), post(), other.fetch(CHAT_URL, { method: "POST", body: BODY }), other.fetch(CHAT_URL, { method: "POST", body: BODY })]
  await new Promise((resolve) => setImmediate(resolve))
  release()
  for (const res of await Promise.all(pending)) assert.equal(res.status, 200)

  assert.deepEqual(to(TOKEN_URL).map((call) => call.headers.cookie).sort(), [COOKIE_A, COOKIE_B].sort(), "one token fetch per account")
  assert.deepEqual(to(CHAT_URL).map((call) => call.headers.authorization).sort(), [
    "Bearer gw-token-A", "Bearer gw-token-A", "Bearer gw-token-A", "Bearer gw-token-B", "Bearer gw-token-B",
  ])
  for (const call of calls) {
    const gateway = call.url === CHAT_URL
    assert.equal(call.headers.cookie !== undefined, !gateway, "cookies go to the console only")
    assert.equal(call.headers.authorization !== undefined, gateway, "tokens go to the gateway only")
  }
})

test("concurrent 401s share one refresh", async () => {
  let issued = 0
  const { post, to } = await setup((url, init) => {
    if (url === TOKEN_URL) return tokenReply(`gw-token-${++issued}`)
    return init.headers.get("authorization") === "Bearer gw-token-1" ? json({}, { status: 401 }) : json({ ok: true })
  })
  for (const res of await Promise.all([post(), post(), post()])) assert.equal(res.status, 200)
  assert.equal(to(TOKEN_URL).length, 2)
})

test("the token cache is bounded and separate per plugin instance", async () => {
  const { account, to } = await setup((url, init) => (url === TOKEN_URL ? tokenReply(`t-${init.headers.get("cookie").length}`) : json({ ok: true })))
  const cookies = Array.from({ length: 12 }, (_, i) => `bce-sessionid=fake-${"x".repeat(i)}`)
  for (const cookie of cookies) await (await account(cookie)).fetch(CHAT_URL, { method: "POST", body: BODY })
  assert.equal(to(TOKEN_URL).length, 12)
  await (await account(cookies[11])).fetch(CHAT_URL, { method: "POST", body: BODY })
  assert.equal(to(TOKEN_URL).length, 12, "a recent account is still cached")
  await (await account(cookies[0])).fetch(CHAT_URL, { method: "POST", body: BODY })
  assert.equal(to(TOKEN_URL).length, 13, "the oldest account was evicted")

  const second = await setup((url) => (url === TOKEN_URL ? tokenReply("other-instance") : json({ ok: true })), cookies[11])
  await second.post()
  assert.equal(second.to(TOKEN_URL).length, 1, "another instance has its own cache")
})

test("abort works for string and Request inputs", async () => {
  const hang = (url, init) =>
    url === TOKEN_URL
      ? tokenReply("gw-token-1")
      : new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true }))

  for (const kind of ["string", "request"]) {
    const { loaded, to } = await setup(hang)
    const controller = new AbortController()
    const pending =
      kind === "string"
        ? loaded.fetch(CHAT_URL, { method: "POST", body: BODY, signal: controller.signal })
        : loaded.fetch(new Request(CHAT_URL, { method: "POST", body: BODY, signal: controller.signal }))
    while (!to(CHAT_URL).length) await new Promise((resolve) => setImmediate(resolve))
    controller.abort()
    await assert.rejects(pending, { name: "AbortError" }, kind)
  }

  // Aborted while waiting for the token: the request ends, the refresh goes on for others.
  let release
  const gate = new Promise((resolve) => (release = resolve))
  const { post, to } = await setup(async (url) => (url === TOKEN_URL ? (await gate, tokenReply("gw-token-1")) : json({ ok: true })))
  const controller = new AbortController()
  const aborted = post({ signal: controller.signal })
  const waiting = post()
  await new Promise((resolve) => setImmediate(resolve))
  controller.abort()
  await assert.rejects(aborted, { name: "AbortError" })
  release()
  assert.equal((await waiting).status, 200)
  assert.equal(to(TOKEN_URL).length, 1)
  assert.equal(to(CHAT_URL).length, 1)

  const already = AbortSignal.abort()
  await assert.rejects(post({ signal: already }), { name: "AbortError" })
})

test("usage reads points without spending them", async () => {
  const quotaUrl = `${CONSOLE_ORIGIN}/api/dumate/points/quota_overview?timezone=Asia%2FShanghai&clientType=desktop&ignoreLoginBonus=true`
  const getAuth = async () => ({ type: "oauth", refresh: COOKIE_A })
  const ok = await setup((url) => {
    assert.equal(url, quotaUrl)
    return json({ code: 0, result: { totalPoints: "1000.00", usedPoints: 250.5 } })
  })
  assert.deepEqual(await ok.hooks.auth.usage(getAuth), {
    balance: "749.5 积分",
    windows: [{ name: "积分", used: 25.05, amount: 250.5, limit: 1000, unit: "积分", display: "250.5 / 1000" }],
    signIn: "kept",
  })
  assert.equal(ok.calls.length, 1)
  assert.equal(ok.calls[0].init.method, "GET")
  assert.equal(ok.calls[0].headers.cookie, COOKIE_A)

  const empty = await setup(() => json({ code: 0, result: { totalPoints: 0, usedPoints: 0 } }))
  assert.equal("used" in (await empty.hooks.auth.usage(getAuth)).windows[0], false, "no share is claimed without a total")

  const cases = [
    [() => json({ code: 0, result: { totalPoints: "n/a" } }), "kept"],
    [() => new Response("secret-upstream-detail", { status: 429 }), "kept"],
    [() => Promise.reject(new Error("secret-upstream-detail")), "kept"],
    [() => new Response("secret-upstream-detail", { status: 401 }), "expired"],
  ]
  for (const [reply, signIn] of cases) {
    const { hooks } = await setup(reply)
    const result = await hooks.auth.usage(getAuth)
    assert.equal(result.signIn, signIn)
    assert.ok(result.error)
    assert.deepEqual(result.windows, [])
    assert.ok(!/secret-upstream-detail|fake-session/.test(JSON.stringify(result)))
  }
})

test("reasoning fields are rewritten for deepseek-v41-flash only", () => {
  const body = (extra) => JSON.stringify({ model: "deepseek-v41-flash", messages: [], ...extra })
  assert.deepEqual(JSON.parse(normalizeReasoning(body({ reasoning_effort: "none" }))), {
    model: "deepseek-v41-flash", messages: [], thinking: { type: "disabled" }, enable_thinking: false,
  })
  const low = JSON.parse(normalizeReasoning(body({ reasoning_effort: "low" })))
  assert.deepEqual([low.reasoning_effort, low.thinking.type, low.enable_thinking], ["high", "enabled", true])
  assert.equal(JSON.parse(normalizeReasoning(body({ reasoning_effort: "max" }))).reasoning_effort, "max")

  const untouched = [body({}), body({ reasoning_effort: "medium" }), JSON.stringify({ model: "model-text", reasoning_effort: "low" }), "not json"]
  for (const text of untouched) assert.equal(normalizeReasoning(text), text)
  const bytes = new TextEncoder().encode(untouched[0])
  assert.equal(normalizeReasoning(bytes), bytes)
})

test("tokenDeadline reads seconds, milliseconds and dates, and caps the age", () => {
  const now = Date.parse("2026-11-14T00:00:00Z")
  const soon = now + 30 * 60_000
  for (const value of [soon, soon / 1000, String(soon), new Date(soon).toISOString()]) {
    assert.equal(tokenDeadline(value, now), soon - 60_000)
  }
  assert.equal(tokenDeadline(now + 14 * 3_600_000, now), now + 3_600_000, "capped at an hour")
  assert.equal(tokenDeadline(undefined, now), now + 600_000)
  assert.equal(tokenDeadline("garbage", now), now + 600_000)
})
