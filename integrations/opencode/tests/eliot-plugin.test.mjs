import test from "node:test"
import assert from "node:assert/strict"
import http from "node:http"
import { once } from "node:events"
import { readFile } from "node:fs/promises"
import { resolve } from "node:path"

const pluginPath = resolve("integrations/opencode/plugins/eliot.js")
const source = await readFile(pluginPath, "utf8")
const pluginModule = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`)

const ENV_KEYS = [
  "ELIOT_TASK_ID",
  "ELIOT_WORK_ITEM_ID",
  "ELIOT_OPENCODE_BRIDGE_URL",
  "ELIOT_OPENCODE_BRIDGE_TOKEN",
  "ELIOT_OPENCODE_BRIDGE_TIMEOUT_MS",
  "ELIOT_OPENCODE_BRIDGE_OUTPUT_LIMIT",
  "ELIOT_GOVERNOR_EXE",
]
const nativeFetch = globalThis.fetch

function cleanEnvironment() {
  for (const key of ENV_KEYS) delete process.env[key]
  delete globalThis.Bun
  globalThis.fetch = nativeFetch
}

async function withServer(handler, body) {
  const server = http.createServer(handler)
  server.listen(0, "127.0.0.1")
  await once(server, "listening")
  try {
    const { port } = server.address()
    return await body(`http://127.0.0.1:${port}/`)
  } finally {
    server.close()
    await once(server, "close")
  }
}

async function hooks() {
  return pluginModule.EliotPlugin({
    client: {
      app: {
        log: async () => {},
      },
    },
  })
}

test.afterEach(cleanEnvironment)

test("mutating gate prefers authenticated loopback HTTP and never sends argument values", async () => {
  await withServer(async (request, response) => {
    const chunks = []
    for await (const chunk of request) chunks.push(chunk)
    const text = Buffer.concat(chunks).toString("utf8")
    const payload = JSON.parse(text)

    assert.equal(request.url, "/v1/host-events")
    assert.equal(request.headers.authorization, "Bearer unit-token")
    assert.equal(request.headers["idempotency-key"], payload.event_id)
    assert.equal(payload.tool, "bash")
    assert.deepEqual(payload.argument_keys, ["command"])
    assert.equal(payload.effect_descriptor.schema_version, "eliot.opencode.effect.v1")
    assert.equal(payload.effect_descriptor.normalization_version, "eliot.opencode.arguments.v1")
    assert.equal(payload.effect_descriptor.tool, "bash")
    assert.deepEqual(payload.effect_descriptor.argument_keys, ["command"])
    assert.match(payload.effect_descriptor.argument_digest, /^[0-9a-f]{64}$/)
    assert.match(payload.effect_digest, /^[0-9a-f]{64}$/)
    assert.equal(text.includes("top-secret-command"), false)
    assert.equal(text.includes("unit-token"), false)

    response.writeHead(200, { "content-type": "application/json" })
    response.end(JSON.stringify({ decision: "allow" }))
  }, async (url) => {
    process.env.ELIOT_TASK_ID = "task-1"
    process.env.ELIOT_OPENCODE_BRIDGE_URL = url
    process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
    const plugin = await hooks()
    await plugin["tool.execute.before"](
      { tool: "bash", callID: "call-1", args: { command: "top-secret-command" } },
      {},
    )
  })
})

test("one transient HTTP retry preserves the exact idempotency key", async () => {
  const keys = []
  let calls = 0
  await withServer(async (request, response) => {
    for await (const _chunk of request) {
      // Drain request before responding.
    }
    keys.push(request.headers["idempotency-key"])
    calls += 1
    if (calls === 1) {
      response.writeHead(503)
      response.end()
      return
    }
    response.writeHead(200, { "content-type": "application/json" })
    response.end(JSON.stringify({ decision: "allow" }))
  }, async (url) => {
    process.env.ELIOT_TASK_ID = "task-1"
    process.env.ELIOT_OPENCODE_BRIDGE_URL = url
    process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
    const plugin = await hooks()
    await plugin["tool.execute.before"]({ tool: "write", callID: "call-retry", args: {} }, {})
  })

  assert.equal(calls, 2)
  assert.equal(keys[0], keys[1])
})

test("non-loopback bridge configuration fails closed for attached mutations", async () => {
  process.env.ELIOT_TASK_ID = "task-1"
  process.env.ELIOT_OPENCODE_BRIDGE_URL = "http://example.com:43123/"
  process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
  const plugin = await hooks()
  await assert.rejects(
    plugin["tool.execute.before"]({ tool: "patch", callID: "call-invalid", args: {} }, {}),
    /literal loopback address/,
  )
})

test("a redirecting bridge never re-issues the payload and never decides the gate", async () => {
  let redirectTargetHits = 0
  await withServer(async (request, response) => {
    for await (const _chunk of request) {
      // Drain before responding.
    }
    redirectTargetHits += 1
    response.writeHead(200, { "content-type": "application/json" })
    response.end(JSON.stringify({ decision: "allow" }))
  }, async (targetUrl) => {
    await withServer(async (request, response) => {
      for await (const _chunk of request) {
        // Drain before redirecting.
      }
      response.writeHead(308, { location: targetUrl })
      response.end()
    }, async (bridgeUrl) => {
      process.env.ELIOT_TASK_ID = "task-1"
      process.env.ELIOT_OPENCODE_BRIDGE_URL = bridgeUrl
      process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
      const plugin = await hooks()
      await assert.rejects(
        plugin["tool.execute.before"]({ tool: "bash", callID: "call-redirect", args: {} }, {}),
        /transport failed|bridge/,
      )
    })
  })

  assert.equal(redirectTargetHits, 0)
})

test("a non-JSON bridge response cannot decide the gate", async () => {
  await withServer(async (request, response) => {
    for await (const _chunk of request) {
      // Drain before responding.
    }
    response.writeHead(200, { "content-type": "text/html" })
    response.end('{"decision":"allow"}')
  }, async (url) => {
    process.env.ELIOT_TASK_ID = "task-1"
    process.env.ELIOT_OPENCODE_BRIDGE_URL = url
    process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
    const plugin = await hooks()
    await assert.rejects(
      plugin["tool.execute.before"]({ tool: "write", callID: "call-html", args: {} }, {}),
      /non-JSON content type/,
    )
  })
})

async function assertRejectedMediaType(contentType) {
  let cancellations = 0
  globalThis.fetch = async () => ({
    status: 200,
    ok: true,
    headers: new Headers({ "content-type": contentType }),
    body: {
      cancel: async () => {
        cancellations += 1
      },
    },
  })
  process.env.ELIOT_TASK_ID = "task-content-type"
  process.env.ELIOT_OPENCODE_BRIDGE_URL = "http://127.0.0.1:43123/"
  process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
  const plugin = await hooks()
  await assert.rejects(
    plugin["tool.execute.before"]({ tool: "write", callID: "call-content-type", args: {} }, {}),
    /non-JSON content type/,
  )
  assert.equal(cancellations, 1)
}

test("deceptive, combined, empty, and malformed JSON media types are rejected and canceled once", async () => {
  for (const contentType of [
    "application/jsonp",
    "application/json-seq",
    "application/json-evil",
    "application/json, text/plain",
    "",
    "; charset=utf-8",
    "application/json; charset",
    "application/json;=utf-8",
    "application/json; charset =utf-8",
    "application/json; charset= utf-8",
  ]) {
    await assertRejectedMediaType(contentType)
  }
})

test("each transient non-success response cancels its body exactly once", async () => {
  const cancellations = []
  let attempts = 0
  globalThis.fetch = async () => {
    attempts += 1
    cancellations.push(0)
    return {
      status: 503,
      ok: false,
      headers: new Headers(),
      body: {
        cancel: async () => {
          cancellations[attempts - 1] += 1
        },
      },
    }
  }
  process.env.ELIOT_TASK_ID = "task-status"
  process.env.ELIOT_OPENCODE_BRIDGE_URL = "http://127.0.0.1:43123/"
  process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
  const plugin = await hooks()
  await assert.rejects(
    plugin["tool.execute.before"]({ tool: "write", callID: "call-status", args: {} }, {}),
    /transient HTTP status 503/,
  )
  assert.deepEqual(cancellations, [1, 1])
})

test("an oversized JSON response cancels its reader exactly once", async () => {
  let cancellations = 0
  let reads = 0
  globalThis.fetch = async () => ({
    status: 200,
    ok: true,
    headers: new Headers({ "content-type": "application/json" }),
    body: {
      getReader: () => ({
        read: async () => {
          reads += 1
          return reads === 1
            ? { done: false, value: new Uint8Array(4097) }
            : { done: true, value: undefined }
        },
        cancel: async () => {
          cancellations += 1
        },
        releaseLock: () => {},
      }),
    },
  })
  process.env.ELIOT_TASK_ID = "task-output-limit"
  process.env.ELIOT_OPENCODE_BRIDGE_URL = "http://127.0.0.1:43123/"
  process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
  process.env.ELIOT_OPENCODE_BRIDGE_OUTPUT_LIMIT = "4096"
  const plugin = await hooks()
  await assert.rejects(
    plugin["tool.execute.before"]({ tool: "write", callID: "call-output-limit", args: {} }, {}),
    /response exceeded its bounded contract/,
  )
  assert.equal(reads, 1)
  assert.equal(cancellations, 1)
})

test("each retried failed JSON response read cancels its reader exactly once", async () => {
  const cancellations = []
  let attempts = 0
  globalThis.fetch = async () => {
    attempts += 1
    cancellations.push(0)
    return {
      status: 200,
      ok: true,
      headers: new Headers({ "content-type": "application/json" }),
      body: {
        getReader: () => ({
          read: async () => {
            throw new Error("simulated response read failure")
          },
          cancel: async () => {
            cancellations[attempts - 1] += 1
          },
          releaseLock: () => {},
        }),
      },
    }
  }
  process.env.ELIOT_TASK_ID = "task-read-failure"
  process.env.ELIOT_OPENCODE_BRIDGE_URL = "http://127.0.0.1:43123/"
  process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
  const plugin = await hooks()
  await assert.rejects(
    plugin["tool.execute.before"]({ tool: "write", callID: "call-read-failure", args: {} }, {}),
    /transport failed/,
  )
  assert.deepEqual(cancellations, [1, 1])
})

test("case-insensitive JSON media types accept valid parameters and whitespace", async () => {
  let reads = 0
  globalThis.fetch = async () => ({
    status: 200,
    ok: true,
    headers: new Headers({ "content-type": "  Application/JSON ; charset=utf-8; profile=\"unit\"  " }),
    body: {
      getReader: () => ({
        read: async () => {
          reads += 1
          return reads === 1
            ? { done: false, value: new TextEncoder().encode('{"decision":"allow"}') }
            : { done: true, value: undefined }
        },
        releaseLock: () => {},
      }),
    },
  })
  process.env.ELIOT_TASK_ID = "task-content-type"
  process.env.ELIOT_OPENCODE_BRIDGE_URL = "http://127.0.0.1:43123/"
  process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
  const plugin = await hooks()
  await plugin["tool.execute.before"]({ tool: "write", callID: "call-valid-content-type", args: {} }, {})
  assert.equal(reads, 2)
})

test("argument key count beyond 64 fails closed instead of truncating the action", async () => {
  await withServer(async (request, response) => {
    request.resume()
    response.writeHead(200, { "content-type": "application/json" })
    response.end(JSON.stringify({ decision: "allow" }))
  }, async (url) => {
    process.env.ELIOT_TASK_ID = "task-bounds"
    process.env.ELIOT_OPENCODE_BRIDGE_URL = url
    process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
    const args = Object.fromEntries(
      Array.from({ length: 65 }, (_, index) => [`key-${String(index).padStart(2, "0")}`, true]),
    )
    const plugin = await hooks()
    await assert.rejects(
      plugin["tool.execute.before"]({ tool: "write", callID: "call-65-keys", args }, {}),
      /key count exceeds its bounded contract/,
    )
  })
})

test("argument key length beyond 128 fails closed instead of dropping the key", async () => {
  await withServer(async (request, response) => {
    request.resume()
    response.writeHead(200, { "content-type": "application/json" })
    response.end(JSON.stringify({ decision: "allow" }))
  }, async (url) => {
    process.env.ELIOT_TASK_ID = "task-bounds"
    process.env.ELIOT_OPENCODE_BRIDGE_URL = url
    process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
    const accepted = "a".repeat(128)
    const rejected = "r".repeat(129)
    const plugin = await hooks()
    await assert.rejects(
      plugin["tool.execute.before"](
        { tool: "write", callID: "call-key-length", args: { [accepted]: true, [rejected]: true } },
        {},
      ),
      /key exceeds its bounded contract/,
    )
  })
})

test("the gate payload carries exactly the contract allowlist and nothing else", async () => {
  const contract = JSON.parse(
    await readFile(resolve("integrations/opencode/plugin-bridge-contract.json"), "utf8"),
  )
  const allowlist = [...contract.payload.allowlisted_fields].sort()

  await withServer(async (request, response) => {
    const chunks = []
    for await (const chunk of request) chunks.push(chunk)
    const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"))

    assert.deepEqual(Object.keys(payload).sort(), allowlist)

    response.writeHead(200, { "content-type": "application/json" })
    response.end(JSON.stringify({ decision: "allow" }))
  }, async (url) => {
    process.env.ELIOT_TASK_ID = "task-1"
    process.env.ELIOT_OPENCODE_BRIDGE_URL = url
    process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
    const plugin = await hooks()
    await plugin["tool.execute.before"](
      { tool: "edit", callID: "call-allowlist", args: { path: "a", content: "b" } },
      {},
    )
  })
})

test("string-shaped tool arguments fail closed instead of becoming one key per byte", async () => {
  process.env.ELIOT_TASK_ID = "task-1"
  const plugin = await hooks()
  await assert.rejects(
    plugin["tool.execute.before"](
      { tool: "bash", callID: "call-string-args", args: "top-secret-command" },
      {},
    ),
    /arguments must be a plain object/,
  )
})

test("effect binding is stable for key order and changes for argument values", async () => {
  const payloads = []
  await withServer(async (request, response) => {
    const chunks = []
    for await (const chunk of request) chunks.push(chunk)
    payloads.push(JSON.parse(Buffer.concat(chunks).toString("utf8")))
    response.writeHead(200, { "content-type": "application/json" })
    response.end(JSON.stringify({ decision: "allow" }))
  }, async (url) => {
    process.env.ELIOT_TASK_ID = "task-digest"
    process.env.ELIOT_OPENCODE_BRIDGE_URL = url
    process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
    const plugin = await hooks()
    await plugin["tool.execute.before"]({ tool: "bash", callID: "call-digest-1", args: { b: 2, a: 1 } }, {})
    await plugin["tool.execute.before"]({ tool: "bash", callID: "call-digest-2", args: { a: 1, b: 2 } }, {})
    await plugin["tool.execute.before"]({ tool: "bash", callID: "call-digest-3", args: { a: 1, b: 3 } }, {})
    await plugin["tool.execute.before"]({ tool: "bash", callID: "call-digest-4" }, { args: { a: 1, b: 2 } })
    await plugin["tool.execute.before"]({ tool: "write", callID: "call-digest-5", args: { a: 1, b: 2 } }, {})
  })

  assert.equal(payloads[0].effect_digest, payloads[1].effect_digest)
  assert.equal(payloads[0].effect_descriptor.argument_digest, payloads[1].effect_descriptor.argument_digest)
  assert.equal(payloads[0].effect_digest, payloads[3].effect_digest)
  assert.deepEqual(payloads[3].argument_keys, ["a", "b"])
  assert.notEqual(payloads[0].effect_digest, payloads[2].effect_digest)
  assert.notEqual(payloads[0].effect_descriptor.argument_digest, payloads[2].effect_descriptor.argument_digest)
  assert.notEqual(payloads[0].event_id, payloads[2].event_id)
  assert.notEqual(payloads[0].effect_digest, payloads[4].effect_digest)
})

test("read-only tools return deterministic skipped receipts through host-event transport", async () => {
  const payloads = []
  let resolvePayloads
  const received = new Promise((resolve) => {
    resolvePayloads = resolve
  })
  await withServer(async (request, response) => {
    const chunks = []
    for await (const chunk of request) chunks.push(chunk)
    const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"))
    payloads.push(payload)
    if (payloads.length === 2) resolvePayloads()
    response.writeHead(200, { "content-type": "application/json" })
    response.end(JSON.stringify({ decision: "recorded" }))
  }, async (url) => {
    process.env.ELIOT_TASK_ID = "task-read-only"
    process.env.ELIOT_OPENCODE_BRIDGE_URL = url
    process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
    const plugin = await hooks()
    const first = await plugin["tool.execute.before"]({ tool: "read", args: { path: "README.md" } }, {})
    const second = await plugin["tool.execute.before"]({ tool: "read", args: { path: "README.md" } }, {})
    await received

    assert.deepEqual(first, second)
    assert.equal(first.decision, "skipped")
    assert.equal(first.reason, "read_only_tool")
    assert.equal(first.tool, "read")
    assert.deepEqual(first.effect_descriptor.argument_keys, ["path"])
    assert.match(first.effect_descriptor.argument_digest, /^[0-9a-f]{64}$/)
    assert.match(first.effect_digest, /^[0-9a-f]{64}$/)
    assert.equal(payloads[0].event_kind, "tool.execute.skipped")
    assert.equal(payloads[0].effect_digest, first.effect_digest)
    assert.equal(JSON.stringify(payloads).includes("README.md"), false)
    assert.equal(payloads[0].event_id, payloads[1].event_id)
  })
})

test("aliases and unknown tools fail closed before bridge dispatch", async () => {
  process.env.ELIOT_TASK_ID = "task-classification"
  const plugin = await hooks()
  for (const tool of ["Bash", " bash", "bash ", "bash.foo", "apply_patch", "notebook", "unknown_tool"]) {
    await assert.rejects(
      plugin["tool.execute.before"]({ tool, args: {} }, {}),
      /cannot classify this OpenCode tool/,
    )
  }
})

test("unsupported argument values fail closed before bridge dispatch", async () => {
  let bridgeCalls = 0
  await withServer(async (request, response) => {
    bridgeCalls += 1
    request.resume()
    response.writeHead(200, { "content-type": "application/json" })
    response.end(JSON.stringify({ decision: "allow" }))
  }, async (url) => {
    process.env.ELIOT_TASK_ID = "task-unbindable"
    process.env.ELIOT_OPENCODE_BRIDGE_URL = url
    process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
    const plugin = await hooks()
    const cyclic = {}
    cyclic.self = cyclic
    const accessor = {}
    Object.defineProperty(accessor, "value", { enumerable: true, get: () => "coerced" })
    const sparse = []
    sparse[1] = "coerced"
    const cases = [
      { value: () => "function" },
      { value: undefined },
      { value: Symbol("secret") },
      { value: 1n },
      { value: Number.NaN },
      { value: Number.POSITIVE_INFINITY },
      { value: new Date(0) },
      { value: new Map([ ["key", "value"] ]) },
      { value: sparse },
      { value: accessor },
      { value: cyclic },
    ]
    for (const args of cases) {
      await assert.rejects(
        plugin["tool.execute.before"]({ tool: "write", args }, {}),
        /cannot bind exact action arguments/,
      )
    }
  })
  assert.equal(bridgeCalls, 0)
})

test("oversized action arguments fail closed before bridge dispatch", async () => {
  process.env.ELIOT_TASK_ID = "task-input-limit"
  const plugin = await hooks()
  await assert.rejects(
    plugin["tool.execute.before"]({ tool: "bash", args: { command: "x".repeat(20_000) } }, {}),
    /effect descriptor exceeds its bounded contract/,
  )
})

test("configured HTTP outage never crosses transport into the legacy process bridge", async () => {
  let legacySpawns = 0
  globalThis.Bun = {
    spawn: () => {
      legacySpawns += 1
      throw new Error("must not run")
    },
  }
  process.env.ELIOT_TASK_ID = "task-1"
  process.env.ELIOT_OPENCODE_BRIDGE_URL = "http://127.0.0.1:1/"
  process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
  process.env.ELIOT_OPENCODE_BRIDGE_TIMEOUT_MS = "500"
  process.env.ELIOT_GOVERNOR_EXE = "C:/eliot-governor.exe"
  const plugin = await hooks()
  await assert.rejects(
    plugin["tool.execute.before"]({ tool: "edit", callID: "call-outage", args: {} }, {}),
    /transport failed|timed out/,
  )
  assert.equal(legacySpawns, 0)
})
