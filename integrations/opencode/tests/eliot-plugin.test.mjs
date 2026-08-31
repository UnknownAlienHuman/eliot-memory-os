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

test("normalized argument keys keep exactly 64 entries and reject the 65th", async () => {
  let payload
  await withServer(async (request, response) => {
    const chunks = []
    for await (const chunk of request) chunks.push(chunk)
    payload = JSON.parse(Buffer.concat(chunks).toString("utf8"))
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
    await plugin["tool.execute.before"]({ tool: "write", callID: "call-64-keys", args }, {})
  })
  assert.equal(payload.argument_keys.length, 64)
  assert.equal(payload.argument_keys.includes("key-64"), false)
  assert.equal(payload.argument_keys.includes("key-00"), true)
})

test("normalized argument keys accept 128 characters and reject 129", async () => {
  let payload
  await withServer(async (request, response) => {
    const chunks = []
    for await (const chunk of request) chunks.push(chunk)
    payload = JSON.parse(Buffer.concat(chunks).toString("utf8"))
    response.writeHead(200, { "content-type": "application/json" })
    response.end(JSON.stringify({ decision: "allow" }))
  }, async (url) => {
    process.env.ELIOT_TASK_ID = "task-bounds"
    process.env.ELIOT_OPENCODE_BRIDGE_URL = url
    process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
    const accepted = "a".repeat(128)
    const rejected = "r".repeat(129)
    const plugin = await hooks()
    await plugin["tool.execute.before"](
      { tool: "write", callID: "call-key-length", args: { [accepted]: true, [rejected]: true } },
      {},
    )
  })
  assert.equal(payload.argument_keys.includes("a".repeat(128)), true)
  assert.equal(payload.argument_keys.includes("r".repeat(129)), false)
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

test("string-shaped tool arguments never become one key per byte", async () => {
  await withServer(async (request, response) => {
    const chunks = []
    for await (const chunk of request) chunks.push(chunk)
    const text = Buffer.concat(chunks).toString("utf8")
    const payload = JSON.parse(text)

    assert.deepEqual(payload.argument_keys, [])
    assert.equal(text.includes("top-secret-command"), false)

    response.writeHead(200, { "content-type": "application/json" })
    response.end(JSON.stringify({ decision: "allow" }))
  }, async (url) => {
    process.env.ELIOT_TASK_ID = "task-1"
    process.env.ELIOT_OPENCODE_BRIDGE_URL = url
    process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
    const plugin = await hooks()
    await plugin["tool.execute.before"](
      { tool: "bash", callID: "call-string-args", args: "top-secret-command" },
      {},
    )
  })
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
