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
  "ELIOT_GOVERNOR_EXE",
]

function cleanEnvironment() {
  for (const key of ENV_KEYS) delete process.env[key]
  delete globalThis.Bun
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
