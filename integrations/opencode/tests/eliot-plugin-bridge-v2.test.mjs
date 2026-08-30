import assert from "node:assert/strict"
import { randomUUID } from "node:crypto"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import http from "node:http"
import os from "node:os"
import path from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

const here = path.dirname(fileURLToPath(import.meta.url))
const pluginPath = path.resolve(here, "../plugins/eliot.js")
const pluginSource = await readFile(pluginPath, "utf8")
const ENV_KEYS = [
  "ELIOT_OPENCODE_BRIDGE_URL",
  "ELIOT_OPENCODE_BRIDGE_TOKEN_FILE",
  "ELIOT_OPENCODE_BRIDGE_TIMEOUT_MS",
  "ELIOT_OPENCODE_PASSIVE_QUEUE_LIMIT",
  "ELIOT_TASK_ID",
  "ELIOT_WORK_ITEM_ID",
  "ELIOT_SESSION_ID",
]

async function loadPlugin() {
  const encoded = Buffer.from(pluginSource).toString("base64")
  const module = await import(`data:text/javascript;base64,${encoded}#${randomUUID()}`)
  return module.EliotPlugin
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

async function waitFor(predicate, timeoutMilliseconds = 3000) {
  const deadline = Date.now() + timeoutMilliseconds
  while (Date.now() < deadline) {
    if (predicate()) return
    await sleep(15)
  }
  throw new Error("condition was not observed before timeout")
}

async function withEnvironment(values, operation) {
  const previous = new Map(ENV_KEYS.map((key) => [key, process.env[key]]))
  for (const key of ENV_KEYS) delete process.env[key]
  for (const [key, value] of Object.entries(values)) {
    if (value != null) process.env[key] = String(value)
  }
  try {
    return await operation()
  } finally {
    for (const key of ENV_KEYS) {
      const value = previous.get(key)
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
}

async function makeTokenFile() {
  const directory = await mkdtemp(path.join(os.tmpdir(), "eliot-opencode-token-"))
  const tokenFile = path.join(directory, "bridge.token")
  await writeFile(tokenFile, "test-bridge-token\n", { encoding: "utf8", mode: 0o600 })
  return {
    tokenFile,
    cleanup: () => rm(directory, { recursive: true, force: true }),
  }
}

async function makeServer(handler) {
  const requests = []
  const server = http.createServer(async (request, response) => {
    const chunks = []
    for await (const chunk of request) chunks.push(chunk)
    const body = Buffer.concat(chunks).toString("utf8")
    const record = {
      method: request.method,
      url: request.url,
      headers: request.headers,
      body,
      parsed: body ? JSON.parse(body) : null,
    }
    requests.push(record)
    await handler({ request, response, record, index: requests.length - 1 })
  })
  await new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", resolve)
  })
  const address = server.address()
  if (!address || typeof address === "string") throw new Error("server did not expose a port")
  return {
    requests,
    url: `http://127.0.0.1:${address.port}`,
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  }
}

function jsonResponse(response, status, value) {
  const body = JSON.stringify(value)
  response.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(body) })
  response.end(body)
}

function client(logs) {
  return {
    app: {
      log: async ({ body }) => logs.push(body),
    },
  }
}

test("passive event uses authenticated loopback transport and compact metadata", async () => {
  const token = await makeTokenFile()
  const server = await makeServer(async ({ response }) => jsonResponse(response, 200, { decision: "recorded" }))
  const logs = []
  try {
    await withEnvironment({
      ELIOT_OPENCODE_BRIDGE_URL: server.url,
      ELIOT_OPENCODE_BRIDGE_TOKEN_FILE: token.tokenFile,
      ELIOT_TASK_ID: "task-1",
      ELIOT_WORK_ITEM_ID: "work-1",
      ELIOT_SESSION_ID: "eliot-session-1",
    }, async () => {
      const EliotPlugin = await loadPlugin()
      const plugin = await EliotPlugin({ client: client(logs) })
      await plugin.event({
        event: {
          type: "file.edited",
          id: "native-event-1",
          properties: {
            sessionID: "host-session-1",
            file: "src/main.rs",
            prompt: "MUST_NOT_LEAK",
            output: "MUST_NOT_LEAK",
            token: "MUST_NOT_LEAK",
            stack: "MUST_NOT_LEAK",
          },
        },
      })
      await waitFor(() => server.requests.length === 1)
    })

    const request = server.requests[0]
    assert.equal(request.method, "POST")
    assert.equal(request.url, "/v1/host-events")
    assert.equal(request.headers.authorization, "Bearer test-bridge-token")
    assert.equal(request.headers["idempotency-key"], request.parsed.event_id)
    assert.equal(request.parsed.schema_version, "eliot.opencode-host-event.v2")
    assert.equal(request.parsed.task_id, "task-1")
    assert.equal(request.parsed.work_item_id, "work-1")
    assert.equal(request.parsed.attached_task, true)
    assert.deepEqual(request.parsed.metadata, {
      session_id: "host-session-1",
      changed_path: "src/main.rs",
    })
    for (const forbidden of ["MUST_NOT_LEAK", "prompt", "output", "token", "stack", "properties"]) {
      assert.equal(request.body.includes(forbidden), false)
    }
  } finally {
    await server.close()
    await token.cleanup()
  }
})

test("transient retry preserves event identity and strips argument values and sensitive keys", async () => {
  const token = await makeTokenFile()
  const server = await makeServer(async ({ response, index }) => {
    if (index === 0) jsonResponse(response, 503, { reason_code: "TRANSIENT" })
    else jsonResponse(response, 200, { decision: "allow", reason_code: "RECORDED" })
  })
  try {
    await withEnvironment({
      ELIOT_OPENCODE_BRIDGE_URL: server.url,
      ELIOT_OPENCODE_BRIDGE_TOKEN_FILE: token.tokenFile,
      ELIOT_TASK_ID: "task-2",
      ELIOT_OPENCODE_BRIDGE_TIMEOUT_MS: "2000",
    }, async () => {
      const EliotPlugin = await loadPlugin()
      const plugin = await EliotPlugin({ client: client([]) })
      await plugin["tool.execute.before"](
        {
          tool: "bash",
          callID: "call-2",
          args: {
            command: "echo SUPER_SECRET_VALUE",
            harmless: "visible-only-as-key",
            api_key: "SUPER_SECRET_VALUE",
            password: "SUPER_SECRET_VALUE",
          },
        },
        { args: { command: "echo SUPER_SECRET_VALUE" }, output: "SUPER_SECRET_VALUE" },
      )
    })
    assert.equal(server.requests.length, 2)
    assert.equal(server.requests[0].body, server.requests[1].body)
    assert.equal(server.requests[0].headers["idempotency-key"], server.requests[1].headers["idempotency-key"])
    const body = server.requests[0].body
    assert.equal(body.includes("SUPER_SECRET_VALUE"), false)
    assert.deepEqual(server.requests[0].parsed.metadata.argument_keys, ["command", "harmless"])
    assert.equal(body.includes("api_key"), false)
    assert.equal(body.includes("password"), false)
  } finally {
    await server.close()
    await token.cleanup()
  }
})

test("attached mutating task fails closed on bridge outage", async () => {
  const token = await makeTokenFile()
  try {
    await withEnvironment({
      ELIOT_OPENCODE_BRIDGE_URL: "http://127.0.0.1:1",
      ELIOT_OPENCODE_BRIDGE_TOKEN_FILE: token.tokenFile,
      ELIOT_TASK_ID: "task-3",
      ELIOT_OPENCODE_BRIDGE_TIMEOUT_MS: "500",
    }, async () => {
      const EliotPlugin = await loadPlugin()
      const plugin = await EliotPlugin({ client: client([]) })
      await assert.rejects(
        plugin["tool.execute.before"]({ tool: "write", callID: "call-3", args: { path: "x" } }, {}),
        /ActionGate|bridge request failed|unavailable/i,
      )
    })
  } finally {
    await token.cleanup()
  }
})

test("explicit deny blocks an attached mutation", async () => {
  const token = await makeTokenFile()
  const server = await makeServer(async ({ response }) => jsonResponse(response, 200, { decision: "deny" }))
  try {
    await withEnvironment({
      ELIOT_OPENCODE_BRIDGE_URL: server.url,
      ELIOT_OPENCODE_BRIDGE_TOKEN_FILE: token.tokenFile,
      ELIOT_TASK_ID: "task-4",
    }, async () => {
      const EliotPlugin = await loadPlugin()
      const plugin = await EliotPlugin({ client: client([]) })
      await assert.rejects(
        plugin["tool.execute.before"]({ tool: "edit", callID: "call-4", args: {} }, {}),
        /denied/i,
      )
    })
  } finally {
    await server.close()
    await token.cleanup()
  }
})

test("non-loopback URL is rejected before network access", async () => {
  const token = await makeTokenFile()
  try {
    await withEnvironment({
      ELIOT_OPENCODE_BRIDGE_URL: "http://example.com",
      ELIOT_OPENCODE_BRIDGE_TOKEN_FILE: token.tokenFile,
      ELIOT_TASK_ID: "task-5",
    }, async () => {
      const EliotPlugin = await loadPlugin()
      const plugin = await EliotPlugin({ client: client([]) })
      await assert.rejects(
        plugin["tool.execute.before"]({ tool: "patch", callID: "call-5", args: {} }, {}),
        /not configured|unavailable/i,
      )
    })
  } finally {
    await token.cleanup()
  }
})

test("invalid and oversized bridge responses fail closed", async () => {
  const token = await makeTokenFile()
  for (const mode of ["invalid", "oversized"]) {
    const server = await makeServer(async ({ response }) => {
      if (mode === "invalid") {
        response.writeHead(200, { "content-type": "application/json" })
        response.end("not-json")
      } else {
        const body = JSON.stringify({ decision: "allow", padding: "x".repeat(70 * 1024) })
        response.writeHead(200, { "content-type": "application/json" })
        response.end(body)
      }
    })
    try {
      await withEnvironment({
        ELIOT_OPENCODE_BRIDGE_URL: server.url,
        ELIOT_OPENCODE_BRIDGE_TOKEN_FILE: token.tokenFile,
        ELIOT_TASK_ID: `task-${mode}`,
      }, async () => {
        const EliotPlugin = await loadPlugin()
        const plugin = await EliotPlugin({ client: client([]) })
        await assert.rejects(
          plugin["tool.execute.before"]({ tool: "bash", callID: `call-${mode}`, args: {} }, {}),
        )
      })
    } finally {
      await server.close()
    }
  }
  await token.cleanup()
})

test("bounded passive queue drops overflow without blocking host callback", async () => {
  const token = await makeTokenFile()
  let releaseFirst
  const gate = new Promise((resolve) => { releaseFirst = resolve })
  const server = await makeServer(async ({ response, index }) => {
    if (index === 0) await gate
    jsonResponse(response, 200, { decision: "recorded" })
  })
  const logs = []
  try {
    await withEnvironment({
      ELIOT_OPENCODE_BRIDGE_URL: server.url,
      ELIOT_OPENCODE_BRIDGE_TOKEN_FILE: token.tokenFile,
      ELIOT_OPENCODE_PASSIVE_QUEUE_LIMIT: "1",
    }, async () => {
      const EliotPlugin = await loadPlugin()
      const plugin = await EliotPlugin({ client: client(logs) })
      await plugin.event({ event: { type: "session.created", id: "event-a", properties: {} } })
      await plugin.event({ event: { type: "session.idle", id: "event-b", properties: {} } })
      await waitFor(() => server.requests.length === 1)
      await waitFor(() => logs.some((entry) => entry.message.includes("queue is full")))
      releaseFirst()
      await sleep(50)
    })
    assert.equal(server.requests.length, 1)
  } finally {
    releaseFirst?.()
    await server.close()
    await token.cleanup()
  }
})
