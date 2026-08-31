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

async function configureAttachedGate(url) {
  process.env.ELIOT_TASK_ID = "task-content-type"
  process.env.ELIOT_OPENCODE_BRIDGE_URL = url
  process.env.ELIOT_OPENCODE_BRIDGE_TOKEN = "unit-token"
  return hooks()
}

test.afterEach(cleanEnvironment)

test("a deceptive application/jsonp media type cannot decide the gate", async () => {
  await withServer(async (request, response) => {
    for await (const _chunk of request) {
      // Drain before responding.
    }
    response.writeHead(200, { "content-type": "application/jsonp" })
    response.end('{"decision":"allow"}')
  }, async (url) => {
    const plugin = await configureAttachedGate(url)
    await assert.rejects(
      plugin["tool.execute.before"](
        { tool: "write", callID: "call-deceptive-json-prefix", args: {} },
        {},
      ),
      /non-JSON content type/,
    )
  })
})

test("application/json with a charset parameter remains admissible", async () => {
  await withServer(async (request, response) => {
    for await (const _chunk of request) {
      // Drain before responding.
    }
    response.writeHead(200, { "content-type": "Application/JSON ; charset=utf-8" })
    response.end('{"decision":"allow"}')
  }, async (url) => {
    const plugin = await configureAttachedGate(url)
    await plugin["tool.execute.before"](
      { tool: "write", callID: "call-parameterized-json", args: {} },
      {},
    )
  })
})
