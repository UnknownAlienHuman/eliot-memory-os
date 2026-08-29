const MUTATING_TOOLS = new Set(["bash", "edit", "write", "patch", "notebook"])
const USEFUL_EVENTS = new Set([
  "session.created",
  "session.compacted",
  "session.error",
  "session.idle",
  "permission.asked",
  "permission.replied",
  "file.edited",
  "todo.updated",
])

const BRIDGE_ENV_KEYS = [
  "APPDATA",
  "COMSPEC",
  "HOMEDRIVE",
  "HOMEPATH",
  "LOCALAPPDATA",
  "PATH",
  "PATHEXT",
  "SystemRoot",
  "TEMP",
  "TMP",
  "USERPROFILE",
  "WINDIR",
  "ELIOT_AUTHORITY_EPOCH",
  "ELIOT_GOVERNOR_EXE",
  "ELIOT_HOST_PROFILE",
  "ELIOT_INSTALLATION_ID",
  "ELIOT_SESSION_ID",
  "ELIOT_STATE_FENCE",
  "ELIOT_TASK_ID",
  "ELIOT_WORKSCOPE_ID",
  "ELIOT_WORK_ITEM_ID",
]

function boundedInteger(name, fallback, minimum, maximum) {
  const parsed = Number.parseInt(process.env[name] ?? "", 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(maximum, Math.max(minimum, parsed))
}

const BRIDGE_TIMEOUT_MS = boundedInteger("ELIOT_OPENCODE_BRIDGE_TIMEOUT_MS", 5000, 500, 15000)
const MAX_PASSIVE_QUEUE = boundedInteger("ELIOT_OPENCODE_PASSIVE_QUEUE_LIMIT", 64, 1, 256)
const MAX_BRIDGE_OUTPUT_BYTES = boundedInteger("ELIOT_OPENCODE_BRIDGE_OUTPUT_LIMIT", 64 * 1024, 4096, 256 * 1024)

let nextSequence = 0
let passiveDepth = 0
let passiveQueue = Promise.resolve()

function attachedTask() {
  return Boolean(process.env.ELIOT_TASK_ID)
}

function bridgeExecutable() {
  if (process.env.ELIOT_GOVERNOR_EXE) return process.env.ELIOT_GOVERNOR_EXE
  if (!process.env.LOCALAPPDATA) return null
  return `${process.env.LOCALAPPDATA}/Eliot/host-integrations/opencode/bin/eliot-governor.exe`
}

function bridgeEnvironment() {
  const env = {}
  for (const key of BRIDGE_ENV_KEYS) {
    const value = process.env[key]
    if (typeof value === "string") env[key] = value
  }
  return env
}

function eventIdentity(sequence) {
  const randomUUID = globalThis.crypto?.randomUUID
  if (typeof randomUUID === "function") return randomUUID.call(globalThis.crypto)
  return `opencode-${Date.now()}-${sequence}`
}

function compactEvent(kind, input = {}, output = {}) {
  const event = input.event ?? input
  const properties = event.properties ?? {}
  const sequence = ++nextSequence
  return {
    event_id: eventIdentity(sequence),
    sequence,
    emitted_at: new Date().toISOString(),
    event_kind: kind,
    vendor_event_kind: event.type ?? kind,
    host_session_id: input.sessionID ?? properties.sessionID ?? properties.session_id ?? null,
    task_id: process.env.ELIOT_TASK_ID ?? null,
    work_item_id: process.env.ELIOT_WORK_ITEM_ID ?? null,
    tool: input.tool ?? properties.tool ?? null,
    changed_path: properties.file ?? properties.path ?? null,
    argument_keys: Object.keys(output.args ?? {}),
    attached_task: attachedTask(),
  }
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

async function readBounded(stream, maximumBytes) {
  if (!stream) return { text: "", truncated: false }

  const reader = stream.getReader()
  const decoder = new TextDecoder()
  let text = ""
  let total = 0
  let truncated = false

  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      const remaining = maximumBytes - total
      if (remaining <= 0) {
        truncated = true
        await reader.cancel()
        break
      }
      const accepted = value.byteLength > remaining ? value.subarray(0, remaining) : value
      total += accepted.byteLength
      text += decoder.decode(accepted, { stream: true })
      if (accepted.byteLength !== value.byteLength) {
        truncated = true
        await reader.cancel()
        break
      }
    }
    text += decoder.decode()
  } finally {
    reader.releaseLock()
  }

  return { text, truncated }
}

async function waitForExit(child, timeoutMilliseconds) {
  let timeoutId
  const timeout = new Promise((resolve) => {
    timeoutId = setTimeout(() => resolve({ timedOut: true, status: null }), timeoutMilliseconds)
  })
  const exited = child.exited.then((status) => ({ timedOut: false, status }))
  const result = await Promise.race([exited, timeout])
  clearTimeout(timeoutId)

  if (result.timedOut) {
    try {
      child.kill()
    } catch {
      // Process cleanup is still checked by the caller's failure disposition.
    }
    await Promise.race([child.exited.catch(() => null), sleep(500)])
  }
  return result
}

function bridgeFailure(required, reason) {
  if (required) throw new Error(reason)
  return { decision: "degraded", reason }
}

async function invokeBridge(kind, input, output, { required = false } = {}) {
  const executable = bridgeExecutable()
  if (!executable) {
    return bridgeFailure(required, "ELIOT ActionGate is unavailable: bridge executable is not configured")
  }

  let child
  try {
    child = Bun.spawn({
      cmd: [executable, "host", "event", "--host", "opencode", "--event", kind],
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
      env: bridgeEnvironment(),
    })
  } catch {
    return bridgeFailure(required, "ELIOT lifecycle bridge could not start")
  }

  const stdout = readBounded(child.stdout, MAX_BRIDGE_OUTPUT_BYTES)
  const stderr = readBounded(child.stderr, MAX_BRIDGE_OUTPUT_BYTES)

  try {
    child.stdin.write(JSON.stringify(compactEvent(kind, input, output)))
    child.stdin.end()
  } catch {
    try {
      child.kill()
    } catch {
      // The required path still fails closed below.
    }
    await Promise.allSettled([stdout, stderr])
    return bridgeFailure(required, "ELIOT lifecycle bridge input failed")
  }

  const exit = await waitForExit(child, BRIDGE_TIMEOUT_MS)
  const [stdoutResult, stderrResult] = await Promise.all([stdout, stderr])

  if (exit.timedOut) {
    return bridgeFailure(required, "ELIOT lifecycle bridge timed out")
  }
  if (stdoutResult.truncated || stderrResult.truncated) {
    return bridgeFailure(required, "ELIOT lifecycle bridge output exceeded its bounded contract")
  }
  if (exit.status !== 0) {
    return bridgeFailure(required, `ELIOT lifecycle bridge exited with status ${exit.status}`)
  }

  try {
    return JSON.parse(stdoutResult.text)
  } catch {
    return bridgeFailure(required, "ELIOT lifecycle bridge returned invalid JSON")
  }
}

async function log(client, level, message, extra = {}) {
  if (!client?.app?.log) return
  try {
    await client.app.log({
      body: {
        service: "eliot-opencode-plugin",
        level,
        message,
        extra,
      },
    })
  } catch {
    // Host logging is advisory and must not recurse into bridge dispatch.
  }
}

function enqueuePassive(client, kind, input, output) {
  if (passiveDepth >= MAX_PASSIVE_QUEUE) {
    void log(client, "warn", "Dropped passive ELIOT event because the bounded queue is full", {
      kind,
      queue_limit: MAX_PASSIVE_QUEUE,
    })
    return
  }

  passiveDepth += 1
  const run = async () => {
    try {
      const result = await invokeBridge(kind, input, output)
      if (result.decision === "degraded") {
        await log(client, "warn", "ELIOT passive lifecycle dispatch degraded", { kind, reason: result.reason })
      }
    } catch {
      await log(client, "warn", "ELIOT passive lifecycle dispatch failed", { kind })
    } finally {
      passiveDepth -= 1
    }
  }
  passiveQueue = passiveQueue.then(run, run)
}

async function requireMutationGate(input, output) {
  const gate = await invokeBridge("tool.execute.before", input, output, { required: true })
  if (gate.decision === "deny") {
    throw new Error(gate.reason ?? "ELIOT ActionGate denied mutation")
  }
  if (!new Set(["recorded", "allow", "allowed", "pass"]).has(gate.decision)) {
    throw new Error("ELIOT ActionGate returned no explicit usable decision")
  }
}

export const EliotPlugin = async ({ client } = {}) => ({
  event: async ({ event }) => {
    if (USEFUL_EVENTS.has(event.type)) enqueuePassive(client, event.type, { event }, {})
  },
  "tool.execute.before": async (input, output) => {
    if (!attachedTask() || !MUTATING_TOOLS.has(input.tool)) return
    await requireMutationGate(input, output)
  },
  "tool.execute.after": async (input, output) => {
    enqueuePassive(client, "tool.execute.after", input, output)
  },
})
