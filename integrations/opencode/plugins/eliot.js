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
  "ELIOT_WORK_LEASE_ID",
]

function boundedInteger(name, fallback, minimum, maximum) {
  const parsed = Number.parseInt(process.env[name] ?? "", 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(maximum, Math.max(minimum, parsed))
}

const BRIDGE_TIMEOUT_MS = boundedInteger("ELIOT_OPENCODE_BRIDGE_TIMEOUT_MS", 5000, 500, 15000)
const STREAM_SETTLE_MS = boundedInteger("ELIOT_OPENCODE_STREAM_SETTLE_MS", 750, 100, 3000)
const MAX_PASSIVE_QUEUE = boundedInteger("ELIOT_OPENCODE_PASSIVE_QUEUE_LIMIT", 64, 1, 256)
const MAX_BRIDGE_OUTPUT_BYTES = boundedInteger(
  "ELIOT_OPENCODE_BRIDGE_OUTPUT_LIMIT",
  64 * 1024,
  4096,
  256 * 1024,
)
const OVERFLOW_LOG_COOLDOWN_MS = boundedInteger(
  "ELIOT_OPENCODE_OVERFLOW_LOG_COOLDOWN_MS",
  5000,
  500,
  60000,
)

let nextSequence = 0
let passiveDepth = 0
let passiveQueue = Promise.resolve()
let droppedPassiveEvents = 0
let overflowLogScheduled = false
let lastDroppedEventKind = null

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

function firstString(...values) {
  return values.find((value) => typeof value === "string" && value.length > 0) ?? null
}

function firstInteger(...values) {
  return values.find((value) => Number.isSafeInteger(value) && value >= 0) ?? null
}

function canonicalIdentityMaterial(value) {
  if (Array.isArray(value)) return value.map(canonicalIdentityMaterial)
  if (!value || typeof value !== "object") return value
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonicalIdentityMaterial(value[key])]),
  )
}

async function sha256Hex(value) {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) return null
  const encoded = new TextEncoder().encode(value)
  const digest = await subtle.digest("SHA-256", encoded)
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")
}

async function compactEvent(kind, input = {}, output = {}) {
  const event = input.event ?? input
  const properties = event.properties ?? {}
  const nativeSequence = firstInteger(
    event.sequence,
    event.seq,
    properties.sequence,
    properties.seq,
  )
  const sequence = nativeSequence ?? ++nextSequence
  const hostSessionId = firstString(
    input.sessionID,
    input.sessionId,
    properties.sessionID,
    properties.sessionId,
    properties.session_id,
  )
  const vendorEventKind = firstString(event.type, kind) ?? kind
  const nativeEventId = firstString(
    event.id,
    event.eventID,
    event.eventId,
    properties.id,
    properties.eventID,
    properties.eventId,
    properties.messageID,
    properties.messageId,
    input.callID,
    input.callId,
    input.toolCallID,
    input.toolCallId,
    output.callID,
    output.callId,
  )
  const tool = firstString(input.tool, properties.tool)
  const changedPath = firstString(properties.file, properties.path)
  const emittedAt =
    firstString(event.emitted_at, event.timestamp, event.time, properties.emitted_at, properties.timestamp) ??
    new Date().toISOString()
  const argumentKeys = Object.keys(output.args ?? {}).sort()
  const identityMaterial = JSON.stringify(
    canonicalIdentityMaterial({
      vendor_event_kind: vendorEventKind,
      native_event_id: nativeEventId,
      native_sequence: nativeSequence,
      host_session_id: hostSessionId,
      tool,
      changed_path: changedPath,
      argument_keys: argumentKeys,
      emitted_at: emittedAt,
      fallback_sequence: nativeEventId || nativeSequence !== null ? null : sequence,
    }),
  )
  const identityDigest = await sha256Hex(identityMaterial)
  const eventId =
    nativeEventId !== null
      ? `opencode:${vendorEventKind}:${nativeEventId}`
      : identityDigest !== null
        ? `opencode:sha256:${identityDigest}`
        : `opencode:${hostSessionId ?? "unknown"}:${vendorEventKind}:${sequence}`

  return {
    event_id: eventId,
    sequence,
    emitted_at: emittedAt,
    event_kind: kind,
    vendor_event_kind: vendorEventKind,
    host_session_id: hostSessionId,
    task_id: process.env.ELIOT_TASK_ID ?? null,
    work_item_id: process.env.ELIOT_WORK_ITEM_ID ?? null,
    tool,
    changed_path: changedPath,
    argument_keys: argumentKeys,
    attached_task: attachedTask(),
  }
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

function boundedDrain(stream, maximumBytes) {
  if (!stream) {
    return {
      promise: Promise.resolve({ text: "", truncated: false, timedOut: false }),
      cancel: () => {},
    }
  }

  const reader = stream.getReader()
  const decoder = new TextDecoder()
  let settled = false

  const promise = (async () => {
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
          void reader.cancel("ELIOT bridge output limit reached").catch(() => {})
          break
        }
        const accepted = value.byteLength > remaining ? value.subarray(0, remaining) : value
        total += accepted.byteLength
        text += decoder.decode(accepted, { stream: true })
        if (accepted.byteLength !== value.byteLength) {
          truncated = true
          void reader.cancel("ELIOT bridge output limit reached").catch(() => {})
          break
        }
      }
      text += decoder.decode()
      return { text, truncated, timedOut: false }
    } finally {
      settled = true
      reader.releaseLock()
    }
  })()

  promise.catch(() => {})
  return {
    promise,
    cancel: (reason) => {
      if (!settled) void reader.cancel(reason).catch(() => {})
    },
  }
}

async function settleDrain(drain, timeoutMilliseconds) {
  let timeoutId
  const timeout = new Promise((resolve) => {
    timeoutId = setTimeout(() => {
      drain.cancel("ELIOT bridge stream settlement deadline")
      resolve({ text: "", truncated: false, timedOut: true })
    }, timeoutMilliseconds)
  })
  const result = await Promise.race([drain.promise, timeout])
  clearTimeout(timeoutId)
  return result
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
    await Promise.race([child.exited.catch(() => null), sleep(STREAM_SETTLE_MS)])
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

  const stdout = boundedDrain(child.stdout, MAX_BRIDGE_OUTPUT_BYTES)
  const stderr = boundedDrain(child.stderr, MAX_BRIDGE_OUTPUT_BYTES)

  try {
    const payload = JSON.stringify(await compactEvent(kind, input, output))
    await child.stdin.write(payload)
    await child.stdin.end()
  } catch {
    try {
      child.kill()
    } catch {
      // The required path still fails closed below.
    }
    stdout.cancel("ELIOT lifecycle bridge input failed")
    stderr.cancel("ELIOT lifecycle bridge input failed")
    await Promise.allSettled([
      settleDrain(stdout, STREAM_SETTLE_MS),
      settleDrain(stderr, STREAM_SETTLE_MS),
    ])
    return bridgeFailure(required, "ELIOT lifecycle bridge input failed")
  }

  const exit = await waitForExit(child, BRIDGE_TIMEOUT_MS)
  if (exit.timedOut) {
    stdout.cancel("ELIOT lifecycle bridge timed out")
    stderr.cancel("ELIOT lifecycle bridge timed out")
  }
  const [stdoutResult, stderrResult] = await Promise.all([
    settleDrain(stdout, STREAM_SETTLE_MS),
    settleDrain(stderr, STREAM_SETTLE_MS),
  ])

  if (exit.timedOut) {
    return bridgeFailure(required, "ELIOT lifecycle bridge timed out")
  }
  if (stdoutResult.timedOut || stderrResult.timedOut) {
    return bridgeFailure(required, "ELIOT lifecycle bridge streams did not close within the bounded contract")
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

function armOverflowLog(client) {
  if (overflowLogScheduled) return

  overflowLogScheduled = true
  setTimeout(() => {
    const dropped = droppedPassiveEvents
    const lastKind = lastDroppedEventKind
    droppedPassiveEvents = 0
    lastDroppedEventKind = null
    void log(client, "warn", "Dropped passive ELIOT events because the bounded queue is full", {
      dropped,
      last_kind: lastKind,
      queue_limit: MAX_PASSIVE_QUEUE,
    }).finally(() => {
      overflowLogScheduled = false
      if (droppedPassiveEvents > 0) armOverflowLog(client)
    })
  }, OVERFLOW_LOG_COOLDOWN_MS)
}

function notePassiveOverflow(client, kind) {
  droppedPassiveEvents += 1
  lastDroppedEventKind = kind
  armOverflowLog(client)
}

function enqueuePassive(client, kind, input, output) {
  if (passiveDepth >= MAX_PASSIVE_QUEUE) {
    notePassiveOverflow(client, kind)
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
