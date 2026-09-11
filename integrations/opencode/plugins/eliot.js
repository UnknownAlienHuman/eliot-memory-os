const MUTATING_TOOLS = new Set(["bash", "edit", "write", "patch"])
const READ_ONLY_TOOLS = new Set(["read", "grep", "glob", "list", "webfetch", "websearch", "lsp", "codesearch"])
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
const TRANSIENT_HTTP_STATUS = new Set([408, 425, 429, 500, 502, 503, 504])
const ALLOWED_HTTP_HOSTS = new Set(["127.0.0.1", "::1", "[::1]"])
const ALLOWED_GATE_DECISIONS = new Set(["recorded", "allow", "allowed", "pass"])

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

const MAX_ARGUMENT_KEYS = 64
const MAX_ARGUMENT_KEY_LENGTH = 128
const MAX_EFFECT_DESCRIPTOR_BYTES = 64 * 1024
const EFFECT_SCHEMA_VERSION = "eliot.opencode.effect.v1"
const ARGUMENT_NORMALIZATION_VERSION = "eliot.opencode.arguments.v1"
const MEDIA_TYPE_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/

function boundedInteger(name, fallback, minimum, maximum) {
  const parsed = Number.parseInt(process.env[name] ?? "", 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(maximum, Math.max(minimum, parsed))
}

function bridgeTimeoutMs() {
  return boundedInteger("ELIOT_OPENCODE_BRIDGE_TIMEOUT_MS", 5000, 500, 15000)
}

function streamSettleMs() {
  return boundedInteger("ELIOT_OPENCODE_STREAM_SETTLE_MS", 750, 100, 3000)
}

function maximumPassiveQueue() {
  return boundedInteger("ELIOT_OPENCODE_PASSIVE_QUEUE_LIMIT", 64, 1, 256)
}

function maximumBridgeOutputBytes() {
  return boundedInteger("ELIOT_OPENCODE_BRIDGE_OUTPUT_LIMIT", 64 * 1024, 4096, 256 * 1024)
}

function overflowLogCooldownMs() {
  return boundedInteger("ELIOT_OPENCODE_OVERFLOW_LOG_COOLDOWN_MS", 5000, 500, 60000)
}

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

function firstPositiveInteger(...values) {
  return values.find((value) => Number.isSafeInteger(value) && value > 0) ?? null
}

async function sha256Hex(value) {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) return null
  const encoded = new TextEncoder().encode(value)
  const digest = await subtle.digest("SHA-256", encoded)
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")
}

function appendCanonical(state, value) {
  state.bytes += new TextEncoder().encode(value).byteLength
  if (state.bytes > MAX_EFFECT_DESCRIPTOR_BYTES) {
    throw new Error("effect descriptor exceeds its bounded contract")
  }
  state.parts.push(value)
}

function appendCanonicalString(state, value) {
  appendCanonical(state, `s${value.length}:`)
  for (let index = 0; index < value.length; index += 1) {
    appendCanonical(state, value.charCodeAt(index).toString(16).padStart(4, "0"))
  }
}

function plainObjectEntries(value) {
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error("unsupported object container")
  }
  if (Object.getOwnPropertySymbols(value).length > 0) throw new Error("symbol properties are not bindable")

  const keys = Object.getOwnPropertyNames(value)
  if (keys.length > MAX_ARGUMENT_KEYS) throw new Error("argument key count exceeds its bounded contract")
  for (const key of keys) {
    if (key.length > MAX_ARGUMENT_KEY_LENGTH) throw new Error("argument key exceeds its bounded contract")
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) {
      throw new Error("accessor or non-enumerable argument is not bindable")
    }
  }
  return keys.sort().map((key) => [key, Object.getOwnPropertyDescriptor(value, key).value])
}

function arrayValues(value) {
  if (Object.getPrototypeOf(value) !== Array.prototype) throw new Error("unsupported array container")
  if (Object.getOwnPropertySymbols(value).length > 0) throw new Error("symbol properties are not bindable")
  if (value.length > MAX_ARGUMENT_KEYS) throw new Error("array entry count exceeds its bounded contract")

  const names = Object.getOwnPropertyNames(value)
  if (names.length !== value.length + 1 || !names.includes("length")) {
    throw new Error("sparse or extended arrays are not bindable")
  }
  const values = []
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index))
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
      throw new Error("sparse or accessor arrays are not bindable")
    }
    values.push(descriptor.value)
  }
  return values
}

function appendCanonicalValue(state, value, active) {
  if (value === null) {
    appendCanonical(state, "null")
    return
  }

  switch (typeof value) {
    case "string":
      appendCanonicalString(state, value)
      return
    case "boolean":
      appendCanonical(state, value ? "true" : "false")
      return
    case "number": {
      if (!Number.isFinite(value)) throw new Error("non-finite number is not bindable")
      const number = Object.is(value, -0) ? "-0" : String(value)
      appendCanonical(state, `number${number.length}:${number}`)
      return
    }
    case "object":
      break
    default:
      throw new Error(`${typeof value} argument is not bindable`)
  }

  if (active.has(value)) throw new Error("cyclic argument container")
  active.add(value)
  try {
    if (Array.isArray(value)) {
      const values = arrayValues(value)
      appendCanonical(state, `array${value.length}[`)
      for (const item of values) appendCanonicalValue(state, item, active)
      appendCanonical(state, "]")
      return
    }

    const entries = plainObjectEntries(value)
    appendCanonical(state, `object${entries.length}{`)
    for (const [key, item] of entries) {
      appendCanonicalString(state, key)
      appendCanonicalValue(state, item, active)
    }
    appendCanonical(state, "}")
  } finally {
    active.delete(value)
  }
}

function canonicalArguments(candidate) {
  if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw new Error("arguments must be a plain object")
  }
  const state = { bytes: 0, parts: [] }
  appendCanonicalValue(state, candidate, new WeakSet())
  return {
    argumentKeys: plainObjectEntries(candidate).map(([key]) => key),
    encoded: state.parts.join(""),
  }
}

function argumentCandidate(input, output = {}) {
  for (const source of [input, output]) {
    if (!source || typeof source !== "object") continue
    for (const key of ["args", "arguments"]) {
      if (Object.hasOwn(source, key)) return source[key]
    }
  }
  return {}
}

function eventArgumentKeys(input, output) {
  try {
    return canonicalArguments(argumentCandidate(input, output)).argumentKeys
  } catch {
    return []
  }
}

function actionBindingError(error) {
  return new Error(`ELIOT ActionGate cannot bind exact action arguments: ${error.message}`)
}

async function createEffectBinding(input, output) {
  try {
    if (!input || typeof input.tool !== "string" || input.tool.length === 0) {
      throw new Error("tool identity is not bindable")
    }
    const { argumentKeys, encoded } = canonicalArguments(argumentCandidate(input, output))
    const argumentDigest = await sha256Hex(`${ARGUMENT_NORMALIZATION_VERSION}:arguments:${encoded}`)
    if (argumentDigest === null) throw new Error("SHA-256 is unavailable")
    const descriptor = {
      schema_version: EFFECT_SCHEMA_VERSION,
      normalization_version: ARGUMENT_NORMALIZATION_VERSION,
      tool: input.tool,
      argument_keys: argumentKeys,
      argument_digest: argumentDigest,
    }
    const descriptorState = { bytes: 0, parts: [] }
    appendCanonicalValue(descriptorState, descriptor, new WeakSet())
    const effectDigest = await sha256Hex(`${EFFECT_SCHEMA_VERSION}:effect:${descriptorState.parts.join("")}`)
    if (effectDigest === null) throw new Error("SHA-256 is unavailable")
    return { descriptor, effectDigest }
  } catch (error) {
    throw actionBindingError(error)
  }
}

function isJsonMediaType(value) {
  if (typeof value !== "string") return false
  let start = 0
  let end = value.length
  while (value[start] === " " || value[start] === "\t") start += 1
  while (end > start && (value[end - 1] === " " || value[end - 1] === "\t")) end -= 1
  const mediaType = value.slice(start, end)
  const separator = mediaType.indexOf("/")
  if (separator <= 0 || mediaType.slice(separator + 1).length === 0) return false
  const type = mediaType.slice(0, separator)
  let position = separator + 1
  while (position < mediaType.length && MEDIA_TYPE_TOKEN.test(mediaType[position])) position += 1
  if (type.toLowerCase() !== "application" || mediaType.slice(separator + 1, position).toLowerCase() !== "json") {
    return false
  }

  while (position < mediaType.length) {
    while (mediaType[position] === " " || mediaType[position] === "\t") position += 1
    if (mediaType[position] !== ";") return false
    position += 1
    while (mediaType[position] === " " || mediaType[position] === "\t") position += 1

    const parameterStart = position
    while (position < mediaType.length && MEDIA_TYPE_TOKEN.test(mediaType[position])) position += 1
    if (position === parameterStart) return false
    if (mediaType[position] !== "=") return false
    position += 1
    if (mediaType[position] === '"') {
      position += 1
      let closed = false
      while (position < mediaType.length) {
        const code = mediaType.charCodeAt(position)
        if (mediaType[position] === "\\") {
          const escapedCode = mediaType.charCodeAt(position + 1)
          if (escapedCode < 0x20 || escapedCode > 0x7e) return false
          position += 2
        } else if (mediaType[position] === '"') {
          position += 1
          closed = true
          break
        } else if (code < 0x20 || code === 0x7f || code > 0x7e) {
          return false
        } else {
          position += 1
        }
      }
      if (!closed) return false
    } else {
      const valueStart = position
      while (position < mediaType.length && MEDIA_TYPE_TOKEN.test(mediaType[position])) position += 1
      if (position === valueStart) return false
    }
  }
  return true
}

async function cancelResponseBody(response, reason) {
  try {
    await response?.body?.cancel?.(reason)
  } catch {
    // Rejection remains fail-closed even when the host cannot cancel cleanly.
  }
}

async function compactEvent(kind, input = {}, output = {}, effectBinding = null) {
  const event = input.event ?? input
  const properties = event.properties ?? {}
  const nativeSequence = firstPositiveInteger(
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
  const argumentKeys = effectBinding?.descriptor.argument_keys ?? eventArgumentKeys(input, output)
  const identityMaterial = JSON.stringify({
    vendor_event_kind: vendorEventKind,
    native_event_id: nativeEventId,
    native_sequence: nativeSequence,
    host_session_id: hostSessionId,
    tool,
    changed_path: changedPath,
    argument_keys: argumentKeys,
    emitted_at: emittedAt,
    fallback_sequence: nativeEventId || nativeSequence !== null ? null : sequence,
    effect_digest: effectBinding?.effectDigest ?? null,
  })
  const identityDigest = await sha256Hex(identityMaterial)
  const eventId =
    effectBinding !== null
      ? `opencode:effect:${effectBinding.effectDigest}${nativeEventId === null ? "" : `:${nativeEventId}`}`
      : nativeEventId !== null
        ? `opencode:${vendorEventKind}:${nativeEventId}`
        : identityDigest !== null
          ? `opencode:sha256:${identityDigest}`
          : `opencode:${hostSessionId ?? "unknown"}:${vendorEventKind}:${sequence}`

  const payload = {
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
  if (effectBinding !== null) {
    payload.effect_descriptor = effectBinding.descriptor
    payload.effect_digest = effectBinding.effectDigest
  }
  return payload
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

class HttpBridgeError extends Error {
  constructor(message, transient = false) {
    super(message)
    this.name = "HttpBridgeError"
    this.transient = transient
  }
}

function httpBridgeConfiguration() {
  const raw = process.env.ELIOT_OPENCODE_BRIDGE_URL
  if (!raw) return null

  let base
  try {
    base = new URL(raw)
  } catch {
    throw new HttpBridgeError("ELIOT OpenCode bridge URL is invalid")
  }
  if (base.protocol !== "http:") {
    throw new HttpBridgeError("ELIOT OpenCode bridge must use loopback HTTP")
  }
  if (!ALLOWED_HTTP_HOSTS.has(base.hostname)) {
    throw new HttpBridgeError("ELIOT OpenCode bridge must use a literal loopback address")
  }
  if (!base.port) {
    throw new HttpBridgeError("ELIOT OpenCode bridge requires an explicit reserved loopback port")
  }
  if (base.username || base.password || base.search || base.hash) {
    throw new HttpBridgeError("ELIOT OpenCode bridge URL cannot contain credentials, query, or fragment")
  }
  if (base.pathname !== "/" && base.pathname !== "") {
    throw new HttpBridgeError("ELIOT OpenCode bridge URL must identify the server root")
  }

  const token = process.env.ELIOT_OPENCODE_BRIDGE_TOKEN
  if (!token) {
    throw new HttpBridgeError("ELIOT OpenCode bridge token is unavailable")
  }
  return {
    endpoint: new URL("/v1/host-events", base).toString(),
    token,
  }
}

async function readBoundedWebStream(stream, maximumBytes) {
  if (!stream) return ""
  const reader = stream.getReader()
  const decoder = new TextDecoder()
  let text = ""
  let total = 0
  let settled = false
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) {
        settled = true
        break
      }
      if (total + value.byteLength > maximumBytes) {
        await reader.cancel("ELIOT OpenCode bridge response limit reached").catch(() => {})
        settled = true
        throw new HttpBridgeError("ELIOT OpenCode bridge response exceeded its bounded contract")
      }
      total += value.byteLength
      text += decoder.decode(value, { stream: true })
    }
    text += decoder.decode()
    return text
  } catch (error) {
    if (!settled) {
      await reader.cancel("ELIOT OpenCode bridge response read abandoned").catch(() => {})
      settled = true
    }
    throw error
  } finally {
    reader.releaseLock()
  }
}

function parseBridgeResponse(text) {
  let value
  try {
    value = JSON.parse(text)
  } catch {
    throw new HttpBridgeError("ELIOT OpenCode bridge returned invalid JSON")
  }
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new HttpBridgeError("ELIOT OpenCode bridge returned an invalid response object")
  }
  if (typeof value.decision !== "string" || value.decision.length === 0) {
    throw new HttpBridgeError("ELIOT OpenCode bridge returned no explicit decision")
  }
  return value
}

async function postHttpBridge(config, payload) {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), bridgeTimeoutMs())
  try {
    const response = await fetch(config.endpoint, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${config.token}`,
        "Content-Type": "application/json",
        "Idempotency-Key": payload.event_id,
        "X-ELIOT-Host": "opencode",
      },
      body: JSON.stringify(payload),
      // A redirect would re-issue this POST — identities, changed_path and
      // argument names — at a host the loopback admission never validated.
      redirect: "error",
      signal: controller.signal,
    })
    if (TRANSIENT_HTTP_STATUS.has(response.status)) {
      await cancelResponseBody(response, "ELIOT OpenCode bridge transient response rejected")
      throw new HttpBridgeError(
        `ELIOT OpenCode bridge returned transient HTTP status ${response.status}`,
        true,
      )
    }
    if (!response.ok) {
      await cancelResponseBody(response, "ELIOT OpenCode bridge non-success response rejected")
      throw new HttpBridgeError(`ELIOT OpenCode bridge returned HTTP status ${response.status}`)
    }
    const contentType = response.headers.get("content-type")
    if (!isJsonMediaType(contentType)) {
      await cancelResponseBody(response, "ELIOT OpenCode bridge response media type rejected")
      throw new HttpBridgeError("ELIOT OpenCode bridge returned a non-JSON content type")
    }
    const text = await readBoundedWebStream(response.body, maximumBridgeOutputBytes())
    return parseBridgeResponse(text)
  } catch (error) {
    if (error instanceof HttpBridgeError) throw error
    if (error?.name === "AbortError") {
      throw new HttpBridgeError("ELIOT OpenCode bridge timed out", true)
    }
    throw new HttpBridgeError("ELIOT OpenCode bridge transport failed", true)
  } finally {
    clearTimeout(timeout)
  }
}

async function invokeHttpBridge(config, payload) {
  let lastError
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      return await postHttpBridge(config, payload)
    } catch (error) {
      lastError = error
      if (!(error instanceof HttpBridgeError) || !error.transient || attempt > 0) break
      await sleep(50)
    }
  }
  throw lastError
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
      // Cleanup is still reflected in the caller's degraded/denied disposition.
    }
    await Promise.race([child.exited.catch(() => null), sleep(streamSettleMs())])
  }
  return result
}

function bridgeFailure(required, reason) {
  if (required) throw new Error(reason)
  return { decision: "degraded", reason }
}

async function invokeLegacyProcessBridge(kind, payload, { required = false } = {}) {
  const executable = bridgeExecutable()
  if (!executable) {
    return bridgeFailure(required, "ELIOT ActionGate is unavailable: bridge executable is not configured")
  }
  if (!globalThis.Bun?.spawn) {
    return bridgeFailure(required, "ELIOT legacy process bridge is unavailable in this host runtime")
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

  const stdout = boundedDrain(child.stdout, maximumBridgeOutputBytes())
  const stderr = boundedDrain(child.stderr, maximumBridgeOutputBytes())
  try {
    await child.stdin.write(JSON.stringify(payload))
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
      settleDrain(stdout, streamSettleMs()),
      settleDrain(stderr, streamSettleMs()),
    ])
    return bridgeFailure(required, "ELIOT lifecycle bridge input failed")
  }

  const exit = await waitForExit(child, bridgeTimeoutMs())
  if (exit.timedOut) {
    stdout.cancel("ELIOT lifecycle bridge timed out")
    stderr.cancel("ELIOT lifecycle bridge timed out")
  }
  const [stdoutResult, stderrResult] = await Promise.all([
    settleDrain(stdout, streamSettleMs()),
    settleDrain(stderr, streamSettleMs()),
  ])

  if (exit.timedOut) return bridgeFailure(required, "ELIOT lifecycle bridge timed out")
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
    return parseBridgeResponse(stdoutResult.text)
  } catch (error) {
    return bridgeFailure(required, error.message)
  }
}

async function invokeBridge(kind, input, output, { required = false, effectBinding = null } = {}) {
  const payload = await compactEvent(kind, input, output, effectBinding)
  let httpConfig
  try {
    httpConfig = httpBridgeConfiguration()
  } catch (error) {
    return bridgeFailure(required, error.message)
  }

  if (httpConfig) {
    try {
      return await invokeHttpBridge(httpConfig, payload)
    } catch (error) {
      // Never cross-transport fail over after an HTTP attempt: the first request may
      // have reached durable admission even when its response was lost.
      return bridgeFailure(required, error.message)
    }
  }
  return invokeLegacyProcessBridge(kind, payload, { required })
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
      queue_limit: maximumPassiveQueue(),
    }).finally(() => {
      overflowLogScheduled = false
      if (droppedPassiveEvents > 0) armOverflowLog(client)
    })
  }, overflowLogCooldownMs())
}

function notePassiveOverflow(client, kind) {
  droppedPassiveEvents += 1
  lastDroppedEventKind = kind
  armOverflowLog(client)
}

function enqueuePassive(client, kind, input, output, options = {}) {
  if (passiveDepth >= maximumPassiveQueue()) {
    notePassiveOverflow(client, kind)
    return
  }

  passiveDepth += 1
  const run = async () => {
    try {
      const result = await invokeBridge(kind, input, output, options)
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

async function requireMutationGate(input, output, effectBinding) {
  const gateOptions = { required: true }
  gateOptions.effectBinding = effectBinding
  const gate = await invokeBridge("tool.execute.before", input, output, gateOptions)
  if (gate.decision === "deny") {
    throw new Error("ELIOT ActionGate denied mutation")
  }
  if (!ALLOWED_GATE_DECISIONS.has(gate.decision)) {
    throw new Error("ELIOT ActionGate returned no explicit usable decision")
  }
}

export const EliotPlugin = async ({ client } = {}) => ({
  event: async ({ event }) => {
    if (USEFUL_EVENTS.has(event.type)) enqueuePassive(client, event.type, { event }, {})
  },
  "tool.execute.before": async (input, output) => {
    if (!attachedTask()) return
    if (READ_ONLY_TOOLS.has(input?.tool)) {
      const effectBinding = await createEffectBinding(input, output)
      enqueuePassive(client, "tool.execute.skipped", input, output, { effectBinding })
      return {
        decision: "skipped",
        reason: "read_only_tool",
        tool: input.tool,
        effect_descriptor: effectBinding.descriptor,
        effect_digest: effectBinding.effectDigest,
      }
    }
    if (!MUTATING_TOOLS.has(input?.tool)) {
      throw new Error("ELIOT ActionGate cannot classify this OpenCode tool")
    }
    const effectBinding = await createEffectBinding(input, output)
    await requireMutationGate(input, output, effectBinding)
  },
  "tool.execute.after": async (input, output) => {
    enqueuePassive(client, "tool.execute.after", input, output)
  },
})
