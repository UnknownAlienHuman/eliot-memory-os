const MUTATING_TOOLS = new Set(["bash", "edit", "write", "patch", "notebook"])

function attachedTask() {
  return Boolean(process.env.ELIOT_TASK_ID)
}

function compactEvent(kind, input = {}, output = {}) {
  const event = input.event ?? input
  const properties = event.properties ?? {}
  return {
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

async function emit(kind, input, output) {
  const executable = process.env.ELIOT_GOVERNOR_EXE ?? (process.env.LOCALAPPDATA
    ? `${process.env.LOCALAPPDATA}/Eliot/host-integrations/opencode/bin/eliot-governor.exe`
    : null)
  if (!executable) return { decision: "passive", reason: "ELIOT_GOVERNOR_EXE is unset" }

  const child = Bun.spawn({
    cmd: [executable, "host", "event", "--host", "opencode", "--event", kind],
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
    env: process.env,
  })
  child.stdin.write(JSON.stringify(compactEvent(kind, input, output)))
  child.stdin.end()
  const text = await new Response(child.stdout).text()
  const status = await child.exited
  if (status !== 0) {
    if (attachedTask() && kind === "tool.execute.before" && MUTATING_TOOLS.has(input.tool)) {
      throw new Error("ELIOT ActionGate is unavailable for an attached mutating task")
    }
    return { decision: "degraded", reason: "ELIOT lifecycle bridge unavailable" }
  }
  try {
    return JSON.parse(text)
  } catch {
    return { decision: "recorded" }
  }
}

export const EliotPlugin = async () => ({
  event: async ({ event }) => {
    const useful = new Set([
      "session.created",
      "session.compacted",
      "session.error",
      "session.idle",
      "permission.asked",
      "permission.replied",
      "file.edited",
      "todo.updated",
    ])
    if (useful.has(event.type)) {
      try {
        await emit(event.type, { event }, {})
      } catch {
        // Passive lifecycle telemetry must not break the host session.
      }
    }
  },
  "tool.execute.before": async (input, output) => {
    if (!attachedTask() || !MUTATING_TOOLS.has(input.tool)) return
    const gate = await emit("tool.execute.before", input, output)
    if (gate.decision === "deny") throw new Error(gate.reason ?? "ELIOT ActionGate denied mutation")
  },
  "tool.execute.after": async (input, output) => {
    try {
      await emit("tool.execute.after", input, output)
    } catch {
      // The completed tool result remains authoritative if telemetry degrades.
    }
  },
})
