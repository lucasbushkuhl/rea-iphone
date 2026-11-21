// Apple crash report summaries — static. Handles the iOS 15+ .ips format
// (a JSON header line followed by a JSON body) and legacy text .crash logs.

export function summarizeCrashReport(text, fileName = null) {
  const nl = text.indexOf("\n");
  const firstLine = nl >= 0 ? text.slice(0, nl) : text;
  let header = null;
  try { header = JSON.parse(firstLine); } catch { /* legacy text */ }

  if (header && nl >= 0) {
    let body = null;
    try { body = JSON.parse(text.slice(nl + 1)); } catch { /* header-only */ }
    const out = {
      file: fileName,
      format: "ips-json",
      bug_type: header.bug_type ?? null,
      app_name: header.app_name ?? body?.procName ?? null,
      bundle_id: header.bundleID ?? body?.bundleInfo?.CFBundleIdentifier ?? null,
      app_version: header.app_version ?? body?.bundleInfo?.CFBundleShortVersionString ?? null,
      build_version: header.build_version ?? body?.bundleInfo?.CFBundleVersion ?? null,
      os_version: header.os_version ?? null,
      timestamp: header.timestamp ?? body?.captureTime ?? null,
      incident_id: header.incident_id ?? body?.incident ?? null,
      slice_uuid: header.slice_uuid ?? null,
      exception: null,
      termination: null,
      faulting_thread: null,
      top_frames: [],
    };
    if (body) {
      if (body.exception) {
        out.exception = {
          type: body.exception.type ?? null,
          signal: body.exception.signal ?? null,
          subtype: body.exception.subtype ?? null,
          codes: body.exception.codes ?? null,
        };
      }
      if (body.termination) {
        out.termination = {
          namespace: body.termination.namespace ?? null,
          code: body.termination.code ?? null,
          indicator: body.termination.indicator ?? null,
          reasons: body.termination.reasons ?? null,
        };
      }
      const images = Array.isArray(body.usedImages) ? body.usedImages : [];
      const threads = Array.isArray(body.threads) ? body.threads : [];
      const idx = Number.isInteger(body.faultingThread) ? body.faultingThread : threads.findIndex((t) => t.triggered);
      const thread = threads[idx];
      if (thread) {
        out.faulting_thread = { index: idx, name: thread.name ?? null, queue: thread.queue ?? null };
        out.top_frames = (thread.frames ?? []).slice(0, 12).map((f) => {
          const img = images[f.imageIndex];
          const where = f.symbol ? `${f.symbol}${f.symbolLocation != null ? ` + ${f.symbolLocation}` : ""}` : `+0x${(f.imageOffset ?? 0).toString(16)}`;
          return `${img?.name ?? "?"} ${where}`;
        });
      }
      if (body.asi) out.application_specific_information = body.asi;
    }
    return out;
  }

  // Legacy text crash log.
  const field = (name) => {
    const m = new RegExp(`^${name}:\\s*(.+)$`, "m").exec(text);
    return m ? m[1].trim() : null;
  };
  const out = {
    file: fileName,
    format: "crash-text",
    app_name: field("Process")?.replace(/\s*\[\d+\]$/, "") ?? null,
    bundle_id: field("Identifier"),
    app_version: field("Version"),
    os_version: field("OS Version"),
    timestamp: field("Date/Time"),
    incident_id: field("Incident Identifier"),
    exception: { type: field("Exception Type"), codes: field("Exception Codes"), subtype: field("Exception Subtype") },
    termination: { reasons: field("Termination Reason") },
    faulting_thread: null,
    top_frames: [],
  };
  const crashed = /^Thread (\d+) Crashed:.*$/m.exec(text);
  if (crashed) {
    out.faulting_thread = { index: Number(crashed[1]) };
    const after = text.slice(crashed.index + crashed[0].length).split("\n").slice(1);
    for (const line of after) {
      if (!/^\d+\s/.test(line)) break;
      out.top_frames.push(line.replace(/\s+/g, " ").trim());
      if (out.top_frames.length >= 12) break;
    }
  }
  return out;
}
