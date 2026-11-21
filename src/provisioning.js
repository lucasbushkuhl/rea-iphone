// embedded.mobileprovision is a CMS (PKCS#7) signed container wrapping a plain
// XML property list. Rather than decode ASN.1, we extract the embedded
// <plist>…</plist> payload — the same pragmatic approach `security cms -D` and
// most tooling rely on — and parse it. Also extracts an entitlements plist
// embedded in a code signature blob by the same scan.

import { parsePlist } from "./plist.js";

function extractEmbeddedPlist(buf) {
  const text = buf.toString("latin1");
  const start = text.indexOf("<?xml");
  const open = start === -1 ? text.indexOf("<plist") : start;
  if (open === -1) return null;
  const end = text.lastIndexOf("</plist>");
  if (end === -1) return null;
  const slice = text.slice(open, end + "</plist>".length);
  try {
    return parsePlist(Buffer.from(slice, "latin1"));
  } catch {
    return null;
  }
}

export function parseProvisioningProfile(buf) {
  const plist = extractEmbeddedPlist(buf);
  if (!plist) return { parsed: false };

  const ent = plist.Entitlements ?? {};
  const now = Date.now();
  const expiry = plist.ExpirationDate ? Date.parse(plist.ExpirationDate) : null;
  const getTaskAllow = ent["get-task-allow"] === true;
  const provisionedDevices = Array.isArray(plist.ProvisionedDevices) ? plist.ProvisionedDevices : null;

  // Distribution type heuristic (path conventions, documented, not proven):
  // - get-task-allow true  -> development build
  // - ProvisionedDevices present, no get-task-allow -> ad hoc
  // - ProvisionAllDevices true -> enterprise (in-house)
  // - none of the above -> App Store distribution
  let distribution;
  if (getTaskAllow) distribution = "development";
  else if (plist.ProvisionsAllDevices === true) distribution = "enterprise";
  else if (provisionedDevices) distribution = "ad-hoc";
  else distribution = "app-store";

  return {
    parsed: true,
    name: plist.Name ?? null,
    appIdName: plist.AppIDName ?? null,
    teamName: plist.TeamName ?? null,
    teamIdentifier: Array.isArray(plist.TeamIdentifier) ? plist.TeamIdentifier : null,
    creationDate: plist.CreationDate ?? null,
    expirationDate: plist.ExpirationDate ?? null,
    expired: expiry !== null ? expiry < now : null,
    platforms: Array.isArray(plist.Platform) ? plist.Platform : null,
    distribution,
    getTaskAllow,
    provisionedDeviceCount: provisionedDevices ? provisionedDevices.length : null,
    applicationIdentifier: ent["application-identifier"] ?? null,
    apsEnvironment: ent["aps-environment"] ?? null,
    entitlements: ent,
  };
}

// Best-effort extraction of an entitlements plist embedded anywhere in a buffer
// (e.g. inside the Mach-O code-signature __LINKEDIT blob).
export function extractEntitlements(buf) {
  const text = buf.toString("latin1");
  // Entitlements plists are small XML plists; find one that mentions a known key.
  const re = /<\?xml[\s\S]*?<\/plist>|<plist[\s\S]*?<\/plist>/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (/application-identifier|get-task-allow|com\.apple\./.test(m[0])) {
      try {
        const parsed = parsePlist(Buffer.from(m[0], "latin1"));
        if (parsed && typeof parsed === "object") return parsed;
      } catch {
        /* keep scanning */
      }
    }
  }
  return null;
}
