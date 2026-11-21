// String extraction and classification — static, execution-free.
//
// Sources: C string literals (__cstring), Objective-C selectors / class names
// / method types, Swift reflection strings, os_log format strings, and
// CFString / NSString literals (__cfstring, UTF-8 and UTF-16). Findings are
// categorized for security and privacy auditing of apps you are authorized to
// examine: endpoints, embedded credentials, integrity-check indicators, TLS
// pinning indicators. Every finding names the rule that matched it.

import { createPointerResolver } from "./macho/fixups.js";

const STRING_SECTIONS = [
  { sect: "__cstring", source: "c-string" },
  { sect: "__objc_methname", source: "objc-selector" },
  { sect: "__objc_classname", source: "objc-class-name" },
  { sect: "__objc_methtype", source: "objc-type-encoding" },
  { sect: "__swift5_reflstr", source: "swift-reflection" },
  { sect: "__oslogstring", source: "os-log-format" },
];

const RULES = [
  // Endpoints and identifiers
  { category: "urls", rule: "url", re: /\b(?:https?|wss?|ftp):\/\/[^\s"'<>\\]+/gi },
  { category: "custom_url_schemes", rule: "custom-scheme", re: /^(?!https?:|wss?:|ftp:|file:)[a-z][a-z0-9+.-]{2,30}:\/\/\S*$/i },
  { category: "emails", rule: "email", re: /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi },
  { category: "ip_addresses", rule: "ipv4", re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
  // Credential candidates (well-known provider formats)
  { category: "credential_candidates", rule: "aws-access-key-id", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { category: "credential_candidates", rule: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { category: "credential_candidates", rule: "stripe-secret-key", re: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b/g },
  { category: "credential_candidates", rule: "stripe-publishable-key", re: /\bpk_(?:live|test)_[0-9A-Za-z]{16,}\b/g },
  { category: "credential_candidates", rule: "slack-token", re: /\bxox[abprs]-[0-9A-Za-z-]{10,}\b/g },
  { category: "credential_candidates", rule: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { category: "credential_candidates", rule: "sendgrid-key", re: /\bSG\.[\w-]{22}\.[\w-]{43}\b/g },
  { category: "credential_candidates", rule: "twilio-api-key", re: /\bSK[0-9a-f]{32}\b/g },
  { category: "credential_candidates", rule: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { category: "credential_candidates", rule: "private-key-block", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  // Jailbreak / tamper / instrumentation detection indicators
  {
    category: "integrity_checks",
    rule: "jailbreak-or-instrumentation-indicator",
    re: /\/Applications\/(?:Cydia|Sileo|Zebra|Installer|blackra1n|FakeCarrier|Icy|IntelliScreen|SBSettings)\.app|\/Library\/MobileSubstrate|\/usr\/sbin\/sshd|\/etc\/apt\b|\/private\/var\/lib\/apt|\/bin\/bash\b|\/usr\/bin\/ssh\b|\/var\/jb\b|\b(?:cydia|sileo|zbra|undecimus):\/\/|\bFridaGadget\b|\bfrida-server\b|\bfrida\b|\bMobileSubstrate\b|\blibhooker\b|\bSubstitute\b|\bcheckra1n\b|\bunc0ver\b|\bpalera1n\b|\bDopamine\b/gi,
  },
  // TLS certificate / public-key pinning indicators
  {
    category: "tls_pinning",
    rule: "pinning-indicator",
    re: /\bTrustKit\b|\bSecTrustEvaluate(?:WithError)?\b|\bpinnedCertificates\b|\bpublicKeyHash(?:es)?\b|\bAFSecurityPolicy\b|\bSSLPinning\b|\bsha256\/[A-Za-z0-9+/=]{43,44}/g,
  },
];

function shannon(s) {
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function isPrintable(s) {
  // Reject strings dominated by control characters (binary noise).
  let bad = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) || c === 0xfffd) bad++;
  }
  return bad === 0;
}

function* cstringsIn(image, sect) {
  const range = image.sectionRange(sect);
  if (!range) return;
  const { buf } = image;
  let start = range.start;
  for (let p = range.start; p <= range.end; p++) {
    if (p === range.end || buf[p] === 0) {
      if (p > start) yield { vm: sect.addr + (start - range.start), value: buf.toString("utf8", start, p) };
      start = p + 1;
    }
  }
}

function readCFStrings(image, resolver) {
  const sect = image.section("__cfstring");
  const out = [];
  if (!sect || !image.is64) return out;
  for (const vm of image.sectionSlots(sect, 32)) {
    const off = image.vmToOffset(vm);
    if (off == null || off + 32 > image.sliceEnd) break;
    const flags = image.u32(off + 8);
    const strVm = resolver.target(vm + 16);
    const len = Number(image.u64(off + 24));
    if (strVm == null || len > 1 << 20) continue;
    const so = image.vmToOffset(strVm);
    if (so == null || image.isEncryptedOffset(so)) continue;
    let value;
    if (flags === 0x7d0) {
      // UTF-16LE string in __ustring
      value = image.buf.toString("utf16le", so, so + len * 2);
    } else {
      value = image.buf.toString("utf8", so, so + len);
    }
    out.push({ vm, value, source: "cfstring" });
  }
  return out;
}

/**
 * Extract and classify strings from one image.
 * options: { minLength = 4, maxStrings = 50000, maxFindingsPerCategory = 500 }
 */
export function extractStrings(image, options = {}) {
  const minLength = options.minLength ?? 4;
  const maxStrings = options.maxStrings ?? 50000;
  const maxPerCat = options.maxFindingsPerCategory ?? 500;
  const resolver = options.resolver ?? createPointerResolver(image);
  const limitations = [];
  const strings = [];
  const counts = {};
  let truncated = false;

  const add = (entry) => {
    if (entry.value.length < minLength || !isPrintable(entry.value)) return;
    counts[entry.source] = (counts[entry.source] ?? 0) + 1;
    if (strings.length < maxStrings) strings.push(entry);
    else truncated = true;
  };

  for (const { sect: name, source } of STRING_SECTIONS) {
    for (const sect of image.sections.filter((s) => s.name === name)) {
      const range = image.sectionRange(sect);
      if (!range) continue;
      if (image.isEncryptedOffset(range.start)) {
        limitations.push(`${sect.segname},${sect.name} lies in the FairPlay-encrypted range; its strings are unreadable without a decrypted binary.`);
        continue;
      }
      for (const s of cstringsIn(image, sect)) add({ ...s, source, section: `${sect.segname},${sect.name}` });
    }
  }
  for (const s of readCFStrings(image, resolver)) add({ ...s, section: "__DATA,__cfstring" });
  if (truncated) limitations.push(`String list truncated at ${maxStrings}; counts are complete.`);

  // Classification
  const findings = {};
  const seen = new Set();
  const record = (category, rule, value, entry) => {
    const key = `${category}\u0000${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings[category] ??= [];
    if (findings[category].length < maxPerCat) {
      findings[category].push({ value, rule, source: entry.source, section: entry.section, address: `0x${entry.vm.toString(16)}` });
    }
  };

  for (const entry of strings) {
    if (entry.source === "objc-type-encoding") continue;
    for (const { category, rule, re } of RULES) {
      re.lastIndex = 0;
      if (re.global) {
        for (const m of entry.value.matchAll(re)) record(category, rule, m[0], entry);
      } else if (re.test(entry.value)) {
        record(category, rule, entry.value, entry);
      }
    }
    // Generic high-entropy tokens (lower confidence than provider formats).
    const v = entry.value;
    if (v.length >= 32 && v.length <= 512 && !/\s/.test(v) && /^[A-Za-z0-9+/=_-]+$/.test(v)) {
      const hexOnly = /^[0-9a-fA-F]+$/.test(v);
      const h = shannon(v);
      if ((hexOnly && h >= 3.5) || (!hexOnly && h >= 4.5)) record("high_entropy", hexOnly ? "hex-entropy" : "base64-entropy", v, entry);
    }
  }

  return { counts, total: strings.length, strings, findings, limitations };
}
