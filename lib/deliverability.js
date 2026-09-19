// Deliverability analysis for .eml files: which ESP sent it, what the receiving
// mail server recorded about SPF / DKIM / DMARC, and a live check of the sender's
// DNS records. Everything is derived from the headers/HTML or from DNS TXT
// lookups — nothing here connects to hosts named in the email.
const dns = require("dns");
const crypto = require("crypto");
const net = require("net");
const { getDomain } = require("tldts");

const DNS_TIMEOUT_MS = 3000;
const OVERALL_TIMEOUT_MS = 12000;
const MAX_DNS_QUERIES = 30;
const SPF_LOOKUP_LIMIT = 10;
const MAX_DKIM_SIGNATURES = 4;
const resolver = new dns.promises.Resolver({ timeout: DNS_TIMEOUT_MS, tries: 1 });

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/i;
const SELECTOR_RE = /^[a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9])?$/i;
// DNS names may start labels with "_" (e.g. include:_spf.google.com), which real domains can't.
const DNS_NAME_RE = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/i;

// Returns a lowercase domain from "user@domain", "<user@domain>", "@domain" or "domain"; null if unusable.
function cleanDomain(value) {
  if (!value) return null;
  let d = String(value).trim().toLowerCase().replace(/^[<"'\s]+|[>"'\s.]+$/g, "");
  if (d.includes("@")) d = d.slice(d.lastIndexOf("@") + 1);
  return DOMAIN_RE.test(d) && !net.isIP(d) ? d : null;
}
const orgDomain = (d) => (d ? getDomain(d) || d : null);
const sameOrg = (a, b) => !!a && !!b && orgDomain(a) === orgDomain(b);

const unfold = (line) => line.replace(/\r?\n[ \t]+/g, " ").trim();

function headerValues(lines, key) {
  return lines
    .filter((h) => h.key === key)
    .map((h) => {
      const line = unfold(h.line);
      return line.slice(line.indexOf(":") + 1).trim();
    });
}

function parseTags(text) {
  const tags = {};
  for (const part of text.split(";")) {
    const i = part.indexOf("=");
    if (i > 0) tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  }
  return tags;
}

function truncate(text, max) {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

// ---------------------------------------------------------------------------
// Authentication-Results (RFC 8601) — what the receiving server recorded
// ---------------------------------------------------------------------------
// Splits on top-level ";" while honouring "quoted strings" and (comments).
function splitResinfos(value) {
  const parts = [];
  let text = "";
  let comments = [];
  let cur = "";
  let depth = 0;
  let inQuote = false;
  for (const ch of value) {
    if (inQuote) {
      text += ch;
      if (ch === '"') inQuote = false;
    } else if (depth > 0) {
      if (ch === "(") {
        depth++;
        cur += ch;
      } else if (ch === ")") {
        depth--;
        if (depth === 0) {
          comments.push(cur.trim());
          cur = "";
          text += " ";
        } else cur += ch;
      } else cur += ch;
    } else if (ch === '"') {
      inQuote = true;
      text += ch;
    } else if (ch === "(") {
      depth = 1;
      cur = "";
    } else if (ch === ";") {
      parts.push({ text: text.trim(), comments });
      text = "";
      comments = [];
    } else text += ch;
  }
  parts.push({ text: text.trim(), comments });
  return parts;
}

function parseAuthResults(value) {
  const [head, ...rest] = splitResinfos(value);
  const authservId = (head.text.split(/\s+/)[0] || "").toLowerCase() || null;
  const results = [];
  for (const part of rest) {
    const m = part.text.match(/^([a-z0-9][a-z0-9-]*)\s*=\s*([a-z0-9-]+)\s*(.*)$/i);
    if (!m) continue;
    const props = {};
    for (const p of m[3].matchAll(/\b(header|smtp|policy|body)\.([a-z0-9_-]+)\s*=\s*("([^"]*)"|[^\s;]+)/gi)) {
      props[`${p[1]}.${p[2]}`.toLowerCase()] = p[4] !== undefined ? p[4] : p[3];
    }
    results.push({
      method: m[1].toLowerCase(),
      result: m[2].toLowerCase(),
      props,
      rest: m[3],
      comments: part.comments,
    });
  }
  return { authservId, results };
}

const alignmentNote = (domain, fromDomain) => {
  if (!domain || !fromDomain) return null;
  return sameOrg(domain, fromDomain)
    ? "Aligned with the From domain"
    : `Not aligned with the From domain (${fromDomain})`;
};

function authenticationFromHeaders(lines, fromDomain) {
  const values = headerValues(lines, "authentication-results");
  const rows = [];
  const notes = [];
  let receiver = null;
  let spfAlignedPass = false;
  let dkimAlignedPass = false;
  let dmarcResult = null;
  let spfDomain = null;

  if (values.length) {
    const { authservId, results } = parseAuthResults(values[0]);
    receiver = authservId;
    if (values.length > 1) {
      notes.push(`${values.length} Authentication-Results headers were found; showing the most recent one (added by ${authservId || "the last server"}).`);
    }

    const spf = results.find((r) => r.method === "spf");
    if (spf) {
      const domain = cleanDomain(spf.props["smtp.mailfrom"]) || cleanDomain(spf.props["smtp.helo"]);
      spfDomain = domain;
      const pass = spf.result === "pass";
      spfAlignedPass = pass && sameOrg(domain, fromDomain);
      rows.push({
        level: pass ? "ok" : "problem",
        text: `SPF — ${spf.result}`,
        summary: `SPF ${spf.result}${domain ? ` for ${domain}` : ""}`,
        details: [domain && `Checked domain: ${domain}`, alignmentNote(domain, fromDomain), spf.comments[0] && truncate(spf.comments[0], 160)].filter(Boolean),
      });
    } else {
      rows.push({ level: "info", text: "SPF — no result recorded", details: [] });
    }

    const dkims = results.filter((r) => r.method === "dkim");
    if (dkims.length) {
      for (const d of dkims) {
        const domain = cleanDomain(d.props["header.d"]) || cleanDomain(d.props["header.i"]);
        const selector = d.props["header.s"];
        const pass = d.result === "pass";
        if (pass && sameOrg(domain, fromDomain)) dkimAlignedPass = true;
        rows.push({
          level: pass ? "ok" : "problem",
          text: `DKIM — ${d.result}`,
          summary: `DKIM ${d.result}${domain ? ` (signed by ${domain})` : ""}`,
          details: [
            domain && `Signed by ${domain}${selector ? ` (selector ${selector})` : ""}`,
            alignmentNote(domain, fromDomain),
            d.comments[0] && truncate(d.comments[0], 160),
          ].filter(Boolean),
        });
      }
    } else {
      rows.push({ level: "info", text: "DKIM — no result recorded", details: [] });
    }

    const dmarc = results.find((r) => r.method === "dmarc");
    if (dmarc) {
      dmarcResult = dmarc.result;
      const policy = ((dmarc.comments[0] || "").match(/\bp=(\w+)/i) || dmarc.rest.match(/\baction=(\w+)/i) || [])[1];
      const pass = dmarc.result === "pass";
      rows.push({
        level: pass ? "ok" : "problem",
        text: `DMARC — ${dmarc.result}`,
        summary: `DMARC ${dmarc.result}${policy ? ` (policy ${policy.toLowerCase()})` : ""}`,
        details: [
          policy && `Policy: ${policy.toLowerCase()}`,
          !pass && ["none", "bestguesspass"].includes(dmarc.result) && "No DMARC policy was applied — the domain may not publish a DMARC record.",
        ].filter(Boolean),
      });
    } else {
      rows.push({ level: "info", text: "DMARC — no result recorded", details: [] });
    }

    if (dmarcResult !== "pass" && !spfAlignedPass && !dkimAlignedPass && fromDomain) {
      rows.push({
        level: "problem",
        text: "Neither SPF nor DKIM passed in alignment with the From domain",
        details: [`DMARC needs at least one of them to pass using ${fromDomain} (or a subdomain of it).`],
      });
    }
    return { found: true, source: "Authentication-Results", receiver, rows, notes, spfDomain };
  }

  // Fallback: Received-SPF only tells us about SPF.
  const receivedSpf = headerValues(lines, "received-spf")[0];
  if (receivedSpf) {
    const result = (receivedSpf.match(/^([a-z]+)/i) || [])[1];
    if (result) {
      const pass = result.toLowerCase() === "pass";
      rows.push({
        level: pass ? "ok" : "problem",
        text: `SPF — ${result.toLowerCase()}`,
        details: [(receivedSpf.match(/\(([^)]*)\)/) || [])[1]].filter(Boolean).map((s) => truncate(s, 160)),
      });
      notes.push("Only a Received-SPF header was found (no Authentication-Results), so DKIM and DMARC results aren't available.");
      return { found: true, source: "Received-SPF", receiver: null, rows, notes, spfDomain: null };
    }
  }

  notes.push(
    "No authentication results were found in this .eml, so there's nothing to report on what the receiving mail server decided. " +
      "This happens when the file was saved from a Sent folder, exported by a tool that strips headers, or never passed through a server that records results."
  );
  return { found: false, source: null, receiver: null, rows, notes, spfDomain: null };
}

// ---------------------------------------------------------------------------
// ESP detection
// ---------------------------------------------------------------------------
// Known sender-infrastructure fingerprints: domains (string = domain or subdomain
// of it; RegExp = tested on the hostname), header-name prefixes, X-Mailer patterns.
// Not exhaustive — "no ESP identified" does not mean none was used.
const ESPS = [
  { name: "SendGrid", domains: ["sendgrid.net", "sendgrid.info", "sendgrid.com"], headers: ["x-sg-eid", "x-sg-id"], messageId: /ismtpd/i },
  { name: "Mailgun", domains: ["mailgun.org", "mailgun.net", "mailgun.com"], headers: ["x-mailgun-"] },
  { name: "Amazon SES", domains: ["amazonses.com"], headers: ["x-ses-"] },
  { name: "Postmark", domains: ["postmarkapp.com", "mtasv.net", /^pm-bounces\./], headers: ["x-pm-"] },
  { name: "SparkPost", domains: ["sparkpostmail.com", "sparkpost.com", "spgo.io"], headers: ["x-msfbl"] },
  { name: "Mailchimp", domains: ["mcsv.net", "mcdlv.net", "list-manage.com", "mailchimp.com", "mailchi.mp", "rsgsv.net", "chimpstatic.com"], mailer: /mailchimp/i },
  { name: "Mandrill (Mailchimp Transactional)", domains: ["mandrillapp.com"], headers: ["x-mandrill-user", "x-mc-user"] },
  { name: "Klaviyo", domains: ["klaviyomail.com", "klaviyo.com", "kmail-lists.com"], headers: ["x-klaviyo-"] },
  { name: "HubSpot", domains: ["hubspotemail.net", "hubspotlinks.com", "hubspot.com"] },
  { name: "Constant Contact", domains: ["constantcontact.com", "ccsend.com", "rs6.net"] },
  { name: "Campaign Monitor", domains: ["createsend.com", /^cmail\d+\.com$/] },
  { name: "Braze", domains: ["braze.com", "braze-images.com", "appboy.com"] },
  { name: "Iterable", domains: ["iterable.com"] },
  { name: "Customer.io", domains: ["customeriomail.com", "customer.io"] },
  { name: "ActiveCampaign", domains: ["activecampaign.com", /^acem(ln[a-d]|s\d+)\.com$/] },
  { name: "Brevo (Sendinblue)", domains: ["sendinblue.com", "brevo.com", "sibautomation.com", "sender-sib.com", /^sendibt\d+\.com$/], headers: ["x-mailin-"] },
  { name: "Salesforce Marketing Cloud", domains: ["exacttarget.com", "exct.net"], headers: ["x-sfmc-"] },
  { name: "Pardot (Salesforce)", domains: ["pardot.com"] },
  { name: "Marketo", domains: ["mktomail.com", "marketo.com"] },
  { name: "Oracle Responsys", domains: ["responsys.net", /^rsys\d\.(net|com)$/] },
  { name: "Mailjet", domains: ["mailjet.com", "mjt.lu"], headers: ["x-mailjet-"] },
  { name: "Emarsys", domains: ["emarsys.net", "emarsys.com"] },
  { name: "Omnisend", domains: ["omnisend.com", "omnisrc.com"] },
  { name: "Drip", domains: ["dripemail2.com", "getdrip.com"] },
  { name: "MailerLite", domains: ["mailerlite.com", "mlsend.com"] },
  { name: "GetResponse", domains: ["getresponse.com"] },
  { name: "Moosend", domains: ["moosend.com"] },
  { name: "Sailthru", domains: ["sailthru.com"] },
  { name: "Shopify Email", domains: ["shopifyemail.com"], headers: ["x-shopify-"] },
  { name: "Kit (ConvertKit)", domains: ["convertkit.com", "convertkit-mail.com", "convertkit-mail2.com"] },
  { name: "beehiiv", domains: ["beehiiv.com"] },
  { name: "Substack", domains: ["substack.com"] },
  { name: "Resend", domains: ["resend.com", "resend.dev"] },
  { name: "Loops", domains: ["loops.so"] },
  { name: "Zoho Campaigns", domains: ["zcsend.net", "zohocampaigns.com"] },
];

const hostMatches = (host, pattern) =>
  pattern instanceof RegExp ? pattern.test(host) : host === pattern || host.endsWith(`.${pattern}`);

function collectHosts(lines, originalHtml) {
  const fromHeaderDomains = (key) => {
    const out = [];
    for (const v of headerValues(lines, key)) {
      for (const m of v.matchAll(/[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})|https?:\/\/([a-z0-9.-]+)/gi)) out.push((m[1] || m[2]).toLowerCase());
    }
    return out;
  };
  const dkim = [];
  for (const v of headerValues(lines, "dkim-signature")) {
    const d = cleanDomain(parseTags(v).d);
    if (d) dkim.push(d);
  }
  const received = [];
  for (const v of headerValues(lines, "received")) {
    const from = v.match(/^from\s+(\S+)/i);
    if (from && from[1]) received.push(from[1].replace(/[\[\]()]/g, "").toLowerCase());
    const rdns = v.match(/\(([a-z0-9.-]+\.[a-z]{2,})\s*\[/i);
    if (rdns) received.push(rdns[1].toLowerCase());
  }
  const links = new Set();
  for (const m of (originalHtml || "").matchAll(/(?:href|src)\s*=\s*["']https?:\/\/([^\/"':?#]+)/gi)) {
    links.add(m[1].toLowerCase());
    if (links.size >= 300) break;
  }
  const messageIds = headerValues(lines, "message-id");
  return {
    returnPath: fromHeaderDomains("return-path"),
    sender: fromHeaderDomains("sender"),
    listUnsubscribe: fromHeaderDomains("list-unsubscribe"),
    dkim,
    received,
    links: [...links],
    messageIds,
    messageIdHosts: messageIds.flatMap((v) => [...v.matchAll(/@([^>\s]+)/g)].map((m) => m[1].toLowerCase())),
  };
}

function detectEsp(lines, originalHtml) {
  const hosts = collectHosts(lines, originalHtml);
  const headerNames = new Set(lines.map((h) => h.key));
  const mailers = ["x-mailer", "user-agent", "x-mail-service"].flatMap((k) => headerValues(lines, k));

  const domainSources = [
    ["Return-Path domain", hosts.returnPath, 3],
    ["DKIM signing domain (d=)", hosts.dkim, 3],
    ["List-Unsubscribe domain", hosts.listUnsubscribe, 3],
    ["Sender domain", hosts.sender, 3],
    ["Message-ID domain", hosts.messageIdHosts, 3],
    ["Received-from host", hosts.received, 2],
    ["Link/image domain in the HTML", hosts.links, 1],
  ];

  const candidates = [];
  for (const esp of ESPS) {
    let score = 0;
    let strong = false;
    const evidence = [];
    for (const [label, list, weight] of domainSources) {
      for (const host of new Set(list)) {
        if ((esp.domains || []).some((p) => hostMatches(host, p))) {
          score += weight;
          if (weight >= 3) strong = true;
          evidence.push(`${label}: ${host}`);
        }
      }
    }
    for (const prefix of esp.headers || []) {
      const hit = [...headerNames].find((n) => n === prefix || (prefix.endsWith("-") && n.startsWith(prefix)));
      if (hit) {
        score += 4;
        strong = true;
        evidence.push(`Header: ${hit}`);
      }
    }
    if (esp.mailer) {
      const hit = mailers.find((m) => esp.mailer.test(m));
      if (hit) {
        score += 4;
        strong = true;
        evidence.push(`X-Mailer: ${truncate(hit, 60)}`);
      }
    }
    if (esp.messageId && hosts.messageIds.some((m) => esp.messageId.test(m))) {
      score += 3;
      strong = true;
      evidence.push("Message-ID format");
    }
    if (score > 0) {
      candidates.push({ name: esp.name, score, strong, evidence });
    }
  }
  if (!candidates.length) return null;

  candidates.sort((a, b) => b.score - a.score);
  const confidence = (c) => (c.score >= 6 ? "high" : c.strong ? "likely" : "possible");
  const [top, ...others] = candidates;
  return {
    name: top.name,
    confidence: confidence(top),
    evidence: top.evidence.slice(0, 6),
    others: others.slice(0, 3).map((c) => ({ name: c.name, confidence: confidence(c) })),
  };
}

// ---------------------------------------------------------------------------
// Live DNS record checks
// ---------------------------------------------------------------------------
function makeDnsClient() {
  let budget = MAX_DNS_QUERIES;
  return async function txt(name) {
    if (budget <= 0) return { status: "error", code: "QUERY_LIMIT", records: [] };
    budget--;
    try {
      const records = await resolver.resolveTxt(name);
      return { status: "ok", records: records.map((r) => r.join("")) };
    } catch (err) {
      if (err.code === "ENOTFOUND" || err.code === "ENODATA") return { status: "missing", records: [] };
      return { status: "error", code: err.code || "ERROR", records: [] };
    }
  };
}

const unavailableRow = (what, r) => ({
  level: "info",
  text: `${what} — couldn't be checked`,
  details: [`DNS lookup failed (${r.code}).`],
});

async function countSpfLookups(record, txt, seen, depth) {
  let count = 0;
  let partial = false;
  let all = null;
  let hasRedirect = false;
  for (const token of record.trim().split(/\s+/).slice(1)) {
    const m = token.match(/^([+\-~?])?([a-z0-9]+)([:=/].*)?$/i);
    if (!m) continue;
    const name = m[2].toLowerCase();
    const arg = m[3] ? m[3].slice(1) : "";
    if (name === "all") all = m[1] || "+";
    else if (["a", "mx", "ptr", "exists"].includes(name)) count++;
    else if (name === "include" || name === "redirect") {
      count++;
      if (name === "redirect") hasRedirect = true;
      const candidate = arg.trim().toLowerCase().replace(/\.$/, "");
      const target = DNS_NAME_RE.test(candidate) && !net.isIP(candidate) ? candidate : null;
      if (!target || seen.has(target) || depth >= SPF_LOOKUP_LIMIT) {
        if (target && seen.has(target)) continue;
        partial = true;
        continue;
      }
      seen.add(target);
      const r = await txt(target);
      const spf = r.records.find((x) => /^v=spf1(\s|$)/i.test(x));
      if (r.status === "error") partial = true;
      else if (spf) {
        const inner = await countSpfLookups(spf, txt, seen, depth + 1);
        count += inner.count;
        partial = partial || inner.partial;
        if (name === "redirect") all = inner.all;
      }
    }
  }
  return { count, partial, all, hasRedirect };
}

async function checkSpfRecord(domain, txt) {
  const what = `SPF record for ${domain}`;
  const r = await txt(domain);
  if (r.status === "error") return unavailableRow(what, r);
  const records = r.records.filter((x) => /^v=spf1(\s|$)/i.test(x));
  if (!records.length) {
    return { level: "problem", text: `${what} — not found`, details: ["No TXT record starting with v=spf1 exists for this domain, so receivers can't verify which servers may send for it."] };
  }
  if (records.length > 1) {
    return { level: "problem", text: `${what} — ${records.length} records found`, details: ["A domain must publish exactly one SPF record; several cause SPF to fail with a permanent error."] };
  }
  const record = records[0];
  const { count, partial, all } = await countSpfLookups(record, txt, new Set([domain]), 0);
  const details = [truncate(record, 300)];
  let level = "ok";
  details.push(`${partial ? "At least " : ""}${count} of ${SPF_LOOKUP_LIMIT} allowed DNS lookups used`);
  if (count > SPF_LOOKUP_LIMIT) {
    level = "problem";
    details.push(`More than ${SPF_LOOKUP_LIMIT} DNS lookups makes SPF fail with a permanent error.`);
  }
  if (all === "+" || all === "?") {
    level = "problem";
    details.push(all === "+" ? "Ends with +all, which allows any server to send as this domain." : "Ends with ?all, which says nothing about unlisted servers.");
  } else if (all === "~") {
    details.push("Ends with ~all (soft fail) — common, but -all is stricter.");
  } else if (all === null) {
    details.push("No 'all' mechanism at the end of the record.");
  }
  return { level, text: `${what} — ${level === "ok" ? "found" : "needs attention"}`, details };
}

async function checkDmarcRecord(fromDomain, txt) {
  const what = `DMARC record for ${fromDomain}`;
  let name = `_dmarc.${fromDomain}`;
  let r = await txt(name);
  let usedParent = null;
  const parent = orgDomain(fromDomain);
  if (r.status === "missing" && parent && parent !== fromDomain) {
    usedParent = parent;
    name = `_dmarc.${parent}`;
    r = await txt(name);
  }
  if (r.status === "error") return unavailableRow(what, r);
  const records = r.records.filter((x) => /^v=DMARC1\s*(;|$)/i.test(x));
  if (!records.length) {
    return { level: "problem", text: `${what} — not found`, details: [`No DMARC record was found at _dmarc.${fromDomain}${usedParent ? ` or _dmarc.${usedParent}` : ""}.`] };
  }
  if (records.length > 1) {
    return { level: "problem", text: `${what} — ${records.length} records found`, details: ["Publish exactly one DMARC record; several are ignored."] };
  }
  const tags = parseTags(records[0]);
  const details = [truncate(records[0], 300)];
  if (usedParent) details.push(`Found on the parent domain (${usedParent}).`);
  if (!tags.p) {
    return { level: "problem", text: `${what} — invalid`, details: [...details, "The record has no p= policy tag."] };
  }
  const policy = tags.p.toLowerCase();
  if (policy === "none") details.push("Policy is none: monitoring only, receivers aren't told to act on failures.");
  if (tags.pct && Number(tags.pct) < 100) details.push(`Only applies to ${tags.pct}% of messages (pct=${tags.pct}).`);
  return { level: "ok", text: `${what} — found (policy ${policy})`, details };
}

function keyStrength(publicKeyB64) {
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(publicKeyB64, "base64"), format: "der", type: "spki" });
    return { type: key.asymmetricKeyType, bits: key.asymmetricKeyDetails && key.asymmetricKeyDetails.modulusLength };
  } catch {
    return null;
  }
}

async function checkDkimKey(domain, selector, txt) {
  const name = `${selector}._domainkey.${domain}`;
  const what = `DKIM key ${name}`;
  const r = await txt(name);
  if (r.status === "error") return unavailableRow(what, r);
  const rec = r.records.find((x) => /(^|;)\s*p=/i.test(x));
  if (!rec) {
    return { level: "problem", text: `${what} — not found`, details: ["The email was signed with this selector, but no public key is published for it in DNS."] };
  }
  const tags = parseTags(rec);
  const p = (tags.p || "").replace(/\s+/g, "");
  if (!p) return { level: "problem", text: `${what} — key revoked`, details: ["The record's p= value is empty, which means the key has been revoked. Signatures using it can't verify."] };
  const details = [];
  let level = "ok";
  if ((tags.k || "rsa").toLowerCase() === "rsa") {
    const strength = keyStrength(p);
    if (!strength) details.push("A key is published, but it couldn't be parsed to check its strength.");
    else if (strength.bits && strength.bits < 1024) {
      level = "problem";
      details.push(`${strength.bits}-bit RSA key — too weak; use 2048-bit.`);
    } else if (strength.bits === 1024) {
      details.push("1024-bit RSA key — works, but 2048-bit is recommended.");
    } else if (strength.bits) details.push(`${strength.bits}-bit RSA key.`);
  } else details.push(`Key type: ${tags.k}.`);
  if (/(^|:)y(:|$)/i.test(tags.t || "")) details.push("The record is flagged as testing mode (t=y).");
  return { level, text: `${what} — ${level === "ok" ? "found" : "needs attention"}`, details };
}

async function checkDns({ fromDomain, spfDomain, dkimSignatures }) {
  const txt = makeDnsClient();
  const jobs = [];
  if (fromDomain) jobs.push(checkDmarcRecord(fromDomain, txt));
  if (spfDomain) jobs.push(checkSpfRecord(spfDomain, txt));
  for (const { domain, selector } of dkimSignatures) jobs.push(checkDkimKey(domain, selector, txt));
  const settle = (p) => p.catch(() => ({ level: "info", text: "A DNS check couldn't be completed", details: [] }));
  const timeout = new Promise((resolve) => setTimeout(() => resolve(null), OVERALL_TIMEOUT_MS).unref());
  const all = Promise.all(jobs.map(settle));
  const rows = await Promise.race([all, timeout]);
  return rows || [{ level: "info", text: "DNS checks timed out", details: ["The DNS lookups took too long, so they were skipped."] }];
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------
async function analyzeDeliverability({ headerLines, fromAddress, originalHtml }) {
  const lines = Array.isArray(headerLines) ? headerLines : [];
  const fromDomain = cleanDomain(fromAddress);
  const returnPathDomain = cleanDomain(headerValues(lines, "return-path")[0]);

  const authentication = authenticationFromHeaders(lines, fromDomain);
  const esp = detectEsp(lines, originalHtml);

  const dkimSignatures = [];
  const seen = new Set();
  for (const value of headerValues(lines, "dkim-signature")) {
    const tags = parseTags(value);
    const domain = cleanDomain(tags.d);
    const selector = tags.s && SELECTOR_RE.test(tags.s.trim()) ? tags.s.trim() : null;
    if (!domain || !selector || seen.has(`${selector}|${domain}`)) continue;
    seen.add(`${selector}|${domain}`);
    dkimSignatures.push({ domain, selector });
    if (dkimSignatures.length >= MAX_DKIM_SIGNATURES) break;
  }

  const spfDomain = authentication.spfDomain || returnPathDomain || fromDomain;
  const dnsRows = await checkDns({ fromDomain, spfDomain, dkimSignatures });

  const identity = { fromDomain, returnPathDomain };
  const findings = [...authentication.rows, ...dnsRows]
    .filter((row) => row.level === "problem")
    .map((row) => ({ level: "problem", text: row.summary || row.text }));

  return { esp, identity, authentication, dns: { rows: dnsRows }, findings };
}

module.exports = { analyzeDeliverability, parseAuthResults, detectEsp, cleanDomain };
