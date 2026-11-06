// Decrypts one blob in this browser. The key stays in the URL fragment, which browsers do not send
// to the server. This protects against a passive host only: a host that rewrites this file could
// read the key, so verify.py exists to check a build outside the browser.
import { Decrypter, identityToRecipient, ed25519 } from "./vendor/facet-crypto.js";

const app = document.getElementById("app");

function el(tag, props = {}, ...children) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

function fail(message) {
  app.replaceChildren(el("p", { className: "status error", textContent: message }));
}

const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (bytes) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha256 = async (data) => hex(await crypto.subtle.digest("SHA-256", data));

async function fetchBytes(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

function unpad(padded) {
  const length = new DataView(padded.buffer, padded.byteOffset).getUint32(0);
  return padded.subarray(4, 4 + length);
}

function parseFragment() {
  const params = new URLSearchParams(location.hash.slice(1));
  const r = params.get("r");
  const state = r ? JSON.parse(atob(r.replace(/-/g, "+").replace(/_/g, "/"))) : {};
  return { key: params.get("k"), knownUrls: state.known_urls ?? [], mutedTopics: state.muted_topics ?? [] };
}

// The recipient's own filter. It runs here, and the sender never learns the outcome.
function applyFilter(items, { knownUrls, mutedTopics }) {
  const shown = [], skipped = [];
  for (const item of items) {
    const muted = item.topics.filter((t) => mutedTopics.includes(t));
    if (item.source_url && knownUrls.includes(item.source_url)) skipped.push({ item, why: "already read" });
    else if (muted.length) skipped.push({ item, why: `not interested: ${muted.join(", ")}` });
    else shown.push(item);
  }
  return { shown, skipped };
}

function itemList(items) {
  return el("ul", {}, ...items.map((i) => el("li", { textContent: i.text })));
}

function renderView(payload, fragment) {
  const { shown, skipped } = applyFilter(payload.items, fragment);
  app.replaceChildren(
    el("h1", { textContent: `From ${payload.person}` }),
    el("p", { className: "sub", textContent: `Update for ${payload.epoch}` }),
    shown.length ? itemList(shown) : el("p", { className: "status", textContent: "Nothing for you this time." }),
  );
  if (skipped.length) {
    const rows = skipped.map(({ item, why }) =>
      el("li", {}, el("span", { className: "tag", textContent: `Skipped by your agent: ${why}` }), item.text));
    app.append(el("h3", { textContent: `${skipped.length} offered, skipped on your side` }),
      el("ul", { className: "skipped" }, ...rows));
  }
  app.append(footer());
}

function traceDetails(view) {
  const { trace } = view;
  const held = trace.decisions.filter((d) => d.action !== "disclose");
  const details = el("details", {},
    el("summary", { textContent: `Trace: ${held.length} held back, ${trace.rounds.length} red-team round(s)` }),
    el("h3", { textContent: "Policy" }), el("p", { textContent: view.policy.rules }),
    el("h3", { textContent: "Held back" }),
    el("ul", {}, ...held.map((d) =>
      el("li", {}, el("span", { className: "tag", textContent: `${d.action} · ${d.category}` }), d.withheld_detail))));
  if (trace.baseline) {
    const free = trace.baseline.hits;
    details.append(el("h3", { textContent: "Baseline: the attacker with an empty update" }),
      el("p", { textContent: free.length
        ? `Guessable from who the reader is alone, so no item is blamed for: ${free.map((h) => `“${h.withheld_fact}”`).join("; ")}`
        : "Nothing private is guessable without the update." }));
  }
  for (const round of trace.rounds) {
    details.append(el("h3", { textContent: `Red-team round ${round.number}` }));
    details.append(el("ul", {}, ...round.guesses.map((g) => el("li", { textContent: `Guess: ${g}` }))));
    if (!round.hits.length) {
      details.append(el("p", { className: "clean", textContent: "Clean: no guess reached a private fact that the update gave away." }));
    }
    for (const hit of round.hits) {
      details.append(el("p", { className: "hit", textContent: `Hit: “${hit.guess}” reveals “${hit.withheld_fact}”. ${hit.rationale}` }));
    }
    for (const hit of round.discounted ?? []) {
      details.append(el("p", { textContent: `Discounted (baseline already reaches it): “${hit.guess}”` }));
    }
    for (const rw of round.rewritten ?? []) {
      details.append(el("p", {}, el("span", { className: "removed", textContent: rw.before.text }), " → ", rw.after.text));
    }
    if (round.removed_items.length) {
      details.append(el("ul", {}, ...round.removed_items.map((i) =>
        el("li", { className: "removed", textContent: i.text }))));
    }
  }
  return details;
}

function renderOwner(payload) {
  app.className = "wide";
  app.replaceChildren(
    el("h1", { textContent: `${payload.person}: one week, ${payload.views.length} audiences` }),
    el("p", { className: "sub", textContent: `Owner view for ${payload.epoch}. Only the owner's key opens this. Each audience's link shows just its own column, without the trace.` }),
    el("div", { className: "grid" }, ...payload.views.map((v) =>
      el("section", { className: "card" },
        el("h2", { textContent: v.view.audience }),
        el("p", { className: "sub", textContent: v.policy.relationship }),
        v.view.items.length ? itemList(v.view.items) : el("p", { className: "status", textContent: "Empty view. The blob is still the same size." }),
        traceDetails(v)))),
    footer());
}

function footer() {
  return el("footer", { textContent: "Decrypted in this browser. The host holds only same-sized ciphertext. Whatever wrote this update saw the whole life-log: encryption starts after generation." });
}

async function loadManifest() {
  const body = await fetchBytes("manifest.json");
  const signature = (new TextDecoder().decode(await fetchBytes("manifest.json.sig"))).trim();
  const pinned = document.querySelector('meta[name="facet-signing-key"]').content;
  if (!ed25519.verify(fromB64(signature), body, fromB64(pinned))) throw new Error("bad signature");
  return JSON.parse(new TextDecoder().decode(body));
}

async function main() {
  const fragment = parseFragment();
  if (!fragment.key) {
    app.replaceChildren(
      el("h1", { textContent: "facet" }),
      el("p", { textContent: "This host stores only encrypted files. Without a key in the link, there is nothing here to read." }));
    return;
  }

  let manifest;
  try {
    manifest = await loadManifest();
  } catch (error) {
    return fail(`Rejected: the manifest failed its signature check (${error.message}).`);
  }

  let aud;
  try {
    const recipient = await identityToRecipient(fragment.key);
    aud = (await sha256(new TextEncoder().encode(recipient))).slice(0, 16);
  } catch {
    return fail("This link's key is malformed.");
  }
  const blob = manifest.blobs.find((b) => b.aud === aud);
  if (!blob) return fail("No update here for this key.");

  const data = await fetchBytes(blob.path);
  if ((await sha256(data)) !== blob.sha256) return fail("Rejected: the blob does not match the signed manifest.");

  try {
    const decrypter = new Decrypter();
    decrypter.addIdentity(fragment.key);
    const payload = JSON.parse(new TextDecoder().decode(unpad(await decrypter.decrypt(data))));
    if (payload.type === "owner") renderOwner(payload);
    else renderView(payload, fragment);
  } catch (error) {
    fail(`Could not decrypt with this key (${error.message}).`);
  }
}

// A different link in the same tab only changes the fragment, which would not re-run this page.
window.addEventListener("hashchange", () => location.reload());
main();
