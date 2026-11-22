"use strict";

/*
 * Local front end for the ICS 3201 password manager.
 *
 * This is NOT part of the assignment submission. It wraps the graded library
 * in password-manager.js without modifying it, and adds the one thing the
 * handout deliberately leaves out: a disk layer.
 *
 * Run:  node frontend/server.js     then open http://localhost:3000
 *
 * No npm dependencies -- Node's built-in http/fs/crypto only.
 */

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const { Keychain } = require("../password-manager");

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");
const VAULT_DIR = path.join(__dirname, "vault");

const VAULT_FILE = path.join(VAULT_DIR, "vault.json");
const CHECKSUM_FILE = path.join(VAULT_DIR, "trusted-checksum.txt");
const PREV_FILE = path.join(VAULT_DIR, "vault.previous.json");
const GOOD_FILE = path.join(VAULT_DIR, "vault.known-good.json");
const GOOD_CHECKSUM = path.join(VAULT_DIR, "vault.known-good.checksum.txt");

/* ---- session state (memory only; cleared when the vault is locked) ---- */

let keychain = null;
let sessionDomains = [];   // the library cannot enumerate domains -- see README note

/* ---- helpers ---- */

function sha256Base64(text) {
  return crypto.createHash("sha256").update(Buffer.from(text)).digest("base64");
}

function vaultExists() {
  return fs.existsSync(VAULT_FILE) && fs.existsSync(CHECKSUM_FILE);
}

function readVaultFiles() {
  return {
    repr: fs.readFileSync(VAULT_FILE, "utf8"),
    checksum: fs.readFileSync(CHECKSUM_FILE, "utf8").trim()
  };
}

/**
 * Writes the keychain to "disk". The checksum goes in a separate file,
 * standing in for the trusted storage the handout assumes (a flash drive
 * on the user's person).
 */
async function persist() {
  fs.mkdirSync(VAULT_DIR, { recursive: true });

  // Keep the previous state so the rollback attack has something to roll back to.
  if (fs.existsSync(VAULT_FILE)) {
    fs.copyFileSync(VAULT_FILE, PREV_FILE);
  }

  const [repr, checksum] = await keychain.dump();
  fs.writeFileSync(VAULT_FILE, repr);
  fs.writeFileSync(CHECKSUM_FILE, checksum);

  // A clean copy so a simulated attack can be undone.
  fs.writeFileSync(GOOD_FILE, repr);
  fs.writeFileSync(GOOD_CHECKSUM, checksum);
}

/**
 * Describes what is actually stored on disk, for the right-hand panel.
 * Everything here is what an adversary with the disk would see.
 */
function inspectDisk() {
  if (!vaultExists()) {
    return { exists: false, records: [], checksum: null, salt: null };
  }
  const { repr, checksum } = readVaultFiles();
  let parsed;
  try {
    parsed = JSON.parse(repr);
  } catch (e) {
    return { exists: true, corrupt: true, records: [], checksum, salt: null };
  }
  const records = Object.getOwnPropertyNames(parsed.kvs || {}).map((slot) => ({
    slot,
    data: parsed.kvs[slot],
    length: String(parsed.kvs[slot]).length
  }));
  return {
    exists: true,
    records,
    checksum,
    salt: parsed.salt || null,
    bytesOnDisk: Buffer.byteLength(repr)
  };
}

function trackDomain(name) {
  if (!sessionDomains.includes(name)) sessionDomains.push(name);
}

/* ---- API ---- */

const routes = {

  "GET /api/state": async () => ({
    vaultExists: vaultExists(),
    unlocked: keychain !== null,
    domains: keychain ? sessionDomains : [],
    disk: inspectDisk()
  }),

  "POST /api/create": async (body) => {
    if (!body.password) throw "Enter a master password.";
    keychain = await Keychain.init(body.password);
    sessionDomains = [];
    // Clear any stale attack artifacts from a previous run.
    for (const f of [PREV_FILE, GOOD_FILE, GOOD_CHECKSUM]) {
      if (fs.existsSync(f)) fs.unlinkSync(f);
    }
    await persist();
    return { unlocked: true };
  },

  "POST /api/unlock": async (body) => {
    if (!vaultExists()) throw "No vault on disk yet. Create one first.";
    const { repr, checksum } = readVaultFiles();
    // The checksum comes from trusted storage, so it is always supplied here.
    keychain = await Keychain.load(body.password, repr, checksum);
    sessionDomains = [];
    return { unlocked: true };
  },

  "POST /api/lock": async () => {
    keychain = null;
    sessionDomains = [];
    return { unlocked: false };
  },

  "POST /api/set": async (body) => {
    if (!keychain) throw "Unlock the vault first.";
    if (!body.domain) throw "Enter a domain.";
    if (!body.password) throw "Enter a password to store.";
    await keychain.set(body.domain, body.password);
    trackDomain(body.domain);
    await persist();
    return { saved: body.domain };
  },

  "POST /api/get": async (body) => {
    if (!keychain) throw "Unlock the vault first.";
    if (!body.domain) throw "Enter a domain to look up.";
    const value = await keychain.get(body.domain);
    if (value !== null) trackDomain(body.domain);
    return { domain: body.domain, value };
  },

  "POST /api/remove": async (body) => {
    if (!keychain) throw "Unlock the vault first.";
    const removed = await keychain.remove(body.domain);
    if (removed) {
      sessionDomains = sessionDomains.filter((d) => d !== body.domain);
      await persist();
    }
    return { removed };
  },

  /* ---- attack simulations ----
     Each one rewrites the vault the way an adversary with disk access would,
     then recomputes the trusted checksum to MATCH, except for the rollback
     case. That is deliberate: it means the swap and tamper demos cannot be
     caught by the checksum, so only the AES-GCM associated-data binding can
     catch them. This is the independence the handout requires. */

  "POST /api/attack/swap": async () => {
    if (!vaultExists()) throw "No vault to attack.";
    const { repr } = readVaultFiles();
    const obj = JSON.parse(repr);
    const slots = Object.getOwnPropertyNames(obj.kvs);
    if (slots.length < 2) throw "Store at least two entries before swapping.";

    const tmp = obj.kvs[slots[0]];
    obj.kvs[slots[0]] = obj.kvs[slots[1]];
    obj.kvs[slots[1]] = tmp;

    const tampered = JSON.stringify(obj);
    fs.writeFileSync(VAULT_FILE, tampered);
    fs.writeFileSync(CHECKSUM_FILE, sha256Base64(tampered)); // checksum made to agree

    keychain = null;
    sessionDomains = [];
    return {
      note: "Two records were swapped and the checksum was recomputed to match. The integrity check will pass; only the per-record binding can catch this."
    };
  },

  "POST /api/attack/tamper": async () => {
    if (!vaultExists()) throw "No vault to attack.";
    const { repr } = readVaultFiles();
    const obj = JSON.parse(repr);
    const slots = Object.getOwnPropertyNames(obj.kvs);
    if (slots.length < 1) throw "Store an entry before tampering.";

    const bytes = Buffer.from(obj.kvs[slots[0]], "base64");
    bytes[bytes.length - 1] ^= 0xff;
    obj.kvs[slots[0]] = bytes.toString("base64");

    const tampered = JSON.stringify(obj);
    fs.writeFileSync(VAULT_FILE, tampered);
    fs.writeFileSync(CHECKSUM_FILE, sha256Base64(tampered)); // checksum made to agree

    keychain = null;
    sessionDomains = [];
    return {
      note: "One byte of a ciphertext was flipped and the checksum was recomputed to match."
    };
  },

  "POST /api/attack/rollback": async () => {
    if (!fs.existsSync(PREV_FILE)) {
      throw "Save at least two changes first, so there is an earlier version to restore.";
    }
    // The adversary restores an old vault but cannot reach the trusted checksum.
    fs.copyFileSync(PREV_FILE, VAULT_FILE);

    keychain = null;
    sessionDomains = [];
    return {
      note: "An earlier version of the vault was restored. The trusted checksum still describes the current version, so it was left alone."
    };
  },

  "POST /api/restore": async () => {
    if (!fs.existsSync(GOOD_FILE)) throw "No clean copy saved yet.";
    fs.copyFileSync(GOOD_FILE, VAULT_FILE);
    fs.copyFileSync(GOOD_CHECKSUM, CHECKSUM_FILE);
    keychain = null;
    sessionDomains = [];
    return { restored: true };
  }
};

/* ---- plumbing ---- */

function serveStatic(req, res) {
  const rel = req.url === "/" ? "index.html" : decodeURIComponent(req.url.slice(1));
  const file = path.join(PUBLIC_DIR, rel);

  // Keep the handler inside public/.
  if (!file.startsWith(PUBLIC_DIR) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
    res.writeHead(404, { "Content-Type": "text/plain" });
    return res.end("Not found");
  }
  const types = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript" };
  res.writeHead(200, { "Content-Type": types[path.extname(file)] || "application/octet-stream" });
  fs.createReadStream(file).pipe(res);
}

const server = http.createServer((req, res) => {
  const key = `${req.method} ${req.url.split("?")[0]}`;

  if (!routes[key]) return serveStatic(req, res);

  let raw = "";
  req.on("data", (chunk) => {
    raw += chunk;
    if (raw.length > 1e6) req.destroy();
  });
  req.on("end", async () => {
    let body = {};
    if (raw) {
      try { body = JSON.parse(raw); } catch (e) { body = {}; }
    }
    try {
      const result = await routes[key](body);
      const state = {
        vaultExists: vaultExists(),
        unlocked: keychain !== null,
        domains: keychain ? sessionDomains : [],
        disk: inspectDisk()
      };
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, ...result, state }));
    } catch (e) {
      // The library throws strings; everything else stringifies fine too.
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        ok: false,
        error: typeof e === "string" ? e : (e && e.message) || String(e),
        state: {
          vaultExists: vaultExists(),
          unlocked: keychain !== null,
          domains: keychain ? sessionDomains : [],
          disk: inspectDisk()
        }
      }));
    }
  });
});

server.listen(PORT, () => {
  console.log(`\n  Keychain front end running at http://localhost:${PORT}`);
  console.log(`  Vault files: ${VAULT_DIR}`);
  console.log(`  Press Ctrl+C to stop.\n`);
});
