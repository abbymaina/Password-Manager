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
 * No npm dependencies -- Node's built-in http/fs/crypto/sqlite only.
 * The vault is stored in SQLite (frontend/vault/vault.db); see db.js.
 */

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const { Keychain } = require("../password-manager");
const { VaultStore } = require("./db");

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");
const VAULT_DIR = path.join(__dirname, "vault");

const store = new VaultStore(VAULT_DIR);

/* ---- session state (memory only; cleared when the vault is locked) ---- */

let keychain = null;
let sessionDomains = [];   // the library cannot enumerate domains -- see README note

/* ---- helpers ---- */

function sha256Base64(text) {
  return crypto.createHash("sha256").update(Buffer.from(text)).digest("base64");
}

function vaultExists() {
  return store.hasVault();
}

function readVault() {
  return { repr: store.readRepr(), checksum: store.readChecksum() };
}

/**
 * Writes the keychain to the database. The checksum goes in a separate file,
 * standing in for the trusted storage the handout assumes (a flash drive
 * on the user's person).
 */
async function persist() {
  // Keep the previous state so the rollback attack has something to roll back to.
  const current = store.readRepr();
  if (current !== null) store.setSnapshot("previous", current);

  const [repr, checksum] = await keychain.dump();
  store.writeRepr(repr);
  store.writeChecksum(checksum);

  // A clean copy so a simulated attack can be undone.
  store.setSnapshot("known-good", repr, checksum);
}

/**
 * Describes what is actually stored in the database, for the right-hand panel.
 * Everything here is what an adversary with the disk would see.
 */
function inspectDisk() {
  if (!vaultExists()) {
    return { exists: false, records: [], checksum: null, salt: null };
  }
  const records = store.records().map((r) => ({
    slot: r.slot,
    data: r.ciphertext,
    length: r.ciphertext.length
  }));
  return {
    exists: true,
    records,
    checksum: store.readChecksum(),
    salt: store.salt(),
    bytesOnDisk: store.sizeBytes()
  };
}

function getState() {
  return {
    vaultExists: vaultExists(),
    unlocked: keychain !== null,
    domains: keychain ? sessionDomains : [],
    disk: inspectDisk()
  };
}

function trackDomain(name) {
  if (!sessionDomains.includes(name)) sessionDomains.push(name);
}

/* ---- API ---- */

const routes = {

  "GET /api/state": async () => getState(),

  "POST /api/create": async (body) => {
    if (!body.password) throw "Enter a master password.";
    keychain = await Keychain.init(body.password);
    sessionDomains = [];
    await persist();
    // A brand-new vault has no earlier version to roll back to.
    store.clearSnapshots();
    store.setSnapshot("known-good", ...(await keychain.dump()));
    return { unlocked: true };
  },

  "POST /api/unlock": async (body) => {
    if (!vaultExists()) throw "No vault on disk yet. Create one first.";
    const { repr, checksum } = readVault();
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
    const rows = store.records();
    if (rows.length < 2) throw "Store at least two entries before swapping.";

    // UPDATE the two rows directly, as someone with the database file would.
    store.swapCiphertexts(rows[0].slot, rows[1].slot);
    store.writeChecksum(sha256Base64(store.readRepr())); // checksum made to agree

    keychain = null;
    sessionDomains = [];
    return {
      note: "Two records were swapped and the checksum was recomputed to match. The integrity check will pass; only the per-record binding can catch this."
    };
  },

  "POST /api/attack/tamper": async () => {
    if (!vaultExists()) throw "No vault to attack.";
    const rows = store.records();
    if (rows.length < 1) throw "Store an entry before tampering.";

    const bytes = Buffer.from(rows[0].ciphertext, "base64");
    bytes[bytes.length - 1] ^= 0xff;
    store.setCiphertext(rows[0].slot, bytes.toString("base64"));
    store.writeChecksum(sha256Base64(store.readRepr())); // checksum made to agree

    keychain = null;
    sessionDomains = [];
    return {
      note: "One byte of a ciphertext was flipped and the checksum was recomputed to match."
    };
  },

  "POST /api/attack/rollback": async () => {
    const prev = store.getSnapshot("previous");
    if (!prev) {
      throw "Save at least two changes first, so there is an earlier version to restore.";
    }
    // The adversary restores an old vault but cannot reach the trusted checksum.
    store.writeRepr(prev.repr);

    keychain = null;
    sessionDomains = [];
    return {
      note: "An earlier version of the vault was restored. The trusted checksum still describes the current version, so it was left alone."
    };
  },

  "POST /api/restore": async () => {
    const good = store.getSnapshot("known-good");
    if (!good) throw "No clean copy saved yet.";
    store.writeRepr(good.repr);
    store.writeChecksum(good.checksum);
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
    let payload;
    try {
      const result = await routes[key](body);
      payload = { ok: true, ...result, state: getState() };
    } catch (e) {
      // The library throws strings; everything else stringifies fine too.
      payload = {
        ok: false,
        error: typeof e === "string" ? e : (e && e.message) || String(e),
        state: getState()
      };
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(payload));
  });
});

server.listen(PORT, () => {
  console.log(`\n  Keychain front end running at http://localhost:${PORT}`);
  console.log(`  Vault database: ${store.dbFile}`);
  console.log(`  Trusted checksum: ${store.checksumFile}`);
  console.log(`  Press Ctrl+C to stop.\n`);
});
