"use strict";

/*
 * SQLite storage for the front end's vault.
 *
 * Uses Node's built-in node:sqlite module (Node 22.13+), so there is still no
 * npm dependency. Not part of the submission.
 *
 * What lives where:
 *
 *   frontend/vault/vault.db               this database (the untrusted disk)
 *     vault_meta   one row: the PBKDF2 salt and the password verifier
 *     records      one row per entry: HMAC slot key -> IV || AES-GCM ciphertext
 *     snapshots    earlier serialized vaults, used by the attack demos
 *
 *   frontend/vault/trusted-checksum.txt   NOT in the database, on purpose.
 *     It stands in for the trusted storage the rollback defense assumes. If it
 *     lived in the same database, an adversary who rolls back the database
 *     would roll back the checksum with it.
 *
 * The library speaks only in the string from dump(). writeRepr() splits that
 * string into rows, and readRepr() rebuilds the identical string, so the
 * SHA-256 checksum still matches. writeRepr() checks this on every save.
 */

const fs = require("fs");
const path = require("path");
const { DatabaseSync } = require("node:sqlite");

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS vault_meta (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    salt        TEXT NOT NULL,
    verifier    TEXT NOT NULL,
    updated_at  TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS records (
    position    INTEGER PRIMARY KEY,
    slot        TEXT NOT NULL UNIQUE,
    ciphertext  TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS snapshots (
    name        TEXT PRIMARY KEY CHECK (name IN ('previous', 'known-good')),
    repr        TEXT NOT NULL,
    checksum    TEXT,
    saved_at    TEXT NOT NULL
  );
`;

function now() {
  return new Date().toISOString();
}

class VaultStore {
  constructor(dir) {
    this.dir = dir;
    this.dbFile = path.join(dir, "vault.db");
    this.checksumFile = path.join(dir, "trusted-checksum.txt");

    fs.mkdirSync(dir, { recursive: true });
    this.db = new DatabaseSync(this.dbFile);
    this.db.exec("PRAGMA journal_mode = DELETE;");   // keep everything in the one vault.db file
    this.db.exec(SCHEMA);

    this.migrateFromJsonFiles();
  }

  /* ---- transactions ---- */

  transaction(fn) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }

  /* ---- the current vault ---- */

  hasVault() {
    const meta = this.db.prepare("SELECT 1 FROM vault_meta WHERE id = 1").get();
    return Boolean(meta) && fs.existsSync(this.checksumFile);
  }

  /** Rebuilds the exact string dump() produced. */
  readRepr() {
    const meta = this.db.prepare("SELECT salt, verifier FROM vault_meta WHERE id = 1").get();
    if (!meta) return null;
    const kvs = {};
    for (const row of this.db.prepare("SELECT slot, ciphertext FROM records ORDER BY position").all()) {
      kvs[row.slot] = row.ciphertext;
    }
    return JSON.stringify({ kvs, salt: meta.salt, verifier: meta.verifier });
  }

  /** Splits a dump() string into rows, replacing whatever was there. */
  writeRepr(repr) {
    const parsed = JSON.parse(repr);
    if (!parsed || typeof parsed.kvs !== "object" ||
        typeof parsed.salt !== "string" || typeof parsed.verifier !== "string") {
      throw new Error("Not a vault serialization.");
    }

    this.transaction(() => {
      this.db.exec("DELETE FROM records");
      const insert = this.db.prepare(
        "INSERT INTO records (position, slot, ciphertext) VALUES (?, ?, ?)"
      );
      Object.getOwnPropertyNames(parsed.kvs).forEach((slot, i) => {
        insert.run(i, slot, String(parsed.kvs[slot]));
      });
      this.db.prepare(`
        INSERT INTO vault_meta (id, salt, verifier, updated_at) VALUES (1, ?, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
          salt = excluded.salt, verifier = excluded.verifier, updated_at = excluded.updated_at
      `).run(parsed.salt, parsed.verifier, now());

      // The checksum is over the exact string, so the rebuild must match byte for byte.
      if (this.readRepr() !== repr) {
        throw new Error("Database round trip changed the vault serialization.");
      }
    });
  }

  records() {
    return this.db.prepare("SELECT slot, ciphertext FROM records ORDER BY position").all();
  }

  salt() {
    const meta = this.db.prepare("SELECT salt FROM vault_meta WHERE id = 1").get();
    return meta ? meta.salt : null;
  }

  /** Direct row edits, the way an adversary with the database file would work. */
  setCiphertext(slot, ciphertext) {
    this.db.prepare("UPDATE records SET ciphertext = ? WHERE slot = ?").run(ciphertext, slot);
  }

  swapCiphertexts(slotA, slotB) {
    this.transaction(() => {
      const get = this.db.prepare("SELECT ciphertext FROM records WHERE slot = ?");
      const a = get.get(slotA).ciphertext;
      const b = get.get(slotB).ciphertext;
      this.setCiphertext(slotA, b);
      this.setCiphertext(slotB, a);
    });
  }

  sizeBytes() {
    return fs.existsSync(this.dbFile) ? fs.statSync(this.dbFile).size : 0;
  }

  /* ---- trusted checksum (separate file, see header) ---- */

  readChecksum() {
    return fs.existsSync(this.checksumFile)
      ? fs.readFileSync(this.checksumFile, "utf8").trim()
      : null;
  }

  writeChecksum(checksum) {
    fs.writeFileSync(this.checksumFile, checksum);
  }

  /* ---- snapshots for the attack demos ---- */

  getSnapshot(name) {
    return this.db.prepare("SELECT repr, checksum FROM snapshots WHERE name = ?").get(name) || null;
  }

  setSnapshot(name, repr, checksum = null) {
    this.db.prepare(`
      INSERT INTO snapshots (name, repr, checksum, saved_at) VALUES (?, ?, ?, ?)
      ON CONFLICT (name) DO UPDATE SET
        repr = excluded.repr, checksum = excluded.checksum, saved_at = excluded.saved_at
    `).run(name, repr, checksum, now());
  }

  clearSnapshots() {
    this.db.exec("DELETE FROM snapshots");
  }

  close() {
    this.db.close();
  }

  /* ---- one-time import of the old JSON-file vault ---- */

  migrateFromJsonFiles() {
    const legacy = {
      vault: path.join(this.dir, "vault.json"),
      previous: path.join(this.dir, "vault.previous.json"),
      good: path.join(this.dir, "vault.known-good.json"),
      goodChecksum: path.join(this.dir, "vault.known-good.checksum.txt")
    };
    if (!fs.existsSync(legacy.vault) || this.readRepr() !== null) return;

    this.writeRepr(fs.readFileSync(legacy.vault, "utf8"));
    if (fs.existsSync(legacy.previous)) {
      this.setSnapshot("previous", fs.readFileSync(legacy.previous, "utf8"));
    }
    if (fs.existsSync(legacy.good) && fs.existsSync(legacy.goodChecksum)) {
      this.setSnapshot(
        "known-good",
        fs.readFileSync(legacy.good, "utf8"),
        fs.readFileSync(legacy.goodChecksum, "utf8").trim()
      );
    }

    // Keep the old files, out of the way, rather than deleting them.
    const backup = path.join(this.dir, "legacy-json");
    fs.mkdirSync(backup, { recursive: true });
    for (const f of Object.values(legacy)) {
      if (fs.existsSync(f)) fs.renameSync(f, path.join(backup, path.basename(f)));
    }
    console.log(`  Imported the old JSON vault into ${this.dbFile}`);
    console.log(`  (originals moved to ${backup})`);
  }
}

/* ---- several vaults, one folder each: frontend/vault/<name>/ ---- */

const NAME_PATTERN = /^[a-z0-9][a-z0-9_-]{0,31}$/;

function isValidName(name) {
  return typeof name === "string" && NAME_PATTERN.test(name);
}

/** Names of the vaults under root, i.e. the subfolders that contain a vault.db. */
function listVaults(root) {
  if (!fs.existsSync(root)) return [];
  return fs.readdirSync(root, { withFileTypes: true })
    .filter((d) => d.isDirectory() && isValidName(d.name) &&
                   fs.existsSync(path.join(root, d.name, "vault.db")))
    .map((d) => d.name)
    .sort();
}

/**
 * Earlier versions kept a single vault directly in root. Move it into
 * root/demo/ so it becomes one named vault among others.
 */
function migrateSingleVault(root, name = "demo") {
  const loose = ["vault.db", "vault.db-journal", "trusted-checksum.txt", "legacy-json"]
    .filter((f) => fs.existsSync(path.join(root, f)));
  if (!loose.includes("vault.db")) return;
  const dest = path.join(root, name);
  fs.mkdirSync(dest, { recursive: true });
  for (const f of loose) fs.renameSync(path.join(root, f), path.join(dest, f));
  console.log(`  Moved the existing vault to ${dest}`);
}

module.exports = { VaultStore, isValidName, listVaults, migrateSingleVault };
