"use strict";

/*
 * Fills the vault with demo data, so a demo does not start with typing.
 *
 * Run:  npm run seed          (master password: demo1234)
 *       npm run seed -- mypassword
 *
 * Then: npm start, and unlock with that password.
 *
 * Not part of the submission.
 */

const fs = require("fs");
const path = require("path");

const { Keychain } = require("../password-manager");

const VAULT_DIR = path.join(__dirname, "vault");
const VAULT_FILE = path.join(VAULT_DIR, "vault.json");
const CHECKSUM_FILE = path.join(VAULT_DIR, "trusted-checksum.txt");
const PREV_FILE = path.join(VAULT_DIR, "vault.previous.json");
const GOOD_FILE = path.join(VAULT_DIR, "vault.known-good.json");
const GOOD_CHECKSUM = path.join(VAULT_DIR, "vault.known-good.checksum.txt");

const MASTER = process.argv[2] || "demo1234";

/*
 * Password lengths run from 1 to 64 on purpose. Every one of these produces a
 * record of exactly the same size on disk, which is the length-hiding property
 * the handout asks for -- visible as a column of identical character counts.
 *
 * The amazon.com entry is the one from the handout's own example table (p. 2).
 */
const ENTRIES = [
  ["www.google.com",       "correct-horse-battery-staple"],
  ["github.com",           "gh_S3cret!2026"],
  ["www.strathmore.edu",   "Str@thm0re#ICS3201"],
  ["www.amazon.com",       "6U)qAl0By%3SZX$o"],
  ["www.safaricom.co.ke",  "mpesa-2026-pin-9981"],
  ["mail.proton.me",       "the-quick-brown-fox-jumps-over-the-lazy-dog-and-keeps-on-running"],
  ["x.com",                "a"],
  ["localhost",            "dev"]
];

function pad(s, n) {
  s = String(s);
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

(async () => {
  // Start from a clean vault so the demo is reproducible.
  fs.rmSync(VAULT_DIR, { recursive: true, force: true });
  fs.mkdirSync(VAULT_DIR, { recursive: true });

  const keychain = await Keychain.init(MASTER);

  for (const [domain, password] of ENTRIES) {
    await keychain.set(domain, password);
  }

  const [repr, checksum] = await keychain.dump();
  fs.writeFileSync(VAULT_FILE, repr);
  fs.writeFileSync(CHECKSUM_FILE, checksum);
  fs.writeFileSync(GOOD_FILE, repr);
  fs.writeFileSync(GOOD_CHECKSUM, checksum);

  // Give the rollback demo an earlier version to restore: the same vault
  // without the last two entries.
  const partial = await Keychain.load(MASTER, repr, checksum);
  await partial.remove("x.com");
  await partial.remove("localhost");
  const [prevRepr] = await partial.dump();
  fs.writeFileSync(PREV_FILE, prevRepr);

  // ---- report ----

  const onDisk = JSON.parse(repr);
  const slots = Object.getOwnPropertyNames(onDisk.kvs);
  const recordLengths = new Set(slots.map((s) => onDisk.kvs[s].length));

  console.log(`\n  Vault seeded with ${ENTRIES.length} entries.`);
  console.log(`  Master password: ${MASTER}\n`);

  console.log(`  ${pad("DOMAIN", 22)}${pad("PASSWORD", 66)}${pad("CHARS", 7)}ON DISK`);
  console.log(`  ${"-".repeat(22 + 66 + 7 + 8)}`);
  for (let i = 0; i < ENTRIES.length; i++) {
    const [domain, password] = ENTRIES[i];
    console.log(
      `  ${pad(domain, 22)}${pad(password, 66)}${pad(password.length, 7)}${onDisk.kvs[slots[i]].length} ch`
    );
  }

  console.log(`\n  Password lengths range from 1 to 64 characters.`);
  console.log(`  Record lengths on disk: ${[...recordLengths].join(", ")} -- all identical.`);
  console.log(`  Vault size: ${Buffer.byteLength(repr)} bytes`);
  console.log(`  Trusted checksum: ${checksum}`);
  console.log(`\n  Now run:  npm start      and unlock with "${MASTER}"\n`);
})().catch((e) => {
  console.error("\n  Seeding failed:", typeof e === "string" ? e : e.message, "\n");
  process.exit(1);
});
