# Password Manager (ICS 3201, Project 1)

A password manager library written in Node.js. It keeps a set of domain → password
records, encrypts them under a single master password, and can be saved to a string and
loaded back. An adversary who can read or change the saved data cannot learn the
passwords, the domain names or the password lengths. They also cannot swap records,
modify a record or roll the vault back to an older version without being detected.

All cryptography uses the Web Crypto API (`crypto.webcrypto.subtle`) that ships with Node,
so the library has no third-party dependencies.

## Project layout

| Path | Purpose |
| --- | --- |
| `password-manager.js` | The `Keychain` class: the graded submission |
| `lib.js` | Helpers for buffers, Base64 and random bytes |
| `test/test-password-manager.js` | Tests for basic features and security |
| `test/test-security-extra.js` | Tests for swap, rollback, length hiding and the master password |
| `frontend/` | Optional local web app built on the library (not part of the submission) |

## How to run it

**Requirements:** Node.js 18 or newer (developed with Node 26) and npm.

```
npm install      # installs the test tools (mocha, expect.js)
npm test         # runs the test suites
```

All 24 tests should pass.

To use the password manager in a browser:

```
npm start        # serves the app at http://localhost:3000
```

Open <http://localhost:3000>. On the first visit, choose a master password to create a new
vault. Stop the server with Ctrl+C.

To start with sample data, run this before `npm start`:

```
npm run seed              # master password: demo1234
npm run seed -- mypw      # or choose your own
```

The vault is saved in `frontend/vault/`. To start over, delete that folder. See
[frontend/README.md](frontend/README.md) for more on the web app.

## Using the library

```js
const { Keychain } = require("./password-manager");

const kc = await Keychain.init("master password");
await kc.set("www.example.com", "hunter2");
await kc.get("www.example.com");          // "hunter2"
await kc.remove("www.example.com");       // true

const [repr, checksum] = await kc.dump(); // serialized vault + SHA-256 checksum
const kc2 = await Keychain.load("master password", repr, checksum);
```

`get` returns `null` for an unknown domain. `remove` returns `false` if there was nothing
to remove. `load` throws an error if the password is wrong or the data has been tampered with.

## How it works

### Key derivation

1. `init` generates a random 16-byte **salt**.
2. **PBKDF2-SHA-256** with 100,000 iterations turns the master password and salt into a
   256-bit master key. This is the only slow step, and it runs once per `init` or `load`.
3. Two independent sub-keys are derived by computing **HMAC-SHA-256** under the master key
   on two fixed labels:
   - `k_mac`, an HMAC key used to hide domain names
   - `k_enc`, an AES-256-GCM key used to encrypt passwords

The master password and the keys are held in memory only. They are never serialized.

### Storing a record

For `set(domain, password)`:

- **Key:** `HMAC(k_mac, domain)`, Base64-encoded. The stored data never contains the
  domain name, and the same domain always maps to the same slot.
- **Value:** `IV || AES-GCM(k_enc, padded password)`, Base64-encoded. Each record gets a fresh
  random 12-byte IV.
  - **Padding:** every password is stored as `[2-byte length][password][zero padding]`,
    padded to 64 bytes. Every ciphertext therefore has the same length, which hides the
    password length.
  - **Associated data:** the record's HMAC key is passed to AES-GCM as associated data,
    which binds each ciphertext to its own slot.

### Serialization

`dump()` returns two strings:

1. A JSON string `{ kvs, salt, verifier }`
2. The SHA-256 checksum of that JSON

`verifier` is a fixed string encrypted under `k_enc`. `load` decrypts it first, so a wrong
master password is rejected even when the vault is empty.

### Defenses

| Attack | Defense |
| --- | --- |
| Reading the vault | Domains appear only as HMAC values. Passwords are AES-GCM encrypted and padded to the same length. |
| Guessing the master password | PBKDF2 with 100,000 iterations and a per-vault random salt slows brute-force guessing and stops precomputed tables. |
| **Swap attack** (moving a ciphertext to another domain's slot) | AES-GCM associated data: the ciphertext fails to decrypt under a different slot key. `load` checks every record, so the swap is caught even without the trusted checksum. |
| **Modified ciphertext** | The AES-GCM authentication tag fails. |
| **Rollback attack** (replacing the vault with an older valid copy) | `load` compares the SHA-256 checksum with the trusted checksum the caller supplies, before doing anything else. |

The swap defense and the rollback defense are independent. The swap defense works without
the checksum, and the checksum alone is enough to detect a rollback.

## Web front end

`frontend/server.js` is a small server built only on Node's built-in `http`, `fs` and
`crypto` modules. It wraps the library and adds a disk layer:

- `frontend/vault/vault.json` holds the output of `dump()[0]`.
- `frontend/vault/trusted-checksum.txt` holds `dump()[1]` in a separate file. It stands in
  for the trusted storage that the rollback defense assumes.

The page can generate random passwords and look up, copy and delete entries. It also has
buttons that **simulate attacks** on the saved vault (swap two records, flip one byte,
roll back) so you can watch each defense reject the tampered vault on the next unlock.
Because the vault stores only HMACs of domain names, the app cannot list saved domains.
It shows only the domains used in the current session.
