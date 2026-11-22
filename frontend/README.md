# Keychain front end

A local web app that turns the graded library into a working password manager.

**This is not part of the submission.** Only `password-manager.js` goes to Gradescope.
Nothing in this folder touches that file — the front end imports it and uses only the
public API (`init`, `load`, `dump`, `set`, `get`, `remove`).

## Run it

```
npm start
```

Then open <http://localhost:3000>. Stop with Ctrl+C.

No npm packages are needed — the server uses only Node's built-in `http`, `fs` and
`crypto`.

To fill the vault with demo data first:

```
npm run seed              # master password: demo1234
npm run seed -- mypw      # or choose your own
```

## Using it

- **Generate** makes a 24-character random password from `crypto.getRandomValues`.
- The counter beside the password field shows **bytes, not characters**, because the
  64-byte limit is a byte limit — a password of accented or non-Latin characters hits it
  sooner than an ASCII one. Save is disabled past 64.
- **Show** reveals either password field; **Copy** puts a looked-up password on the
  clipboard.
- Click any record on the dark side to expand the full slot key and ciphertext.
- Click a domain in the session list to look it up again.

## What it adds

The handout (§2.1) deliberately leaves out the disk layer: the library serializes to a
string instead of writing a file. The front end supplies that layer:

- `frontend/vault/vault.json` — the output of `dump()[0]`
- `frontend/vault/trusted-checksum.txt` — the output of `dump()[1]`, kept in a separate
  file to stand in for the trusted storage the rollback defense assumes

Both are recreated on first run. Delete the `vault/` folder to start over.

## Why there is no list of saved domains

The vault stores `HMAC(k_mac, domain)` as its key, never the domain itself, so the
library has no way to enumerate what is in it — that is the point of the design. The
"this session" list on the left is only what passed through the current session, held
in memory and cleared on lock.

A real product would solve this by storing the domain name inside each record's
authenticated plaintext and rebuilding an index at load time. That is the same
technique described in short-answer question 4.

## Attack simulations

The buttons on the dark panel rewrite the vault the way an adversary with disk access
would, then lock the keychain so you can try to unlock again.

| Button | What it does | Which defense catches it |
| --- | --- | --- |
| Swap two records | Exchanges two ciphertexts between slots, **then recomputes the checksum to match** | AES-GCM associated data |
| Flip one byte | Inverts the last byte of a ciphertext, **then recomputes the checksum to match** | AES-GCM authentication tag |
| Roll back | Restores an older vault, leaving the trusted checksum alone | SHA-256 integrity check |
| Repair the vault | Restores the last known-good vault and checksum | — |

The first two deliberately fix up the checksum so the integrity check passes. That is
what makes them a real demonstration: only the per-record binding can catch them, which
is the independence the handout requires between the swap and rollback defenses.

Storing two entries first is required before the swap demo, and two saves are required
before the rollback demo has an earlier version to restore.
