"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/* Domain separation constants: the two sub-keys are produced by evaluating HMAC
   (used here as a PRF) under the PBKDF2 master key at two fixed, distinct points. */
const SUBKEY_MAC_LABEL = "subkey:domain-mac";
const SUBKEY_AES_LABEL = "subkey:password-encryption";

const SALT_LENGTH = 16;           // 128-bit salt for PBKDF2, as recommended in the handout
const IV_LENGTH = 12;             // 96-bit IV, the recommended nonce size for AES-GCM
const LENGTH_PREFIX_BYTES = 2;    // big-endian length header stored with every padded password
const PADDED_LENGTH = MAX_PASSWORD_LENGTH + LENGTH_PREFIX_BYTES; // every plaintext is exactly this long

/* Fixed sentinel encrypted under the AES-GCM sub-key so that a wrong master
   password is detected even when the keychain holds no records at all. */
const VERIFIER_PLAINTEXT = "keychain-password-verifier";
const VERIFIER_AAD = "keychain-verifier-aad";

/********* Helpers ********/

/**
 * Pads a password out to a constant-length buffer so that the ciphertext
 * stored on disk reveals nothing about the true password length.
 * Layout: [2-byte big-endian length][password bytes][zero padding]
 */
function padPassword(value) {
  const raw = stringToBuffer(value);
  if (raw.length > MAX_PASSWORD_LENGTH) {
    throw "Password exceeds the maximum supported length of " + MAX_PASSWORD_LENGTH + " bytes";
  }
  const padded = Buffer.alloc(PADDED_LENGTH, 0);
  padded.writeUInt16BE(raw.length, 0);
  raw.copy(padded, LENGTH_PREFIX_BYTES);
  return padded;
}

/**
 * Inverse of padPassword: recovers the original password from a padded buffer.
 */
function unpadPassword(buf) {
  const padded = Buffer.from(buf);
  if (padded.length !== PADDED_LENGTH) {
    throw "Tampering detected: decrypted record has an unexpected length";
  }
  const len = padded.readUInt16BE(0);
  if (len > MAX_PASSWORD_LENGTH) {
    throw "Tampering detected: decrypted record declares an invalid length";
  }
  return bufferToString(padded.subarray(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + len));
}

/**
 * Derives the master key and the two sub-keys from a master password and salt.
 * Exactly one PBKDF2 evaluation happens here; the sub-keys come from HMAC,
 * which we rely on as a secure PRF.
 */
async function deriveKeys(password, saltBuffer) {
  const rawKey = await subtle.importKey(
    "raw",
    stringToBuffer(password),
    "PBKDF2",
    false,
    ["deriveKey", "deriveBits"]
  );

  const masterBits = await subtle.deriveBits(
    { name: "PBKDF2", salt: saltBuffer, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    rawKey,
    256
  );

  const masterKey = await subtle.importKey(
    "raw",
    masterBits,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const macBits = await subtle.sign("HMAC", masterKey, stringToBuffer(SUBKEY_MAC_LABEL));
  const aesBits = await subtle.sign("HMAC", masterKey, stringToBuffer(SUBKEY_AES_LABEL));

  const macKey = await subtle.importKey(
    "raw",
    macBits,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );

  const aesKey = await subtle.importKey(
    "raw",
    aesBits,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  return { macKey, aesKey };
}

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   * Arguments:
   *  You may design the constructor with any parameters you would like.
   * Return Type: void
   */
  constructor(secrets, data) {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
      kvs: data.kvs,            // HMAC(domain) -> Base64(IV || AES-GCM ciphertext)
      salt: data.salt,          // Base64 PBKDF2 salt; public by design
      verifier: data.verifier   // Base64(IV || ciphertext) of a fixed sentinel string
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      macKey: secrets.macKey,   // HMAC sub-key used to blind domain names
      aesKey: secrets.aesKey    // AES-GCM sub-key used to encrypt passwords
    };
  };

  /**
   * Computes the KVS lookup key for a domain: a Base64-encoded HMAC of the
   * domain name under the secret MAC sub-key.
   */
  async domainTag(name) {
    const tag = await subtle.sign("HMAC", this.secrets.macKey, stringToBuffer(name));
    return encodeBuffer(tag);
  }

  /**
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    if (typeof password !== "string") {
      throw "The master password must be a string";
    }

    const salt = getRandomBytes(SALT_LENGTH);
    const secrets = await deriveKeys(password, salt);

    // Encrypt the sentinel so that load() can reject a wrong password even on
    // an empty keychain.
    const iv = getRandomBytes(IV_LENGTH);
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: stringToBuffer(VERIFIER_AAD) },
      secrets.aesKey,
      stringToBuffer(VERIFIER_PLAINTEXT)
    );

    return new Keychain(secrets, {
      kvs: {},
      salt: encodeBuffer(salt),
      verifier: encodeBuffer(Buffer.concat([Buffer.from(iv), Buffer.from(ct)]))
    });
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    if (typeof password !== "string") {
      throw "The master password must be a string";
    }

    // --- Rollback defense: verify the trusted checksum before anything else. ---
    if (trustedDataCheck !== undefined) {
      const digest = await subtle.digest("SHA-256", stringToBuffer(repr));
      if (encodeBuffer(digest) !== trustedDataCheck) {
        throw "Integrity check failed: the serialized keychain does not match the trusted checksum (possible rollback or tampering)";
      }
    }

    const parsed = JSON.parse(repr);
    if (parsed === null || typeof parsed !== "object" ||
        typeof parsed.salt !== "string" ||
        typeof parsed.verifier !== "string" ||
        parsed.kvs === null || typeof parsed.kvs !== "object") {
      throw "Tampering detected: malformed keychain serialization";
    }

    const salt = decodeBuffer(parsed.salt);
    const secrets = await deriveKeys(password, salt);

    // --- Password check: the sentinel only decrypts under the right key. ---
    const verifierBytes = decodeBuffer(parsed.verifier);
    let sentinel;
    try {
      sentinel = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: verifierBytes.subarray(0, IV_LENGTH),
          additionalData: stringToBuffer(VERIFIER_AAD)
        },
        secrets.aesKey,
        verifierBytes.subarray(IV_LENGTH)
      );
    } catch (e) {
      throw "Incorrect master password, or the keychain has been tampered with";
    }
    if (bufferToString(sentinel) !== VERIFIER_PLAINTEXT) {
      throw "Incorrect master password, or the keychain has been tampered with";
    }

    const keychain = new Keychain(secrets, {
      kvs: parsed.kvs,
      salt: parsed.salt,
      verifier: parsed.verifier
    });

    // --- Swap defense: every record must authenticate against its own key. ---
    // Each ciphertext was bound to its domain tag via AES-GCM associated data,
    // so a record moved to a different slot fails to decrypt here. This holds
    // whether or not a trusted checksum was supplied.
    for (const tag of Object.getOwnPropertyNames(parsed.kvs)) {
      await keychain.decryptRecord(tag, parsed.kvs[tag]);
    }

    return keychain;
  };

  /**
   * Decrypts one KVS record, authenticating it against the slot it was found
   * in. Throws if the record was moved, modified, or encrypted under a
   * different key.
   */
  async decryptRecord(tag, record) {
    if (typeof record !== "string") {
      throw "Tampering detected: malformed record in the password database";
    }
    const bytes = decodeBuffer(record);
    if (bytes.length <= IV_LENGTH) {
      throw "Tampering detected: truncated record in the password database";
    }
    let plaintext;
    try {
      plaintext = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: bytes.subarray(0, IV_LENGTH),
          additionalData: stringToBuffer(tag)   // binds ciphertext to its domain
        },
        this.secrets.aesKey,
        bytes.subarray(IV_LENGTH)
      );
    } catch (e) {
      throw "Tampering detected: a record failed authentication (possible swap attack or modified ciphertext)";
    }
    return unpadPassword(plaintext);
  }

  /**
    * Returns a JSON serialization of the contents of the keychain that can be
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */
  async dump() {
    const repr = JSON.stringify({
      kvs: this.data.kvs,
      salt: this.data.salt,
      verifier: this.data.verifier
    });
    const digest = await subtle.digest("SHA-256", stringToBuffer(repr));
    return [repr, encodeBuffer(digest)];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    if (typeof name !== "string") {
      throw "The domain name must be a string";
    }
    const tag = await this.domainTag(name);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, tag)) {
      return null;
    }
    return await this.decryptRecord(tag, this.data.kvs[tag]);
  };

  /**
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    if (typeof name !== "string" || typeof value !== "string") {
      throw "The domain name and the password must both be strings";
    }
    const tag = await this.domainTag(name);
    const padded = padPassword(value);
    const iv = getRandomBytes(IV_LENGTH);
    const ct = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
        additionalData: stringToBuffer(tag)   // binds ciphertext to this domain
      },
      this.secrets.aesKey,
      padded
    );
    this.data.kvs[tag] = encodeBuffer(Buffer.concat([Buffer.from(iv), Buffer.from(ct)]));
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    if (typeof name !== "string") {
      throw "The domain name must be a string";
    }
    const tag = await this.domainTag(name);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, tag)) {
      return false;
    }
    delete this.data.kvs[tag];
    return true;
  };
};

module.exports = { Keychain }
