"use strict";

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

const PBKDF2_ITERATIONS = 100000;
const MAX_PASSWORD_LENGTH = 64;

class Keychain {
  constructor(masterKey, salt, hmacKey, encKey, kvs = {}) {
    this.data = {
      salt: salt,  // Salt for PBKDF2
      kvs: kvs     // Key-value store for encrypted passwords
    };
    
    this.secrets = {
      masterKey: masterKey,
      hmacKey: hmacKey,
      encKey: encKey
    };
  }

  static async init(password) {
    const salt = getRandomBytes(16);
    // Generate a verification hash during initialization
    const verificationKey = getRandomBytes(32);
    
    const masterKey = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    const derivedKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      masterKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      true,
      ["sign", "verify"]
    );

    const keyMaterial = await subtle.exportKey("raw", derivedKey);

    const hmacKey = await subtle.importKey(
      "raw",
      keyMaterial,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );

    const encKey = await subtle.importKey(
      "raw",
      keyMaterial,
      "AES-GCM",
      false,
      ["encrypt", "decrypt"]
    );

    // Encrypt the verification key with the derived key
    const iv = getRandomBytes(12);
    const verificationData = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      encKey,
      verificationKey
    );

    const keychain = new Keychain(masterKey, salt, hmacKey, encKey);
    // Store verification data in the keychain
    keychain.data.verification = {
      data: encodeBuffer(verificationData),
      iv: encodeBuffer(iv)
    };

    return keychain;
  }

static async load(password, repr, trustedDataCheck) {
    const data = JSON.parse(repr);

    // Verify data integrity if checksum provided
    if (trustedDataCheck !== undefined) {
        const hash = await subtle.digest("SHA-256", stringToBuffer(repr));
        const hashString = encodeBuffer(hash);
        if (hashString !== trustedDataCheck) {
            throw new Error("Data integrity check failed");
        }
    }

    // Ensure salt is in the correct format
    let salt;
    if (typeof data.salt === 'string') {
        salt = decodeBuffer(data.salt);
    } else if (data.salt instanceof Uint8Array || Buffer.isBuffer(data.salt)) {
        salt = data.salt;
    } else {
        throw new Error("Invalid salt format");
    }

    // Recreate the master key from the password
    const masterKey = await subtle.importKey(
        "raw", 
        stringToBuffer(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    try {
        // Derive key material using stored salt
        const derivedKey = await subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: PBKDF2_ITERATIONS,
                hash: "SHA-256"
            },
            masterKey,
            { name: "HMAC", hash: "SHA-256", length: 256 },
            true,
            ["sign", "verify"]
        );

        const keyMaterial = await subtle.exportKey("raw", derivedKey);

        // Create HMAC key and encryption key
        const hmacKey = await subtle.importKey(
            "raw",
            keyMaterial,
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign", "verify"]
        );

        const encKey = await subtle.importKey(
            "raw",
            keyMaterial,
            "AES-GCM",
            false,
            ["encrypt", "decrypt"]
        );

        // Verify the password using the verification data
        if (data.verification) {
            try {
                await subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: decodeBuffer(data.verification.iv)
                    },
                    encKey,
                    decodeBuffer(data.verification.data)
                );
                // If decryption succeeds, password is correct - create new keychain
                return new Keychain(masterKey, salt, hmacKey, encKey, data.kvs);
            } catch (error) {
                // If decryption fails, the password is incorrect
                throw new Error("Incorrect password");
            }
        } else {
            throw new Error("No verification data available");
        }
    } catch (error) {
        // Propagate the specific error or throw a generic one
        if (error.message === "Incorrect password" || error.message === "No verification data available") {
            throw error;
        }
        throw new Error("Failed to load keychain");
    }
}


  async dump() {
    const repr = JSON.stringify({
      ...this.data,
      salt: encodeBuffer(this.data.salt)
    });
    const hash = await subtle.digest("SHA-256", stringToBuffer(repr));
    return [repr, encodeBuffer(hash)];
  }

  async _hmacDomain(domain) {
    const hmac = await subtle.sign(
      { name: "HMAC", hash: "SHA-256" },
      this.secrets.hmacKey,
      stringToBuffer(domain)
    );
    return encodeBuffer(hmac);
  }

  async get(domain) {
    const domainHmac = await this._hmacDomain(domain);
    const encrypted = this.data.kvs[domainHmac];
    if (!encrypted) {
      return null;
    }

    try {
      const { ciphertext, iv, associatedData } = JSON.parse(encrypted);

      if (associatedData !== domainHmac) {
        throw "Swap attack detected";
      }

      const decrypted = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: decodeBuffer(iv),
          additionalData: stringToBuffer(associatedData)
        },
        this.secrets.encKey,
        decodeBuffer(ciphertext)
      );

      return bufferToString(decrypted).replace(/\0+$/, '');
    } catch (e) {
      throw "Decryption failed or tampering detected";
    }
  }

  async set(domain, password) {
    const paddedPassword = password.padEnd(MAX_PASSWORD_LENGTH, '\0');
    const domainHmac = await this._hmacDomain(domain);
    const iv = getRandomBytes(12);

    const ciphertext = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
        additionalData: stringToBuffer(domainHmac)
      },
      this.secrets.encKey,
      stringToBuffer(paddedPassword)
    );

    this.data.kvs[domainHmac] = JSON.stringify({
      ciphertext: encodeBuffer(ciphertext),
      iv: encodeBuffer(iv),
      associatedData: domainHmac
    });
  }

  async remove(domain) {
    const domainHmac = await this._hmacDomain(domain);
    if (this.data.kvs[domainHmac]) {
      delete this.data.kvs[domainHmac];
      return true;
    }
    return false;
  }
}

module.exports = { Keychain };
