// aes.js

// Text encoder/decoder
const enc = new TextEncoder();
const dec = new TextDecoder();

// Generate a key from password + salt
async function getKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations: 100000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"] // ✅ this was missing
  );
}

// Encrypt text
async function encryptText(plainText, password) {
  const salt = "my-static-salt"; // better: random salt + save with ciphertext
  const key = await getKey(password, salt);

  const iv = crypto.getRandomValues(new Uint8Array(12)); // random IV
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plainText)
  );

  return {
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(cipherBuffer))),
    iv: btoa(String.fromCharCode(...iv))
  };
}

// Decrypt text
async function decryptText(ciphertext, password, ivBase64) {
  if (!ciphertext) throw new Error("No ciphertext present to decrypt.");

  const salt = "my-static-salt";
  const key = await getKey(password, salt);

  const iv = new Uint8Array(
    atob(ivBase64).split("").map(c => c.charCodeAt(0))
  );

  const cipherBytes = new Uint8Array(
    atob(ciphertext).split("").map(c => c.charCodeAt(0))
  );

  const plainBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    cipherBytes
  );

  return dec.decode(plainBuffer);
}

// Export functions for HTML
window.encryptText = encryptText;
window.decryptText = decryptText;
