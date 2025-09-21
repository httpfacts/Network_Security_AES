// aes.js
// Robust AES-GCM demo: PBKDF2 -> AES-GCM
// Ciphertext format: Base64( salt(16) || iv(12) || ciphertext )

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// Helpers: ArrayBuffer <-> Base64
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Derive an AES-GCM key from a password and salt (salt: ArrayBuffer or Uint8Array)
async function deriveKeyFromPassword(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  // IMPORTANT: deriveKey must have 5 args - algorithm, baseKey, derivedKeyType, extractable, keyUsages
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 150000,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Encrypt: returns base64 string containing (salt || iv || ciphertext)
async function encryptText(plaintext, password) {
  if (!password) throw new Error('Password required for encryption.');
  const salt = crypto.getRandomValues(new Uint8Array(16)); // 16 bytes
  const iv = crypto.getRandomValues(new Uint8Array(12));   // 12 bytes for GCM
  const key = await deriveKeyFromPassword(password, salt);

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    textEncoder.encode(plaintext)
  );

  // Combine salt + iv + ciphertext
  const combined = new Uint8Array(salt.byteLength + iv.byteLength + encrypted.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.byteLength);
  combined.set(new Uint8Array(encrypted), salt.byteLength + iv.byteLength);

  return arrayBufferToBase64(combined.buffer);
}

// Decrypt: expects the base64 produced by encryptText
async function decryptText(base64Combined, password) {
  if (!base64Combined) throw new Error('No ciphertext present to decrypt.');
  if (!password) throw new Error('Password required for decryption.');

  const combinedBuf = base64ToArrayBuffer(base64Combined);
  const combined = new Uint8Array(combinedBuf);

  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ciphertext = combined.slice(28).buffer;

  const key = await deriveKeyFromPassword(password, salt);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext);
  return textDecoder.decode(decrypted);
}

/* --- UI wiring --- */
document.addEventListener('DOMContentLoaded', () => {
  const pwdEl = document.getElementById('password');
  const ptEl = document.getElementById('plaintext');
  const ctEl = document.getElementById('ciphertext');
  const decEl = document.getElementById('decrypted');

  const encryptBtn = document.getElementById('encryptBtn');
  const decryptBtn = document.getElementById('decryptBtn');
  const randomBtn = document.getElementById('randomBtn');

  encryptBtn.addEventListener('click', async () => {
    ctEl.value = '';
    decEl.value = '';
    const password = pwdEl.value;
    const plaintext = ptEl.value || '';
    try {
      encryptBtn.disabled = true;
      encryptBtn.textContent = 'Encrypting...';
      const out = await encryptText(plaintext, password);
      ctEl.value = out;
    } catch (err) {
      alert('Encryption error: ' + (err.message || err));
    } finally {
      encryptBtn.disabled = false;
      encryptBtn.textContent = 'Encrypt';
    }
  });

  decryptBtn.addEventListener('click', async () => {
    decEl.value = '';
    const password = pwdEl.value;
    const combined = ctEl.value.trim();
    if (!combined) return alert('No ciphertext present to decrypt.');
    try {
      decryptBtn.disabled = true;
      decryptBtn.textContent = 'Decrypting...';
      const plain = await decryptText(combined, password);
      decEl.value = plain;
    } catch (err) {
      alert('Decryption failed (wrong password or corrupted data).');
    } finally {
      decryptBtn.disabled = false;
      decryptBtn.textContent = 'Decrypt';
    }
  });

  randomBtn.addEventListener('click', () => {
    const rnd = Array.from(crypto.getRandomValues(new Uint8Array(12)))
      .map(b => ('0' + b.toString(16)).slice(-2)).join('');
    pwdEl.value = rnd;
    alert('Random password generated in the password field. Save it to decrypt later.');
  });
});
