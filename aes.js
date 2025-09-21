// aes.js
// Simple AES-GCM encrypt/decrypt demo using Web Crypto API
// Key derived from password via PBKDF2
// Ciphertext format: base64( iv + ciphertext + tag ) where iv (12 bytes) is stored in front

// helper: convert string <-> ArrayBuffer
function str2ab(str){ return new TextEncoder().encode(str); }
function ab2str(buf){ return new TextDecoder().decode(buf); }

// base64 helpers
function abToBase64(buf){
  const bin = String.fromCharCode(...new Uint8Array(buf));
  return btoa(bin);
}
function base64ToAb(b64){
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) arr[i]=bin.charCodeAt(i);
  return arr.buffer;
}

// derive AES-GCM key from password
async function deriveKeyFromPassword(password, saltBuf, keyLen = 256){
  const pwKey = await crypto.subtle.importKey('raw', str2ab(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({
    name: 'PBKDF2',
    salt: saltBuf,
    iterations: 100000,
    hash: 'SHA-256'
  },{
    name: 'AES-GCM',
    length: keyLen
  }, false, ['encrypt','decrypt']);
}

async function encrypt(plaintext, password){
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
  const salt = crypto.getRandomValues(new Uint8Array(16)); // 128-bit salt
  const key = await deriveKeyFromPassword(password, salt);
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, str2ab(plaintext));
  // store: salt (16) + iv(12) + ciphertext
  const combined = new Uint8Array(salt.byteLength + iv.byteLength + ct.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.byteLength);
  combined.set(new Uint8Array(ct), salt.byteLength + iv.byteLength);
  return abToBase64(combined.buffer);
}

async function decrypt(base64Combined, password){
  const buf = base64ToAb(base64Combined);
  const arr = new Uint8Array(buf);
  const salt = arr.slice(0,16);
  const iv = arr.slice(16, 28);
  const ct = arr.slice(28).buffer;
  const key = await deriveKeyFromPassword(password, salt);
  try{
    const plainBuf = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
    return ab2str(plainBuf);
  }catch(e){
    throw new Error('Decryption failed (wrong password or corrupted data)');
  }
}

// UI wiring
document.addEventListener('DOMContentLoaded', ()=>{
  const pwd = document.getElementById('password');
  const pt = document.getElementById('plaintext');
  const enc = document.getElementById('ciphertext');
  const dec = document.getElementById('decrypted');

  document.getElementById('encryptBtn').addEventListener('click', async ()=>{
    enc.value = '';
    dec.value = '';
    const password = pwd.value || prompt('No password entered. Enter a password to derive the AES key:');
    if(!password) return alert('Password required.');
    const plaintext = pt.value || '';
    try{
      enc.value = 'Encrypting...';
      const b64 = await encrypt(plaintext, password);
      enc.value = b64;
    }catch(err){
      enc.value = '';
      alert('Encryption error: ' + (err.message || err));
    }
  });

  document.getElementById('decryptBtn').addEventListener('click', async ()=>{
    dec.value = '';
    const password = pwd.value || prompt('Enter password used for encryption:');
    if(!password) return alert('Password required.');
    const b64 = enc.value.trim();
    if(!b64) return alert('No ciphertext present to decrypt.');
    try{
      dec.value = 'Decrypting...';
      const plain = await decrypt(b64, password);
      dec.value = plain;
    }catch(err){
      dec.value = '';
      alert('Decryption error: ' + (err.message || err));
    }
  });

  // create random password (for demonstrative use)
  document.getElementById('generateBtn').addEventListener('click', ()=>{
    const rnd = Array.from(crypto.getRandomValues(new Uint8Array(12))).map(b=>('0'+b.toString(16)).slice(-2)).join('');
    pwd.value = rnd;
    alert('Random password generated and placed into password field. Save it if you want to decrypt later.');
  });
});
