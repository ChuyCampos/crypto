import { randomBytes } from 'crypto';

// Generate 32 random bytes for AES-256
const masterKey = randomBytes(32);

const iv = randomBytes(16);

// Encode for storage (e.g., base64 or hex)
console.log('KeyBase64:', masterKey.toString('base64'));
console.log('IVBase64:', iv.toString('base64'));
