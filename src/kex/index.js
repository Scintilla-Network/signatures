import * as ecdh from './ecdh.js';
import { kyber768 } from './kyber768.js';
import { kyber1024 } from './kyber1024.js';
// Create aliases for recommended defaults
const recommended = kyber1024;    // Most secure (ASD requirement after 2030)
const fast = kyber768;           // Good balance of security and performance
const classic = ecdh;            // Classical fallback

export {
    // Classic
    ecdh,
    
    // Post-quantum
    kyber768,    // Category 3 (~AES-192)
    kyber1024,   // Category 5 (~AES-256)
    
    // Recommended defaults
    recommended,
    fast,
    classic
}; 