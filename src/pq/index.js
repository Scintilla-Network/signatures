import {dilithium65} from './dilithium65.js';
import {dilithium87} from './dilithium87.js';
import {sphincs192} from './sphincs192.js';
import {sphincs256} from './sphincs256.js';

// Create aliases for recommended defaults
const recommended = sphincs256.fast;     // Most secure, conservative choice (ASD requirement after 2030)
const fast = dilithium87;               // Best performance while maintaining security
const conservative = sphincs256.small;   // Most conservative choice, smaller signatures

export {
    // Lattice-based (ML-DSA/Dilithium)
    dilithium65,   // Category 3 (~AES-192)
    dilithium87,   // Category 5 (~AES-256)
    
    // Hash-based (SLH-DSA/SPHINCS+)
    sphincs192,    // Category 3 (~AES-192)
    sphincs256,    // Category 5 (~AES-256)
    
    // Recommended defaults
    recommended,
    fast,
    conservative
}; 