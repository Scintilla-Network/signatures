/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {globalThis.Uint8Array} Uint8Array
 */

import { secp256k1 } from './secp256k1.js';
import { ed25519 } from './ed25519.js';
import { bls12_381 } from './bls12_381.js';
import { p256 } from './p256.js';
import { p384 } from './p384.js';
import { p521 } from './p521.js';

/**
 * Classic signature schemes
 * @namespace classic
 */

/**
 * Bitcoin/Ethereum signatures (secp256k1)
 * @type {import('./secp256k1.js').secp256k1}
 */
export { secp256k1 };

/**
 * EdDSA signatures (ed25519)
 * @type {import('./ed25519.js').ed25519}
 */
export { ed25519 };

/**
 * BLS signatures (BLS12-381)
 * @type {import('./bls12_381.js').bls12_381}
 */
export { bls12_381 };

/**
 * NIST P-256 (prime256v1)
 * @type {import('./p256.js').p256}
 */
export { p256 };

/**
 * NIST P-384
 * @type {import('./p384.js').p384}
 */
export { p384 };

/**
 * NIST P-521
 * @type {import('./p521.js').p521}
 */
export { p521 };

// Known aliases
/**
 * Alias for ed25519
 * @type {import('./ed25519.js').ed25519}
 */
export { ed25519 as eddsa };

/**
 * Alias for secp256k1
 * @type {import('./secp256k1.js').secp256k1}
 */
export { secp256k1 as ecdsa };

/**
 * Alias for bls12_381
 * @type {import('./bls12_381.js').bls12_381}
 */
export { bls12_381 as bls };