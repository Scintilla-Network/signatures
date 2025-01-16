/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {globalThis.Uint8Array} Uint8Array
 */

import { 
    slh_dsa_sha2_256f as sphincs256f,
    slh_dsa_sha2_256s as sphincs256s
} from '@noble/post-quantum/slh-dsa';
import { isUint8Array } from '../utils/types.js';

/**
 * Create SPHINCS+ variant with consistent error messages
 * @param {{ 
 *   keygen: (seed: Uint8Array) => { publicKey: Uint8Array, secretKey: Uint8Array },
 *   sign: (secretKey: Uint8Array, message: Uint8Array) => Uint8Array,
 *   verify: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => boolean
 * }} impl - SPHINCS+ implementation (fast or small)
 * @returns {{
 *   generatePrivateKey: (seed?: Uint8Array) => Uint8Array,
 *   generateKeyPair: (seed?: Uint8Array) => { publicKey: Uint8Array, secretKey: Uint8Array },
 *   getPublicKey: (privateKey: Uint8Array) => Uint8Array,
 *   sign: (message: Uint8Array, secretKey: Uint8Array) => Uint8Array,
 *   verify: (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => boolean
 * }}
 */
const createSphincsVariant = (impl) => ({
    /**
     * Generate a new private key seed
     * @param {Uint8Array} [seed] - Optional 64-byte seed for deterministic key generation
     * @returns {Uint8Array} Private key seed
     * @throws {Error} If seed is invalid
     */
    generatePrivateKey(seed) {
        if (seed !== undefined && !isUint8Array(seed)) {
            throw new Error('seed must be a Uint8Array, use utils.formatMessage() for automatic conversion');
        }
        return seed || crypto.getRandomValues(new Uint8Array(96));
    },

    /**
     * Generate a new key pair
     * @param {Uint8Array} [seed] - Optional 64-byte seed for deterministic key generation
     * @returns {{ publicKey: Uint8Array, secretKey: Uint8Array }} Key pair
     * @throws {Error} If seed is invalid
     */
    generateKeyPair(seed) {
        const genSeed = this.generatePrivateKey(seed);
        return impl.keygen(genSeed);
    },

    /**
     * Derive public key from private key seed
     * @param {Uint8Array} privateKey - Private key seed
     * @returns {Uint8Array} Public key
     * @throws {Error} If private key seed is invalid
     */
    getPublicKey(privateKey) {
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return impl.keygen(privateKey).publicKey;
    },

    /**
     * Sign a message
     * @param {Uint8Array} message - Message to sign
     * @param {Uint8Array} secretKey - Secret key to sign with
     * @returns {Uint8Array} Signature
     * @throws {Error} If inputs are invalid
     */
    sign(message, secretKey) {
        if (!isUint8Array(message)) {
            throw new Error('message must be a Uint8Array, use utils.formatMessage() for automatic conversion');
        }
        if (!isUint8Array(secretKey)) {
            throw new Error('secretKey must be a Uint8Array, use utils.fromHex() if you have a hex string');
        }
        return impl.sign(secretKey, message);
    },

    /**
     * Verify a signature
     * @param {Uint8Array} signature - Signature to verify
     * @param {Uint8Array} message - Original message
     * @param {Uint8Array} publicKey - Public key to verify against
     * @returns {boolean} True if signature is valid
     * @throws {Error} If inputs are invalid
     */
    verify(signature, message, publicKey) {
        if (!isUint8Array(signature)) {
            throw new Error('signature must be a Uint8Array, use utils.fromHex() if you have a hex string');
        }
        if (!isUint8Array(message)) {
            throw new Error('message must be a Uint8Array, use utils.formatMessage() for automatic conversion');
        }
        if (!isUint8Array(publicKey)) {
            throw new Error('publicKey must be a Uint8Array, use utils.fromHex() if you have a hex string');
        }
        return impl.verify(publicKey, message, signature);
    }
});

/**
 * SLH-DSA-256 (SPHINCS+-256) signatures
 * @namespace sphincs256
 */
export const sphincs256 = {
    /** Fast variant optimized for speed */
    fast: createSphincsVariant(sphincs256f),
    /** Small variant optimized for size */
    small: createSphincsVariant(sphincs256s)
}; 