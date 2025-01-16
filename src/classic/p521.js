/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {globalThis.Uint8Array} Uint8Array
 */

import { p521 as noble } from '@noble/curves/p521';
import { isUint8Array } from '../utils/types.js';

/**
 * NIST P-521 signatures
 * @namespace p521
 */
export const p521 = {
    /**
     * Generate a new private key
     * @param {Uint8Array} [seed] - Optional 66-byte seed for deterministic key generation
     * @returns {Uint8Array} 66-byte private key
     * @throws {Error} If seed is invalid
     */
    generatePrivateKey(seed) {
        if (seed !== undefined) {
            if (!isUint8Array(seed)) {
                throw new Error('seed must be a Uint8Array');
            }
            if (seed.length !== 66) {
                throw new Error('seed must be 66 bytes');
            }
            // Use seed directly as private key after validation
            return seed;
        }
        return noble.utils.randomPrivateKey();
    },

    /**
     * Derive public key from private key
     * @param {Uint8Array} privateKey - 66-byte private key
     * @returns {Uint8Array} 67-byte compressed public key
     * @throws {Error} If private key is invalid
     */
    getPublicKey(privateKey) {
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return noble.getPublicKey(privateKey);
    },

    /**
     * Sign a 66-byte message hash
     * @param {Uint8Array} message - 66-byte message hash to sign
     * @param {Uint8Array} privateKey - 66-byte private key
     * @returns {Uint8Array} 132-byte signature
     * @throws {Error} If inputs are invalid
     */
    sign(message, privateKey) {
        if (!isUint8Array(message)) {
            throw new Error('message must be a Uint8Array');
        }
        if (message.length !== 66) {
            throw new Error('message must be 66 bytes');
        }
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return noble.sign(message, privateKey).toCompactRawBytes();
    },

    /**
     * Verify a signature
     * @param {Uint8Array} signature - 132-byte signature to verify
     * @param {Uint8Array} message - 66-byte message hash
     * @param {Uint8Array} publicKey - 67-byte public key
     * @returns {boolean} True if signature is valid
     * @throws {Error} If inputs are invalid
     */
    verify(signature, message, publicKey) {
        if (!isUint8Array(signature)) {
            throw new Error('signature must be a Uint8Array');
        }
        if (signature.length !== 132) {
            throw new Error('signature must be 132 bytes');
        }
        if (!isUint8Array(message)) {
            throw new Error('message must be a Uint8Array');
        }
        if (message.length !== 66) {
            throw new Error('message must be 66 bytes');
        }
        if (!isUint8Array(publicKey)) {
            throw new Error('publicKey must be a Uint8Array');
        }
        return noble.verify(signature, message, publicKey);
    }
}; 