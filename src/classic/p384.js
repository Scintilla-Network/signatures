/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {globalThis.Uint8Array} Uint8Array
 */

import { p384 as noble } from '@noble/curves/p384';
import { isUint8Array } from '../utils/types.js';

/**
 * NIST P-384 signatures
 * @namespace p384
 */
export const p384 = {
    /**
     * Generate a new private key
     * @param {Uint8Array} [seed] - Optional 48-byte seed for deterministic key generation
     * @returns {Uint8Array} 48-byte private key
     * @throws {Error} If seed is invalid
     */
    generatePrivateKey(seed) {
        if (seed !== undefined) {
            if (!isUint8Array(seed)) {
                throw new Error('seed must be a Uint8Array');
            }
            if (seed.length !== 48) {
                throw new Error('seed must be 48 bytes');
            }
            // Use seed directly as private key after validation
            return seed;
        }
        return noble.utils.randomPrivateKey();
    },

    /**
     * Derive public key from private key
     * @param {Uint8Array} privateKey - 48-byte private key
     * @returns {Uint8Array} 49-byte compressed public key
     * @throws {Error} If private key is invalid
     */
    getPublicKey(privateKey) {
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return noble.getPublicKey(privateKey);
    },

    /**
     * Sign a 48-byte message hash
     * @param {Uint8Array} message - 48-byte message hash to sign
     * @param {Uint8Array} privateKey - 48-byte private key
     * @returns {Uint8Array} 96-byte signature
     * @throws {Error} If inputs are invalid
     */
    sign(message, privateKey) {
        if (!isUint8Array(message)) {
            throw new Error('message must be a Uint8Array');
        }
        if (message.length !== 48) {
            throw new Error('message must be 48 bytes');
        }
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return noble.sign(message, privateKey).toCompactRawBytes();
    },

    /**
     * Verify a signature
     * @param {Uint8Array} signature - 96-byte signature to verify
     * @param {Uint8Array} message - 48-byte message hash
     * @param {Uint8Array} publicKey - 49-byte public key
     * @returns {boolean} True if signature is valid
     * @throws {Error} If inputs are invalid
     */
    verify(signature, message, publicKey) {
        if (!isUint8Array(signature)) {
            throw new Error('signature must be a Uint8Array');
        }
        if (signature.length !== 96) {
            throw new Error('signature must be 96 bytes');
        }
        if (!isUint8Array(message)) {
            throw new Error('message must be a Uint8Array');
        }
        if (message.length !== 48) {
            throw new Error('message must be 48 bytes');
        }
        if (!isUint8Array(publicKey)) {
            throw new Error('publicKey must be a Uint8Array');
        }
        return noble.verify(signature, message, publicKey);
    }
}; 