/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {globalThis.Uint8Array} Uint8Array
 */

import { x25519 } from '@noble/curves/ed25519';
import { isUint8Array } from '../utils/types.js';

/**
 * Classic ECDH key exchange with X25519
 * @namespace ecdh
 */
export const ecdh = {
    /**
     * Generate a new private key
     * @param {Uint8Array} [seed] - Optional 32-byte seed for deterministic key generation
     * @returns {Uint8Array} 32-byte private key
     * @throws {Error} If seed is invalid
     */
    generatePrivateKey(seed) {
        if (seed !== undefined) {
            if (!isUint8Array(seed)) {
                throw new Error('seed must be a Uint8Array');
            }
            if (seed.length !== 32) {
                throw new Error('seed must be 32 bytes');
            }
            return seed;
        }
        return x25519.utils.randomPrivateKey();
    },

    /**
     * Generate a new key pair
     * @param {Uint8Array} [seed] - Optional 32-byte seed for deterministic key generation
     * @returns {{ privateKey: Uint8Array, publicKey: Uint8Array }} Key pair
     * @throws {Error} If seed is invalid
     */
    generateKeyPair(seed) {
        const privateKey = this.generatePrivateKey(seed);
        const publicKey = this.getPublicKey(privateKey);
        return { privateKey, publicKey };
    },

    /**
     * Derive public key from private key
     * @param {Uint8Array} privateKey - 32-byte private key
     * @returns {Uint8Array} 32-byte public key
     * @throws {Error} If private key is invalid
     */
    getPublicKey(privateKey) {
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        if (privateKey.length !== 32) {
            throw new Error('privateKey must be 32 bytes');
        }
        return x25519.getPublicKey(privateKey);
    },

    /**
     * Compute shared secret from private key and peer's public key
     * @param {Uint8Array} privateKey - 32-byte private key
     * @param {Uint8Array} publicKey - 32-byte public key
     * @returns {Uint8Array} 32-byte shared secret
     * @throws {Error} If inputs are invalid
     */
    computeSharedSecret(privateKey, publicKey) {
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        if (!isUint8Array(publicKey)) {
            throw new Error('publicKey must be a Uint8Array');
        }
        if (privateKey.length !== 32) {
            throw new Error('privateKey must be 32 bytes');
        }
        if (publicKey.length !== 32) {
            throw new Error('publicKey must be 32 bytes');
        }
        return x25519.getSharedSecret(privateKey, publicKey);
    }
}; 