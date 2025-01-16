/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {globalThis.Uint8Array} Uint8Array
 */

import { ed25519 as nobleEd25519 } from '@noble/curves/ed25519';
import { isUint8Array } from '../utils/types.js';
import { formatMessage } from '../utils/format.js';

/**
 * EdDSA signatures (ed25519)
 * @namespace ed25519
 */
export const ed25519 = {
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
        return nobleEd25519.utils.randomPrivateKey();
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
     * Sign a message
     * @param {string|Uint8Array} message - Message to sign
     * @param {Uint8Array} privateKey - 32-byte private key
     * @returns {Uint8Array} 64-byte signature
     * @throws {Error} If inputs are invalid
     */
    sign(message, privateKey) {
        try {
            if (!(message instanceof Uint8Array || typeof message === 'string' || (message && typeof message === 'object' && !Array.isArray(message) && Object.keys(message).length > 0))) {
                throw new Error('Message must be a string, Uint8Array, or JSON object');
            }
            const formattedMessage = formatMessage(message);
            if (!isUint8Array(privateKey)) {
                throw new Error('privateKey must be a Uint8Array');
            }
            if (privateKey.length !== 32) {
                throw new Error('privateKey must be 32 bytes');
            }
            return nobleEd25519.sign(formattedMessage, privateKey);
        } catch (error) {
            if (error && typeof error === 'object' && 'message' in error && error.message === 'No root') {
                throw new Error('Message must be a string, Uint8Array, or JSON object');
            }
            throw error;
        }
    },

    /**
     * Verify a signature
     * @param {Uint8Array} signature - 64-byte signature to verify
     * @param {string|Uint8Array} message - Message that was signed
     * @param {Uint8Array} publicKey - 32-byte public key
     * @returns {boolean} True if signature is valid
     * @throws {Error} If inputs are invalid
     */
    verify(signature, message, publicKey) {
        try {
            if (!isUint8Array(signature)) {
                throw new Error('signature must be a Uint8Array');
            }
            if (signature.length !== 64) {
                throw new Error('signature must be 64 bytes');
            }
            if (!(message instanceof Uint8Array || typeof message === 'string' || (message && typeof message === 'object' && !Array.isArray(message) && Object.keys(message).length > 0))) {
                throw new Error('Message must be a string, Uint8Array, or JSON object');
            }
            const formattedMessage = formatMessage(message);
            if (!isUint8Array(publicKey)) {
                throw new Error('publicKey must be a Uint8Array');
            }
            if (publicKey.length !== 32) {
                throw new Error('publicKey must be 32 bytes');
            }
            return nobleEd25519.verify(signature, formattedMessage, publicKey);
        } catch (error) {
            if (error && typeof error === 'object' && 'message' in error && error.message === 'No root') {
                throw new Error('Message must be a string, Uint8Array, or JSON object');
            }
            throw error;
        }
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
        return nobleEd25519.getPublicKey(privateKey);
    }
}; 