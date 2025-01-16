/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {globalThis.Uint8Array} Uint8Array
 */

import { bls12_381 as noble } from '@noble/curves/bls12-381';
import { isUint8Array } from '../utils/types.js';
import { formatMessage } from '../utils/format.js';

/**
 * BLS signatures on BLS12-381
 * @namespace bls12_381
 */
export const bls12_381 = {
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
        return noble.utils.randomPrivateKey();
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
     * @returns {Uint8Array} 48-byte public key
     * @throws {Error} If private key is invalid
     */
    getPublicKey(privateKey) {
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return noble.getPublicKey(privateKey);
    },

    /**
     * Sign a message
     * @param {string|Uint8Array} message - Message to sign
     * @param {Uint8Array} privateKey - Private key
     * @returns {Uint8Array} Signature
     * @throws {Error} If inputs are invalid
     */
    sign(message, privateKey) {
        if (!(message instanceof Uint8Array || typeof message === 'string' || (message && typeof message === 'object' && !Array.isArray(message) && Object.keys(message).length > 0))) {
            throw new Error('Message must be a string, Uint8Array, or JSON object');
        }
        const formattedMessage = formatMessage(message);
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return noble.sign(formattedMessage, privateKey);
    },

    /**
     * Verify a signature
     * @param {Uint8Array} signature - Signature to verify
     * @param {string|Uint8Array} message - Message that was signed
     * @param {Uint8Array} publicKey - Public key
     * @returns {boolean} True if signature is valid
     * @throws {Error} If inputs are invalid
     */
    verify(signature, message, publicKey) {
        if (!isUint8Array(signature)) {
            throw new Error('signature must be a Uint8Array');
        }
        if (!(message instanceof Uint8Array || typeof message === 'string' || (message && typeof message === 'object' && !Array.isArray(message) && Object.keys(message).length > 0))) {
            throw new Error('Message must be a string, Uint8Array, or JSON object');
        }
        const formattedMessage = formatMessage(message);
        if (!isUint8Array(publicKey)) {
            throw new Error('publicKey must be a Uint8Array');
        }
        return noble.verify(signature, formattedMessage, publicKey);
    },

    /**
     * Aggregate multiple signatures into one
     * @param {Uint8Array[]} signatures - Signatures to aggregate
     * @returns {Uint8Array} Aggregated signature
     * @throws {Error} If inputs are invalid
     */
    aggregateSignatures(signatures) {
        if (!Array.isArray(signatures)) {
            throw new Error('signatures must be an array');
        }
        for (const sig of signatures) {
            if (!isUint8Array(sig)) {
                throw new Error('all signatures must be Uint8Array');
            }
        }
        return noble.aggregateSignatures(signatures);
    },

    /**
     * Aggregate multiple public keys into one
     * @param {Uint8Array[]} publicKeys - Public keys to aggregate
     * @returns {Uint8Array} Aggregated public key
     * @throws {Error} If inputs are invalid
     */
    aggregatePublicKeys(publicKeys) {
        if (!Array.isArray(publicKeys)) {
            throw new Error('publicKeys must be an array');
        }
        for (const key of publicKeys) {
            if (!isUint8Array(key)) {
                throw new Error('all public keys must be Uint8Array');
            }
        }
        return noble.aggregatePublicKeys(publicKeys);
    }
}; 