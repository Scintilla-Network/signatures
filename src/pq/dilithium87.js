/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {import('../types.js').PublicKey} PublicKey
 * @typedef {import('../types.js').PrivateKey} PrivateKey
 * @typedef {import('../types.js').Signature} Signature
 * @typedef {import('../types.js').Signing} Signing
 */

import { ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import { isUint8Array } from '../utils/types.js';
import { formatMessage } from '../utils/format.js';

/**
 * ML-DSA-87 (Dilithium mode 3) signatures
 * Implements the {@link Signing} interface
 * Security level: NIST Level 5 (equivalent to AES-256)
 * @namespace dilithium87
 */
export const dilithium87 = {
    /**
     * Generate a new private key
     * @param {Bytes} [seed] - Optional 32-byte seed for deterministic key generation
     * @returns {PrivateKey} Private key
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
        return crypto.getRandomValues(new Uint8Array(32));
    },

    /**
     * Generate a new key pair
     * @param {Bytes} [seed] - Optional 32-byte seed for deterministic key generation
     * @returns {{ publicKey: PublicKey; privateKey: PrivateKey }} Generated key pair
     * @throws {Error} If seed is invalid
     */
    generateKeyPair(seed) {
        const genSeed = this.generatePrivateKey(seed);
        const { publicKey, secretKey: privateKey } = ml_dsa87.keygen(genSeed);
        return { publicKey, privateKey };
    },

    /**
     * Derive public key from private key
     * @param {PrivateKey} privateKey - Private key
     * @returns {PublicKey} Public key
     * @throws {Error} If private key is invalid
     */
    getPublicKey(privateKey) {
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        const { publicKey } = ml_dsa87.keygen(privateKey);
        return publicKey;
    },

    /**
     * Sign a message
     * @param {Bytes} message - Message to sign
     * @param {PrivateKey} privateKey - Private key
     * @returns {Signature} Signature
     * @throws {Error} If inputs are invalid
     */
    sign(message, privateKey) {
        if (!isUint8Array(message)) {
            throw new Error('message must be a Uint8Array, use utils.formatMessage() for automatic conversion');
        }
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return ml_dsa87.sign(privateKey, formatMessage(message));
    },

    /**
     * Verify a signature
     * @param {Signature} signature - Signature to verify
     * @param {Bytes} message - Original message
     * @param {PublicKey} publicKey - Public key
     * @returns {boolean} True if signature is valid
     * @throws {Error} If inputs are invalid
     */
    verify(signature, message, publicKey) {
        if (!isUint8Array(message)) {
            throw new Error('message must be a Uint8Array, use utils.formatMessage() for automatic conversion');
        }
        if (!isUint8Array(signature)) {
            throw new Error('signature must be a Uint8Array');
        }
        if (!isUint8Array(publicKey)) {
            throw new Error('publicKey must be a Uint8Array');
        }
        return ml_dsa87.verify(publicKey, formatMessage(message), signature);
    }
}; 