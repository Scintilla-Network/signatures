/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {globalThis.Uint8Array} Uint8Array
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { isUint8Array } from '../utils/types.js';

/**
 * ML-DSA-65 (Dilithium mode 2) signatures
 * @namespace dilithium65
 */
export const dilithium65 = {
    /**
     * Generate a new private key
     * @param {Uint8Array} [seed] - Optional 32-byte seed for deterministic key generation
     * @returns {Uint8Array} Private key
     * @throws {Error} If seed is invalid
     */
    generatePrivateKey(seed) {
        if (seed !== undefined && !isUint8Array(seed)) {
            throw new Error('seed must be a Uint8Array, use utils.formatMessage() for automatic conversion');
        }
        return seed || crypto.getRandomValues(new Uint8Array(32));
    },

    /**
     * Generate a new key pair
     * @param {Uint8Array} [seed] - Optional 32-byte seed for deterministic key generation
     * @returns {{ publicKey: Uint8Array, secretKey: Uint8Array }} Key pair
     * @throws {Error} If seed is invalid
     */
    generateKeyPair(seed) {
        const genSeed = this.generatePrivateKey(seed);
        return ml_dsa65.keygen(genSeed);
    },

    /**
     * Derive public key from private key
     * @param {Uint8Array} privateKey - Private key
     * @returns {Uint8Array} Public key
     * @throws {Error} If private key is invalid
     */
    getPublicKey(privateKey) {
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return ml_dsa65.keygen(privateKey).publicKey;
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
        return ml_dsa65.sign(secretKey, message);
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
        return ml_dsa65.verify(publicKey, message, signature);
    }
}; 