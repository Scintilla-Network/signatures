/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {import('../types.js').PublicKey} PublicKey
 * @typedef {import('../types.js').PrivateKey} PrivateKey
 * @typedef {import('../types.js').Signature} Signature
 * @typedef {import('../types.js').Signing} Signing
 */

import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { isUint8Array } from '../utils/types.js';
import { formatMessage } from '../utils/format.js';

// Export ProjectivePoint for external use

/**
 * BLS signatures on BLS12-381 curve (Boneh-Lynn-Shacham)
 * Implements the {@link Signing} interface
 * @namespace bls12_381
 */
export const bls12_381 = {
    /**
     * Generate a new private key
     * @param {Bytes} [seed] - Optional 32-byte seed for deterministic key generation
     * @returns {PrivateKey} 32-byte private key
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
        return bls.utils.randomPrivateKey();
    },

    /**
     * Generate a new key pair
     * @param {Bytes} [seed] - Optional 32-byte seed for deterministic key generation
     * @returns {{ publicKey: PublicKey; privateKey: PrivateKey }} Generated key pair
     * @throws {Error} If seed is invalid
     */
    generateKeyPair(seed) {
        const privateKey = this.generatePrivateKey(seed);
        const publicKey = this.getPublicKey(privateKey);
        return { publicKey, privateKey };
    },

    /**
     * Derive public key from private key
     * @param {PrivateKey} privateKey - 32-byte private key
     * @returns {PublicKey} 48-byte public key
     * @throws {Error} If private key is invalid
     */
    getPublicKey(privateKey) {
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return bls.getPublicKey(privateKey);
    },

    /**
     * Sign a message
     * @param {Bytes} message - Message to sign
     * @param {PrivateKey} privateKey - 32-byte private key
     * @returns {Signature} 96-byte signature
     * @throws {Error} If inputs are invalid
     */
    sign(message, privateKey) {
        if (!isUint8Array(message)) {
            throw new Error('message must be a Uint8Array, use utils.formatMessage() for automatic conversion');
        }
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return bls.sign(formatMessage(message), privateKey);
    },

    /**
     * Verify a signature
     * @param {Signature} signature - 96-byte signature to verify
     * @param {Bytes} message - Original message
     * @param {PublicKey} publicKey - 48-byte public key
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
        return bls.verify(signature, formatMessage(message), publicKey);
    },

    /**
     * Aggregate signatures
     * @param {Signature[]} signatures - Array of 96-byte signatures to aggregate
     * @returns {Signature} 96-byte aggregated signature
     * @throws {Error} If inputs are invalid
     */
    aggregateSignatures(signatures) {
        if (!Array.isArray(signatures)) {
            throw new Error('signatures must be an array');
        }
        if (signatures.some(sig => !isUint8Array(sig))) {
            throw new Error('all signatures must be Uint8Array');
        }
        return bls.aggregateSignatures(signatures);
    },

    /**
     * Aggregate public keys
     * @param {PublicKey[]} publicKeys - Array of 48-byte public keys to aggregate
     * @returns {PublicKey} 48-byte aggregated public key
     * @throws {Error} If inputs are invalid
     */
    aggregatePublicKeys(publicKeys) {
        if (!Array.isArray(publicKeys)) {
            throw new Error('publicKeys must be an array');
        }
        if (publicKeys.some(key => !isUint8Array(key))) {
            throw new Error('all public keys must be Uint8Array');
        }
        return bls.aggregatePublicKeys(publicKeys);
    }
}; 