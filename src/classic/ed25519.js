/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {import('../types.js').PublicKey} PublicKey
 * @typedef {import('../types.js').PrivateKey} PrivateKey
 * @typedef {import('../types.js').Signature} Signature
 * @typedef {import('../types.js').Signing} Signing
 */

import { ed25519 as ed } from '@noble/curves/ed25519';
import { isUint8Array } from '../utils/types.js';
import { formatMessage } from '../utils/format.js';

// Export ExtendedPoint for external use
export const ExtendedPoint = ed.ExtendedPoint;
export const utils = ed.utils;

// Export curve parameters
export const CURVE = ed.CURVE;

/**
 * Utility function to get compact bytes representation
 * @param {Uint8Array} key - The public key
 * @returns {Uint8Array} Compressed point representation
 */
export const toCompactBytes = (key) => {
    return ed.ExtendedPoint.fromHex(key).toRawBytes();
};

/**
 * EdDSA with Ed25519 curve (Schnorr signatures)
 * Implements the {@link Signing} interface
 * @namespace ed25519
 */
export const ed25519 = {
    ExtendedPoint,
    /**
     * Check if a value is a valid private key
     * @param {Uint8Array} privateKey - Value to check
     * @returns {boolean} True if value is a valid private key
     */
    isValidPrivateKey(privateKey) {
        if (!isUint8Array(privateKey)) return false;
        if (privateKey.length !== 32) return false;
        try {
            return ed.utils.isValidPrivateKey(privateKey);
        } catch {
            return false;
        }
    },

    /**
     * Check if a value is a valid public key
     * @param {Uint8Array} publicKey - Value to check
     * @returns {boolean} True if value is a valid public key
     */
    isValidPublicKey(publicKey) {
        if (!isUint8Array(publicKey)) return false;
        if (publicKey.length !== 32) return false;
        try {
            return ExtendedPoint.fromHex(publicKey) instanceof ExtendedPoint;
        } catch {
            return false;
        }
    },

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
        return ed.utils.randomPrivateKey();
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
     * @returns {PublicKey} 32-byte public key
     * @throws {Error} If private key is invalid
     */
    getPublicKey(privateKey) {
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return ed.getPublicKey(privateKey);
    },

    /**
     * Sign a message
     * @param {Bytes} message - Message to sign
     * @param {PrivateKey} privateKey - 32-byte private key
     * @returns {Signature} 64-byte signature
     * @throws {Error} If inputs are invalid
     */
    sign(message, privateKey) {
        if (!isUint8Array(message)) {
            throw new Error('Message must be a Uint8Array, use utils.formatMessage() for automatic conversion');
        }
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return ed.sign(formatMessage(message), privateKey);
    },

    /**
     * Verify a signature
     * @param {Signature} signature - 64-byte signature to verify
     * @param {Bytes} message - Original message
     * @param {PublicKey} publicKey - 32-byte public key
     * @returns {boolean} True if signature is valid
     * @throws {Error} If inputs are invalid
     */
    verify(signature, message, publicKey) {
        if (!isUint8Array(message)) {
            throw new Error('Message must be a Uint8Array, use utils.formatMessage() for automatic conversion');
        }
        if (!isUint8Array(signature)) {
            throw new Error('Signature must be a Uint8Array');
        }
        if (!isUint8Array(publicKey)) {
            throw new Error('PublicKey must be a Uint8Array');
        }
        return ed.verify(signature, formatMessage(message), publicKey);
    }
}; 