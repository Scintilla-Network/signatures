/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {globalThis.Uint8Array} Uint8Array
 */

import { p256 as noble } from '@noble/curves/p256';
import { isUint8Array } from '../utils/types.js';

// Export ProjectivePoint for external use
export const ProjectivePoint = noble.ProjectivePoint;

// Export curve parameters
export const CURVE = noble.CURVE;

/**
 * Utility function to get compact bytes representation
 * @param {Uint8Array} key - The public key to compress
 * @returns {Uint8Array} Compressed public key
 */
export const toCompactBytes = (key) => {
    const point = ProjectivePoint.fromHex(key);
    return point.toRawBytes(true);
};

/**
 * NIST P-256 (prime256v1) signatures
 * @namespace p256
 */
export const p256 = {
    ProjectivePoint,
    CURVE,
    /**
     * Check if a value is a valid private key
     * @param {Uint8Array} privateKey - Value to check
     * @returns {boolean} True if value is a valid private key
     */
    isValidPrivateKey(privateKey) {
        if (!isUint8Array(privateKey)) return false;
        if (privateKey.length !== 32) return false;
        try {
            return noble.utils.isValidPrivateKey(privateKey);
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
        try {
            return ProjectivePoint.fromHex(publicKey) instanceof ProjectivePoint;
        } catch {
            return false;
        }
    },

    /**
     * Convert a point to compact 33-byte representation
     * @param {Uint8Array} point - 65-byte uncompressed point
     * @returns {Uint8Array} 33-byte compressed point
     * @throws {Error} If point is invalid
     */
    toCompactBytes(point) {
        if (!isUint8Array(point)) throw new Error('Point must be Uint8Array');
        return noble.ProjectivePoint.fromHex(point).toRawBytes(true);
    },

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
     * Derive public key from private key
     * @param {Uint8Array} privateKey - 32-byte private key
     * @returns {Uint8Array} 33-byte compressed public key
     * @throws {Error} If private key is invalid
     */
    getPublicKey(privateKey) {
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return noble.getPublicKey(privateKey);
    },

    /**
     * Sign a 32-byte message hash
     * @param {Uint8Array} message - 32-byte message hash to sign
     * @param {Uint8Array} privateKey - 32-byte private key
     * @returns {Uint8Array} 64-byte signature
     * @throws {Error} If inputs are invalid
     */
    sign(message, privateKey) {
        if (!isUint8Array(message)) {
            throw new Error('message must be a Uint8Array');
        }
        if (message.length !== 32) {
            throw new Error('message must be 32 bytes');
        }
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return noble.sign(message, privateKey).toCompactRawBytes();
    },

    /**
     * Verify a signature
     * @param {Uint8Array} signature - 64-byte signature to verify
     * @param {Uint8Array} message - 32-byte message hash
     * @param {Uint8Array} publicKey - 33-byte public key
     * @returns {boolean} True if signature is valid
     * @throws {Error} If inputs are invalid
     */
    verify(signature, message, publicKey) {
        if (!isUint8Array(signature)) {
            throw new Error('signature must be a Uint8Array');
        }
        if (signature.length !== 64) {
            throw new Error('signature must be 64 bytes');
        }
        if (!isUint8Array(message)) {
            throw new Error('message must be a Uint8Array');
        }
        if (message.length !== 32) {
            throw new Error('message must be 32 bytes');
        }
        if (!isUint8Array(publicKey)) {
            throw new Error('publicKey must be a Uint8Array');
        }
        return noble.verify(signature, message, publicKey);
    }
}; 