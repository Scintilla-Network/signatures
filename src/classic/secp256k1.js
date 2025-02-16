/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {import('../types.js').PublicKey} PublicKey
 * @typedef {import('../types.js').PrivateKey} PrivateKey
 * @typedef {import('../types.js').Signature} Signature
 * @typedef {import('../types.js').Signing} Signing
 */

import { secp256k1 as secp } from '@noble/curves/secp256k1';
import { isUint8Array, isHexString } from '../utils/types.js';
import { formatMessage } from '../utils/format.js';
import { toHex, fromHex } from '../utils/hex.js';

// Export ProjectivePoint for external use
export const ProjectivePoint = secp.ProjectivePoint;

// Export curve parameters
export const CURVE = secp.CURVE;

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
 * ECDSA with secp256k1 curve (Bitcoin's signature scheme)
 * Implements the {@link Signing} interface
 * @namespace secp256k1
 */
export const secp256k1 = {
    ProjectivePoint,
    CURVE: secp.CURVE,
    /**
     * Check if a value is a valid private key
     * @param {Uint8Array} privateKey - Value to check
     * @returns {boolean} True if value is a valid private key
     */
    isValidPrivateKey(privateKey) {
        if (!isUint8Array(privateKey)) return false;
        if (privateKey.length !== 32) return false;
        try {
            return secp.utils.isValidPrivateKey(privateKey);
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
        return secp.utils.randomPrivateKey();
    },

    /**
     * Generate a new key pair
     * @param {Bytes} [seed] - Optional 32-byte seed for deterministic key generation
     * @returns {Promise<{ publicKey: PublicKey; privateKey: PrivateKey }>} Generated key pair
     * @throws {Error} If seed is invalid
     */
    async generateKeyPair(seed) {
        const privateKey = await this.generatePrivateKey(seed);
        const publicKey = await this.getPublicKey(privateKey);
        return { publicKey, privateKey };
    },

    /**
     * Derive public key from private key
     * @param {PrivateKey} privateKey - 32-byte private key
     * @returns {PublicKey} 33-byte compressed public key
     * @throws {Error} If private key is invalid
     */
    getPublicKey(privateKey) {
        if (!isUint8Array(privateKey)) {
            throw new Error('privateKey must be a Uint8Array');
        }
        return secp.getPublicKey(privateKey);
    },

    /**
     * Sign a message
     * @param {Bytes} message - Message to sign (will be hashed if not 32 bytes)
     * @param {PrivateKey} privateKey - 32-byte private key
     * @returns {Signature} 64-byte signature
     * @throws {Error} If inputs are invalid
     */
    sign(message, privateKey) {
        try {
            if (!(message instanceof Uint8Array || typeof message === 'string' || (message && typeof message === 'object' && !Array.isArray(message) && Object.keys(message).length > 0))) {
                throw new Error('Message must be a string, Uint8Array, or JSON object');
            }
            if (typeof message === 'string' && !isHexString(message)) {
                throw new Error('Message must be a string, Uint8Array, or JSON object');
            }
            const formattedMessage = formatMessage(message);
            if (!isUint8Array(privateKey)) {
                throw new Error('privateKey must be a Uint8Array');
            }
            return secp.sign(formattedMessage, privateKey).toCompactRawBytes();
        } catch (error) {
            if (error && typeof error === 'object' && 'message' in error && error.message === 'Invalid hex') {
                throw new Error('Message must be a string, Uint8Array, or JSON object');
            }
            throw error;
        }
    },

    /**
     * Verify a signature
     * @param {Signature} signature - 64-byte signature to verify
     * @param {Bytes} message - Original message (will be hashed if not 32 bytes)
     * @param {PublicKey} publicKey - 33-byte public key
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
            if (typeof message === 'string' && !isHexString(message)) {
                throw new Error('Message must be a string, Uint8Array, or JSON object');
            }
            const formattedMessage = formatMessage(message);
            if (!isUint8Array(publicKey)) {
                throw new Error('publicKey must be a Uint8Array');
            }
            return secp.verify(signature, formattedMessage, publicKey);
        } catch (error) {
            if (error && typeof error === 'object' && 'message' in error && error.message === 'Invalid hex') {
                throw new Error('Message must be a string, Uint8Array, or JSON object');
            }
            throw error;
        }
    }
};

export { toHex, fromHex }; 