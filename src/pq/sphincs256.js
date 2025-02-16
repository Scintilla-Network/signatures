/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {import('../types.js').PublicKey} PublicKey
 * @typedef {import('../types.js').PrivateKey} PrivateKey
 * @typedef {import('../types.js').Signature} Signature
 * @typedef {import('../types.js').Signing} Signing
 */

import { slh_dsa_sha2_256f as sphincs256f, slh_dsa_sha2_256s as sphincs256s } from '@noble/post-quantum/slh-dsa';
import { isUint8Array } from '../utils/types.js';
import { formatMessage } from '../utils/format.js';

/**
 * Create a SPHINCS+ instance with given variant
 * @param {{
 *   keygen: (seed: Uint8Array) => { publicKey: Uint8Array, privateKey: Uint8Array },
 *   sign: (privateKey: Uint8Array, message: Uint8Array) => Uint8Array,
 *   verify: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => boolean
 * }} variant - SPHINCS+ variant to use
 * @returns {Signing} SPHINCS+ signing interface
 */
const createSphincs = (variant) => ({
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
            if (seed.length !== 96) {
                throw new Error('seed must be 96 bytes');
            }
            return seed;
        }
        return crypto.getRandomValues(new Uint8Array(96));
    },

    /**
     * Generate a new key pair
     * @param {Bytes} [seed] - Optional 32-byte seed for deterministic key generation
     * @returns {{ publicKey: PublicKey; privateKey: PrivateKey }} Generated key pair
     * @throws {Error} If seed is invalid
     */
    generateKeyPair(seed) {
        const genSeed = this.generatePrivateKey(seed);
        const { publicKey, secretKey: privateKey } = variant.keygen(genSeed);
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
        const { publicKey } = variant.keygen(privateKey);
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
        return variant.sign(privateKey, formatMessage(message));
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
        return variant.verify(publicKey, formatMessage(message), signature);
    }
});

/**
 * SPHINCS+-256 signatures (SLH-DSA-SHA2-256)
 * Implements the {@link Signing} interface
 * Security level: NIST Level 5 (equivalent to AES-256)
 * @namespace sphincs256
 */
export const sphincs256 = {
    ...createSphincs(sphincs256f),
    /**
     * Fast variant - larger signatures but faster operations
     * Signature size: ~30KB
     */
    fast: createSphincs(sphincs256f),
    /**
     * Small variant - smaller signatures but slower operations
     * Signature size: ~8KB
     */
    small: createSphincs(sphincs256s)
}; 