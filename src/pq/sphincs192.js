/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {import('../types.js').PublicKey} PublicKey
 * @typedef {import('../types.js').PrivateKey} PrivateKey
 * @typedef {import('../types.js').Signature} Signature
 * @typedef {import('../types.js').Signing} Signing
 */

import { slh_dsa_sha2_192f as sphincs192f, slh_dsa_sha2_192s as sphincs192s } from '@noble/post-quantum/slh-dsa';
import { isUint8Array } from '../utils/types.js';
import { formatMessage } from '../utils/format.js';

/**
 * Create a SPHINCS+ instance with given variant
 * @param {{
 *   keygen: (seed: Uint8Array) => { publicKey: Uint8Array, secretKey: Uint8Array },
 *   sign: (secretKey: Uint8Array, message: Uint8Array) => Uint8Array,
 *   verify: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => boolean
 * }} variant - SPHINCS+ variant to use
 * @returns {Signing} SPHINCS+ signing interface
 */
const createSphincs = (variant) => ({
    /**
     * Generate a new private key
     * @param {Bytes} [seed] - Optional 32-byte seed for deterministic key generation
     * @returns {Promise<PrivateKey>} Private key
     * @throws {Error} If seed is invalid
     */
    async generatePrivateKey(seed) {
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
     * @returns {Promise<{ publicKey: PublicKey; privateKey: PrivateKey }>} Generated key pair
     * @throws {Error} If seed is invalid
     */
    async generateKeyPair(seed) {
        const genSeed = await this.generatePrivateKey(seed);
        const { publicKey, secretKey: privateKey } = variant.keygen(genSeed);
        return { publicKey, privateKey };
    },

    /**
     * Derive public key from private key
     * @param {PrivateKey} privateKey - Private key
     * @returns {Promise<PublicKey>} Public key
     * @throws {Error} If private key is invalid
     */
    async getPublicKey(privateKey) {
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
     * @returns {Promise<Signature>} Signature
     * @throws {Error} If inputs are invalid
     */
    async sign(message, privateKey) {
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
     * @param {Bytes} message - Original message
     * @param {Signature} signature - Signature to verify
     * @param {PublicKey} publicKey - Public key
     * @returns {Promise<boolean>} True if signature is valid
     * @throws {Error} If inputs are invalid
     */
    async verify(message, signature, publicKey) {
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
 * SPHINCS+-192 signatures (SLH-DSA-SHA2-192)
 * Implements the {@link Signing} interface
 * Security level: NIST Level 3 (equivalent to AES-192)
 * @namespace sphincs192
 */
export const sphincs192 = {
    ...createSphincs(sphincs192f),
    /**
     * Fast variant - larger signatures but faster operations
     * Signature size: ~17KB
     */
    fast: createSphincs(sphincs192f),
    /**
     * Small variant - smaller signatures but slower operations
     * Signature size: ~4KB
     */
    small: createSphincs(sphincs192s)
}; 