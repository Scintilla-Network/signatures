/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {globalThis.Uint8Array} Uint8Array
 */

import { ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { isUint8Array } from '../utils/types.js';

/**
 * ML-KEM-1024 key encapsulation
 * @namespace kyber1024
 */
export const kyber1024 = {
    /**
     * Generate a new private key
     * @param {Uint8Array} [seed] - Optional 64-byte seed for deterministic key generation
     * @returns {Uint8Array} Private key
     * @throws {Error} If seed is invalid
     */
    generatePrivateKey(seed) {
        if (seed !== undefined && !isUint8Array(seed)) {
            throw new Error('seed must be a Uint8Array');
        }
        return seed || crypto.getRandomValues(new Uint8Array(64));
    },

    /**
     * Generate a new key pair
     * @param {Uint8Array} [seed] - Optional 64-byte seed for deterministic key generation
     * @returns {{ publicKey: Uint8Array, secretKey: Uint8Array }} Key pair
     * @throws {Error} If seed is invalid
     */
    generateKeyPair(seed) {
        const genSeed = this.generatePrivateKey(seed);
        return ml_kem1024.keygen(genSeed);
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
        return ml_kem1024.keygen(privateKey).publicKey;
    },

    /**
     * Generate shared secret and encapsulation
     * @param {Uint8Array} publicKey - Public key to encapsulate against
     * @returns {{ ciphertext: Uint8Array, sharedSecret: Uint8Array }} Encapsulation result
     * @throws {Error} If public key is invalid
     */
    encapsulate(publicKey) {
        if (!isUint8Array(publicKey)) {
            throw new Error('publicKey must be a Uint8Array');
        }
        const result = ml_kem1024.encapsulate(publicKey);
        return {
            ciphertext: result.cipherText,
            sharedSecret: result.sharedSecret
        };
    },

    /**
     * Recover shared secret from ciphertext and secret key
     * @param {Uint8Array} ciphertext - Encapsulation ciphertext
     * @param {Uint8Array} secretKey - Secret key to decapsulate with
     * @returns {Uint8Array} Shared secret
     * @throws {Error} If inputs are invalid
     */
    decapsulate(ciphertext, secretKey) {
        if (!isUint8Array(ciphertext)) {
            throw new Error('ciphertext must be a Uint8Array');
        }
        if (!isUint8Array(secretKey)) {
            throw new Error('secretKey must be a Uint8Array');
        }
        return ml_kem1024.decapsulate(ciphertext, secretKey);
    }
}; 