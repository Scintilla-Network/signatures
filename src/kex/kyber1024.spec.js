import { describe, it, expect } from 'vitest';
import { kyber1024 } from './kyber1024.js';
import { TEST_VECTOR } from '../test/vectors.js';

describe('kyber1024', () => {
    it('should generate keys and perform key exchange', () => {
        const { secretKey, publicKey } = kyber1024.generateKeyPair(TEST_VECTOR.kyberSeed);
        expect(secretKey).toBeInstanceOf(Uint8Array);
        expect(publicKey).toBeInstanceOf(Uint8Array);

        const { ciphertext, sharedSecret: clientShared } = kyber1024.encapsulate(publicKey);
        expect(ciphertext).toBeInstanceOf(Uint8Array);
        expect(clientShared).toBeInstanceOf(Uint8Array);

        const serverShared = kyber1024.decapsulate(ciphertext, secretKey);
        expect(serverShared).toBeInstanceOf(Uint8Array);
        expect(serverShared).toEqual(clientShared);
    });

    it('should validate key generation input', () => {
        expect(() => kyber1024.generateKeyPair('invalid'))
            .toThrow('seed must be a Uint8Array');
    });

    it('should validate encapsulation input', () => {
        expect(() => kyber1024.encapsulate('invalid'))
            .toThrow('publicKey must be a Uint8Array');
    });

    it('should validate decapsulation input', () => {
        const { secretKey } = kyber1024.generateKeyPair();
        const ciphertext = new Uint8Array(TEST_VECTOR.kyber1024.ciphertextSize);

        expect(() => kyber1024.decapsulate('invalid', secretKey))
            .toThrow('ciphertext must be a Uint8Array');
        expect(() => kyber1024.decapsulate(ciphertext, 'invalid'))
            .toThrow('secretKey must be a Uint8Array');
    });

    // Test key and shared secret sizes
    it('should generate correct size outputs', () => {
        const { secretKey, publicKey } = kyber1024.generateKeyPair();
        expect(publicKey.length).toBe(TEST_VECTOR.kyber1024.publicKeySize);
        expect(secretKey.length).toBe(TEST_VECTOR.kyber1024.secretKeySize);

        const { ciphertext, sharedSecret } = kyber1024.encapsulate(publicKey);
        expect(ciphertext.length).toBe(TEST_VECTOR.kyber1024.ciphertextSize);
        expect(sharedSecret.length).toBe(TEST_VECTOR.kyber1024.sharedSecretSize);
    });

}); 