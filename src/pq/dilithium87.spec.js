import { describe, it, expect } from 'vitest';
import { dilithium87 } from './dilithium87.js';
import { TEST_VECTOR } from '../test/vectors.js';

describe('ML-DSA (Dilithium)', () => {
    describe('dilithium87', () => {
        it('should sign and verify', () => {
            const { secretKey, publicKey } = dilithium87.generateKeyPair(TEST_VECTOR.dilithiumSeed);
            expect(secretKey).toBeInstanceOf(Uint8Array);
            expect(publicKey).toBeInstanceOf(Uint8Array);
            
            const signature = dilithium87.sign(TEST_VECTOR.message, secretKey);
            expect(signature).toBeInstanceOf(Uint8Array);
            
            const isValid = dilithium87.verify(signature, TEST_VECTOR.message, publicKey);
            expect(isValid).toBe(true);
        });

        it('should validate key generation input', () => {
            expect(() => dilithium87.generateKeyPair('invalid'))
                .toThrow('seed must be a Uint8Array');
        });

        it('should validate signing input', () => {
            const { secretKey } = dilithium87.generateKeyPair();
            expect(() => dilithium87.sign('invalid', secretKey))
                .toThrow('message must be a Uint8Array');
            expect(() => dilithium87.sign(TEST_VECTOR.message, 'invalid'))
                .toThrow('secretKey must be a Uint8Array');
        });

        it('should validate verification input', () => {
            const { publicKey } = dilithium87.generateKeyPair();
            const signature = new Uint8Array(TEST_VECTOR.dilithium87.signatureSize);

            expect(() => dilithium87.verify('invalid', TEST_VECTOR.message, publicKey))
                .toThrow('signature must be a Uint8Array');
            expect(() => dilithium87.verify(signature, 'invalid', publicKey))
                .toThrow('message must be a Uint8Array');
            expect(() => dilithium87.verify(signature, TEST_VECTOR.message, 'invalid'))
                .toThrow('publicKey must be a Uint8Array');
        });

        // Test key and signature sizes
        it('should generate correct size outputs', () => {
            const { secretKey, publicKey } = dilithium87.generateKeyPair();
            expect(publicKey.length).toBe(TEST_VECTOR.dilithium87.publicKeySize);
            expect(secretKey.length).toBe(TEST_VECTOR.dilithium87.secretKeySize);

            const signature = dilithium87.sign(TEST_VECTOR.message, secretKey);
            expect(signature.length).toBe(TEST_VECTOR.dilithium87.signatureSize);
        });
    });
});
