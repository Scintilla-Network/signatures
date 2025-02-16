import { describe, it, expect } from 'vitest';
import { dilithium65 } from './dilithium65.js';
import { TEST_VECTOR } from '../test/vectors.js';

describe('ML-DSA (Dilithium)', () => {
    describe('dilithium65', () => {
        it('should sign and verify', () => {
            const { privateKey, publicKey } = dilithium65.generateKeyPair(TEST_VECTOR.dilithiumSeed);
            expect(privateKey).toBeInstanceOf(Uint8Array);
            expect(publicKey).toBeInstanceOf(Uint8Array);
            
            const signature = dilithium65.sign(TEST_VECTOR.message, privateKey);
            expect(signature).toBeInstanceOf(Uint8Array);
            
            const isValid = dilithium65.verify(signature, TEST_VECTOR.message, publicKey);
            expect(isValid).toBe(true);
        });

        it('should validate key generation input', () => {
            expect(() => dilithium65.generateKeyPair('invalid'))
                .toThrow('seed must be a Uint8Array');
        });

        it('should validate signing input', () => {
            const { privateKey } = dilithium65.generateKeyPair();
            expect(() => dilithium65.sign('invalid', privateKey))
                .toThrow('message must be a Uint8Array');
            expect(() => dilithium65.sign(TEST_VECTOR.message, 'invalid'))
                .toThrow('privateKey must be a Uint8Array');
        });

        it('should validate verification input', () => {
            const { publicKey } = dilithium65.generateKeyPair();
            const signature = new Uint8Array(TEST_VECTOR.dilithium65.signatureSize);

            expect(() => dilithium65.verify('invalid', TEST_VECTOR.message, publicKey))
                .toThrow('signature must be a Uint8Array');
            expect(() => dilithium65.verify(signature, 'invalid', publicKey))
                .toThrow('message must be a Uint8Array');
            expect(() => dilithium65.verify(signature, TEST_VECTOR.message, 'invalid'))
                .toThrow('publicKey must be a Uint8Array');
        });

        // Test key and signature sizes
        it('should generate correct size outputs', () => {
            const { privateKey, publicKey } = dilithium65.generateKeyPair();
            expect(publicKey.length).toBe(TEST_VECTOR.dilithium65.publicKeySize);
            expect(privateKey.length).toBe(TEST_VECTOR.dilithium65.secretKeySize);

            const signature = dilithium65.sign(TEST_VECTOR.message, privateKey);
            expect(signature.length).toBe(TEST_VECTOR.dilithium65.signatureSize);
        });
    }); 
});
