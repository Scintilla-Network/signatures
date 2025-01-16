import { describe, it, expect } from 'vitest';
import { sphincs192 } from './sphincs192.js';
import { TEST_VECTOR } from '../test/vectors.js';

describe('SLH-DSA (SPHINCS+)', () => {
    describe('sphincs192', () => {
        describe('fast variant', () => {
            it('should sign and verify', () => {
                const { secretKey, publicKey } = sphincs192.fast.generateKeyPair(TEST_VECTOR.sphincs192Seed);
            expect(secretKey).toBeInstanceOf(Uint8Array);
            expect(publicKey).toBeInstanceOf(Uint8Array);
            
            const signature = sphincs192.fast.sign(TEST_VECTOR.message, secretKey);
            expect(signature).toBeInstanceOf(Uint8Array);
            
            const isValid = sphincs192.fast.verify(signature, TEST_VECTOR.message, publicKey);
            expect(isValid).toBe(true);
        });

        it('should validate key generation input', () => {
            expect(() => sphincs192.fast.generateKeyPair('invalid'))
                .toThrow('seed must be a Uint8Array');
        });

        it('should validate signing input', () => {
            const { secretKey } = sphincs192.fast.generateKeyPair();
            expect(() => sphincs192.fast.sign('invalid', secretKey))
                .toThrow('message must be a Uint8Array');
            expect(() => sphincs192.fast.sign(TEST_VECTOR.message, 'invalid'))
                .toThrow('secretKey must be a Uint8Array');
        });

        it('should validate verification input', () => {
            const { publicKey } = sphincs192.fast.generateKeyPair();
            const signature = new Uint8Array(TEST_VECTOR.sphincs192.fast.signatureSize);

            expect(() => sphincs192.fast.verify('invalid', TEST_VECTOR.message, publicKey))
                .toThrow('signature must be a Uint8Array');
            expect(() => sphincs192.fast.verify(signature, 'invalid', publicKey))
                .toThrow('message must be a Uint8Array');
            expect(() => sphincs192.fast.verify(signature, TEST_VECTOR.message, 'invalid'))
                .toThrow('publicKey must be a Uint8Array');
        });

        // Test key and signature sizes
        it('should generate correct size outputs', () => {
            const { secretKey, publicKey } = sphincs192.fast.generateKeyPair();
            expect(publicKey.length).toBe(TEST_VECTOR.sphincs192.fast.publicKeySize);
            expect(secretKey.length).toBe(TEST_VECTOR.sphincs192.fast.secretKeySize);

            const signature = sphincs192.fast.sign(TEST_VECTOR.message, secretKey);
            expect(signature.length).toBe(TEST_VECTOR.sphincs192.fast.signatureSize);
        });
    });

    describe('small variant', () => {
        it('should sign and verify', () => {
            const { secretKey, publicKey } = sphincs192.small.generateKeyPair(TEST_VECTOR.sphincs192Seed);
            expect(secretKey).toBeInstanceOf(Uint8Array);
            expect(publicKey).toBeInstanceOf(Uint8Array);
            
            const signature = sphincs192.small.sign(TEST_VECTOR.message, secretKey);
            expect(signature).toBeInstanceOf(Uint8Array);
            
            const isValid = sphincs192.small.verify(signature, TEST_VECTOR.message, publicKey);
            expect(isValid).toBe(true);
        });

        it('should validate key generation input', () => {
            expect(() => sphincs192.small.generateKeyPair('invalid'))
                .toThrow('seed must be a Uint8Array');
        });

        it('should validate signing input', () => {
            const { secretKey } = sphincs192.small.generateKeyPair();
            expect(() => sphincs192.small.sign('invalid', secretKey))
                .toThrow('message must be a Uint8Array');
            expect(() => sphincs192.small.sign(TEST_VECTOR.message, 'invalid'))
                .toThrow('secretKey must be a Uint8Array');
        });

        it('should validate verification input', () => {
            const { publicKey } = sphincs192.small.generateKeyPair();
            const signature = new Uint8Array(TEST_VECTOR.sphincs192.small.signatureSize);

            expect(() => sphincs192.small.verify('invalid', TEST_VECTOR.message, publicKey))
                .toThrow('signature must be a Uint8Array');
            expect(() => sphincs192.small.verify(signature, 'invalid', publicKey))
                .toThrow('message must be a Uint8Array');
            expect(() => sphincs192.small.verify(signature, TEST_VECTOR.message, 'invalid'))
                .toThrow('publicKey must be a Uint8Array');
        });

        // Test key and signature sizes
        it('should generate correct size outputs', () => {
            const { secretKey, publicKey } = sphincs192.small.generateKeyPair();
            expect(publicKey.length).toBe(TEST_VECTOR.sphincs192.small.publicKeySize);
            expect(secretKey.length).toBe(TEST_VECTOR.sphincs192.small.secretKeySize);

            const signature = sphincs192.small.sign(TEST_VECTOR.message, secretKey);
                expect(signature.length).toBe(TEST_VECTOR.sphincs192.small.signatureSize);
            });
        });
    });
}); 