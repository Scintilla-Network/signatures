import { describe, it, expect } from 'vitest';
import { sphincs256 } from './sphincs256.js';
import { TEST_VECTOR } from '../test/vectors.js';

describe('SLH-DSA (SPHINCS+)', () => {
    describe('sphincs256', () => {
        describe('fast variant', () => {
            it('should sign and verify', () => {
                const { privateKey, publicKey } = sphincs256.fast.generateKeyPair(TEST_VECTOR.sphincs256Seed);
                expect(privateKey).toBeInstanceOf(Uint8Array);
                expect(publicKey).toBeInstanceOf(Uint8Array);
                
                const signature = sphincs256.fast.sign(TEST_VECTOR.message, privateKey);
                expect(signature).toBeInstanceOf(Uint8Array);
                
                const isValid = sphincs256.fast.verify(signature, TEST_VECTOR.message, publicKey);
                expect(isValid).toBe(true);
            });

            it('should validate key generation input', () => {
                expect(() => sphincs256.fast.generateKeyPair('invalid'))
                    .toThrow('seed must be a Uint8Array');
            });

            it('should validate signing input', () => {
                const { privateKey } = sphincs256.fast.generateKeyPair();
                expect(() => sphincs256.fast.sign('invalid', privateKey))
                    .toThrow('message must be a Uint8Array');
                expect(() => sphincs256.fast.sign(TEST_VECTOR.message, 'invalid'))
                    .toThrow('privateKey must be a Uint8Array');
            });

            it('should validate verification input', () => {
                const { publicKey } = sphincs256.fast.generateKeyPair();
                const signature = new Uint8Array(TEST_VECTOR.sphincs256.fast.signatureSize);

                expect(() => sphincs256.fast.verify('invalid', TEST_VECTOR.message, publicKey))
                    .toThrow('signature must be a Uint8Array');
                expect(() => sphincs256.fast.verify(signature, 'invalid', publicKey))
                    .toThrow('message must be a Uint8Array');
                expect(() => sphincs256.fast.verify(signature, TEST_VECTOR.message, 'invalid'))
                    .toThrow('publicKey must be a Uint8Array');
            });

            // Test key and signature sizes
            it('should generate correct size outputs', () => {
                const { privateKey, publicKey } = sphincs256.fast.generateKeyPair();
                expect(publicKey.length).toBe(TEST_VECTOR.sphincs256.fast.publicKeySize);
                expect(privateKey.length).toBe(TEST_VECTOR.sphincs256.fast.secretKeySize);

                const signature = sphincs256.fast.sign(TEST_VECTOR.message, privateKey);
                expect(signature.length).toBe(TEST_VECTOR.sphincs256.fast.signatureSize);
            });
        });

        describe('small variant', () => {
            it('should sign and verify', () => {
                const { privateKey, publicKey } = sphincs256.small.generateKeyPair(TEST_VECTOR.sphincs256Seed);
                expect(privateKey).toBeInstanceOf(Uint8Array);
                expect(publicKey).toBeInstanceOf(Uint8Array);
                
                const signature = sphincs256.small.sign(TEST_VECTOR.message, privateKey);
                expect(signature).toBeInstanceOf(Uint8Array);
                
                const isValid = sphincs256.small.verify(signature, TEST_VECTOR.message, publicKey);
                expect(isValid).toBe(true);
            });

            it('should validate key generation input', () => {
                expect(() => sphincs256.small.generateKeyPair('invalid'))
                    .toThrow('seed must be a Uint8Array');
            });

            it('should validate signing input', () => {
                const { privateKey } = sphincs256.small.generateKeyPair();
                expect(() => sphincs256.small.sign('invalid', privateKey))
                    .toThrow('message must be a Uint8Array');
                expect(() => sphincs256.small.sign(TEST_VECTOR.message, 'invalid'))
                    .toThrow('privateKey must be a Uint8Array');
            });

            it('should validate verification input', () => {
                const { publicKey } = sphincs256.small.generateKeyPair();
                const signature = new Uint8Array(TEST_VECTOR.sphincs256.small.signatureSize);

                expect(() => sphincs256.small.verify('invalid', TEST_VECTOR.message, publicKey))
                    .toThrow('signature must be a Uint8Array');
                expect(() => sphincs256.small.verify(signature, 'invalid', publicKey))
                    .toThrow('message must be a Uint8Array');
                expect(() => sphincs256.small.verify(signature, TEST_VECTOR.message, 'invalid'))
                    .toThrow('publicKey must be a Uint8Array');
            });

            // Test key and signature sizes
            it('should generate correct size outputs', () => {
                const { privateKey, publicKey } = sphincs256.small.generateKeyPair();
                expect(publicKey.length).toBe(TEST_VECTOR.sphincs256.small.publicKeySize);
                expect(privateKey.length).toBe(TEST_VECTOR.sphincs256.small.secretKeySize);

                const signature = sphincs256.small.sign(TEST_VECTOR.message, privateKey);
                    expect(signature.length).toBe(TEST_VECTOR.sphincs256.small.signatureSize);
                });
            });
        });
}); 