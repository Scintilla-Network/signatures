import { describe, it, expect } from 'vitest';
import { ed25519 } from './ed25519.js';
import { utils } from '../utils/index.js';

const TEST_VECTOR = {
    message: new Uint8Array([116, 101, 115, 116]), // UTF-8 encoded "test"
    messageString: 'test',
    ed25519Seed: new Uint8Array(32).fill(1)
};

describe('ed25519', () => {
    it('should sign and verify with Uint8Array message', () => {
        const { privateKey, publicKey } = ed25519.generateKeyPair(TEST_VECTOR.ed25519Seed);
        expect(privateKey).toBeInstanceOf(Uint8Array);
        expect(publicKey).toBeInstanceOf(Uint8Array);

        const signature = ed25519.sign(TEST_VECTOR.message, privateKey);
        expect(signature).toBeInstanceOf(Uint8Array);

        const isValid = ed25519.verify(signature, TEST_VECTOR.message, publicKey);
        expect(isValid).toBe(true);
    });

    it('should sign and verify with string message', () => {
        const { privateKey, publicKey } = ed25519.generateKeyPair(TEST_VECTOR.ed25519Seed);
        const signature = ed25519.sign(utils.formatMessage(TEST_VECTOR.messageString), privateKey);
        const isValid = ed25519.verify(signature, utils.formatMessage(TEST_VECTOR.messageString), publicKey);
        expect(isValid).toBe(true);
    });

    it('should validate key generation input', () => {
        expect(() => ed25519.generateKeyPair('invalid'))
            .toThrow('seed must be a Uint8Array');
        expect(() => ed25519.generateKeyPair(new Uint8Array(31)))
            .toThrow('seed must be 32 bytes');
    });

    it('should validate signing input', () => {
        const { privateKey } = ed25519.generateKeyPair();
        expect(() => ed25519.sign({}, privateKey))
            .toThrow('Message must be a Uint8Array, use utils.formatMessage() for automatic conversion');
        expect(() => ed25519.sign(TEST_VECTOR.message, 'invalid'))
            .toThrow('privateKey must be a Uint8Array');
        expect(() => ed25519.sign(TEST_VECTOR.message, new Uint8Array(31)))
            .toThrow('private key of length 32 expected, got 31');
    });

    it('should validate verification input', () => {
        const { publicKey } = ed25519.generateKeyPair();
        const signature = new Uint8Array(64);

        expect(() => ed25519.verify('invalid', TEST_VECTOR.message, publicKey))
            .toThrow('Signature must be a Uint8Array');
        expect(() => ed25519.verify(signature, {}, publicKey))
            .toThrow('Message must be a Uint8Array, use utils.formatMessage() for automatic conversion');
        expect(() => ed25519.verify(signature, TEST_VECTOR.message, 'invalid'))
            .toThrow('PublicKey must be a Uint8Array');
        expect(() => ed25519.verify(new Uint8Array(63), TEST_VECTOR.message, publicKey))
            .toThrow('signature of length 64 expected, got 63');
        expect(() => ed25519.verify(signature, TEST_VECTOR.message, new Uint8Array(31)))
            .toThrow('publicKey of length 32 expected, got 31');
    });

    // Test key and signature sizes
    it('should generate correct size outputs', () => {
        const { privateKey, publicKey } = ed25519.generateKeyPair();
        expect(privateKey.length).toBe(32); // Private key is 32 bytes
        expect(publicKey.length).toBe(32);

        const signature = ed25519.sign(TEST_VECTOR.message, privateKey);
        expect(signature.length).toBe(64);
    });
}); 