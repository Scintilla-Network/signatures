import { describe, it, expect } from 'vitest';
import { p256 } from './p256.js';
import { formatMessageHash } from '../utils/format.js';

const TEST_VECTOR = {
    messageHash: new Uint8Array(32).fill(1)
};

describe('p256', () => {
    it('should sign and verify', () => {
        const privateKey = p256.generatePrivateKey();
        const publicKey = p256.getPublicKey(privateKey);
        const signature = p256.sign(TEST_VECTOR.messageHash, privateKey);
        expect(p256.verify(signature, TEST_VECTOR.messageHash, publicKey)).toBe(true);
    });

    it('should validate key generation input', () => {
        expect(() => p256.generatePrivateKey('invalid'))
            .toThrow('seed must be a Uint8Array');
        expect(() => p256.generatePrivateKey(new Uint8Array(31)))
            .toThrow('seed must be 32 bytes');
    });

    it('should validate signing input', () => {
        const privateKey = p256.generatePrivateKey();
        expect(() => p256.sign('invalid', privateKey))
            .toThrow('message must be a Uint8Array');
        expect(() => p256.sign(new Uint8Array(31), privateKey))
            .toThrow('message must be 32 bytes');
        expect(() => p256.sign(TEST_VECTOR.messageHash, 'invalid'))
            .toThrow('privateKey must be a Uint8Array');
    });

    it('should validate verification input', () => {
        const publicKey = p256.getPublicKey(p256.generatePrivateKey());
        const signature = new Uint8Array(64);
        expect(() => p256.verify('invalid', TEST_VECTOR.messageHash, publicKey))
            .toThrow('signature must be a Uint8Array');
        expect(() => p256.verify(signature, 'invalid', publicKey))
            .toThrow('message must be a Uint8Array');
        expect(() => p256.verify(signature, TEST_VECTOR.messageHash, 'invalid'))
            .toThrow('publicKey must be a Uint8Array');
    });
}); 