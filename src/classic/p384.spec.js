import { describe, it, expect } from 'vitest';
import { p384 } from './p384.js';
import { formatMessageHash } from '../utils/format.js';

const TEST_VECTOR = {
    messageHash: new Uint8Array(48).fill(1)
};

describe('p384', () => {
    it('should sign and verify', () => {
        const privateKey = p384.generatePrivateKey();
        const publicKey = p384.getPublicKey(privateKey);
        const signature = p384.sign(TEST_VECTOR.messageHash, privateKey);
        expect(p384.verify(signature, TEST_VECTOR.messageHash, publicKey)).toBe(true);
    });

    it('should validate key generation input', () => {
        expect(() => p384.generatePrivateKey('invalid'))
            .toThrow('seed must be a Uint8Array');
        expect(() => p384.generatePrivateKey(new Uint8Array(47)))
            .toThrow('seed must be 48 bytes');
    });

    it('should validate signing input', () => {
        const privateKey = p384.generatePrivateKey();
        expect(() => p384.sign('invalid', privateKey))
            .toThrow('message must be a Uint8Array');
        expect(() => p384.sign(new Uint8Array(47), privateKey))
            .toThrow('message must be 48 bytes');
        expect(() => p384.sign(TEST_VECTOR.messageHash, 'invalid'))
            .toThrow('privateKey must be a Uint8Array');
    });

    it('should validate verification input', () => {
        const publicKey = p384.getPublicKey(p384.generatePrivateKey());
        const signature = new Uint8Array(96);
        expect(() => p384.verify('invalid', TEST_VECTOR.messageHash, publicKey))
            .toThrow('signature must be a Uint8Array');
        expect(() => p384.verify(signature, 'invalid', publicKey))
            .toThrow('message must be a Uint8Array');
        expect(() => p384.verify(signature, TEST_VECTOR.messageHash, 'invalid'))
            .toThrow('publicKey must be a Uint8Array');
    });
}); 