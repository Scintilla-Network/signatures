import { describe, it, expect } from 'vitest';
import { p521 } from './p521.js';
import { formatMessageHash } from '../utils/format.js';

const TEST_VECTOR = {
    messageHash: new Uint8Array(66).fill(1)
};

describe('p521', () => {
    it('should sign and verify', () => {
        const privateKey = p521.generatePrivateKey();
        const publicKey = p521.getPublicKey(privateKey);
        const signature = p521.sign(TEST_VECTOR.messageHash, privateKey);
        expect(p521.verify(signature, TEST_VECTOR.messageHash, publicKey)).toBe(true);
    });

    it('should validate key generation input', () => {
        expect(() => p521.generatePrivateKey('invalid'))
            .toThrow('seed must be a Uint8Array');
        expect(() => p521.generatePrivateKey(new Uint8Array(65)))
            .toThrow('seed must be 66 bytes');
    });

    it('should validate signing input', () => {
        const privateKey = p521.generatePrivateKey();
        expect(() => p521.sign('invalid', privateKey))
            .toThrow('message must be a Uint8Array');
        expect(() => p521.sign(new Uint8Array(65), privateKey))
            .toThrow('message must be 66 bytes');
        expect(() => p521.sign(TEST_VECTOR.messageHash, 'invalid'))
            .toThrow('privateKey must be a Uint8Array');
    });

    it('should validate verification input', () => {
        const publicKey = p521.getPublicKey(p521.generatePrivateKey());
        const signature = new Uint8Array(132);
        expect(() => p521.verify('invalid', TEST_VECTOR.messageHash, publicKey))
            .toThrow('signature must be a Uint8Array');
        expect(() => p521.verify(signature, 'invalid', publicKey))
            .toThrow('message must be a Uint8Array');
        expect(() => p521.verify(signature, TEST_VECTOR.messageHash, 'invalid'))
            .toThrow('publicKey must be a Uint8Array');
    });
}); 