import { describe, it, expect } from 'vitest';
import { secp256k1 } from './secp256k1.js';
import { formatMessageHash } from '../utils/format.js';

const TEST_VECTOR = {
    messageHash: new Uint8Array(32).fill(1),
    messageHex: '0'.repeat(64)  // 32-byte hex string
};

describe('secp256k1', () => {
    it('should sign and verify with Uint8Array message', () => {
        const privateKey = secp256k1.generatePrivateKey();
        const publicKey = secp256k1.getPublicKey(privateKey);
        const signature = secp256k1.sign(TEST_VECTOR.messageHash, privateKey);
        expect(secp256k1.verify(signature, TEST_VECTOR.messageHash, publicKey)).toBe(true);
    });

    it('should sign and verify with hex string message', () => {
        const privateKey = secp256k1.generatePrivateKey();
        const publicKey = secp256k1.getPublicKey(privateKey);
        const signature = secp256k1.sign(TEST_VECTOR.messageHex, privateKey);
        expect(secp256k1.verify(signature, TEST_VECTOR.messageHex, publicKey)).toBe(true);
    });

    it('should validate key generation input', () => {
        expect(() => secp256k1.generatePrivateKey('invalid'))
            .toThrow('seed must be a Uint8Array');
        expect(() => secp256k1.generatePrivateKey(new Uint8Array(31)))
            .toThrow('seed must be 32 bytes');
    });

    it('should validate signing input', () => {
        const privateKey = secp256k1.generatePrivateKey();
        // We hash it.
        // expect(() => secp256k1.sign(new Uint8Array(31), privateKey))
        //     .toThrow('message must be 32 bytes');
        expect(() => secp256k1.sign('invalid hex', privateKey))
            .toThrow('Message must be a string, Uint8Array, or JSON object');
        expect(() => secp256k1.sign(TEST_VECTOR.messageHash, 'invalid'))
            .toThrow('privateKey must be a Uint8Array');
    });

    it('should validate verification input', () => {
        const publicKey = secp256k1.getPublicKey(secp256k1.generatePrivateKey());
        const signature = new Uint8Array(64);
        // We allows both of those tests now
        // expect(() => secp256k1.verify('invalid', TEST_VECTOR.messageHash, publicKey))
            // .toThrow('signature must be a Uint8Array');
        // expect(() => secp256k1.verify(new Uint8Array(31), signature, publicKey))
            // .toThrow('message must be 32 bytes');
        expect(() => secp256k1.verify(signature, 'invalid hex', publicKey))
            .toThrow('Message must be a string, Uint8Array, or JSON object');
        expect(() => secp256k1.verify(signature, TEST_VECTOR.messageHash, 'invalid'))
            .toThrow('publicKey must be a Uint8Array');
    });
}); 