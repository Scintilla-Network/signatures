import { describe, it, expect } from 'vitest';
import { ecdh } from './ecdh.js';
import { TEST_VECTOR } from '../test/vectors.js';

describe('ecdh', () => {
    it('should perform key exchange', () => {
        const alicePriv = ecdh.generatePrivateKey();
        const alicePub = ecdh.getPublicKey(alicePriv);
        const bobPriv = ecdh.generatePrivateKey();
        const bobPub = ecdh.getPublicKey(bobPriv);

        const aliceShared = ecdh.computeSharedSecret(alicePriv, bobPub);
        const bobShared = ecdh.computeSharedSecret(bobPriv, alicePub);

        expect(aliceShared).toEqual(bobShared);
    });

    it('should validate key generation input', () => {
        expect(() => ecdh.generatePrivateKey('invalid'))
            .toThrow('seed must be a Uint8Array');
        expect(() => ecdh.generatePrivateKey(new Uint8Array(31)))
            .toThrow('seed must be 32 bytes');
    });

    it('should validate public key derivation input', () => {
        expect(() => ecdh.getPublicKey('invalid'))
            .toThrow('privateKey must be a Uint8Array');
        expect(() => ecdh.getPublicKey(new Uint8Array(31)))
            .toThrow('privateKey must be 32 bytes');
    });

    it('should validate shared secret computation input', () => {
        const privateKey = ecdh.generatePrivateKey();
        const publicKey = ecdh.getPublicKey(privateKey);

        expect(() => ecdh.computeSharedSecret('invalid', publicKey))
            .toThrow('privateKey must be a Uint8Array');
        expect(() => ecdh.computeSharedSecret(privateKey, 'invalid'))
            .toThrow('publicKey must be a Uint8Array');
        expect(() => ecdh.computeSharedSecret(new Uint8Array(31), publicKey))
            .toThrow('privateKey must be 32 bytes');
        expect(() => ecdh.computeSharedSecret(privateKey, new Uint8Array(31)))
            .toThrow('publicKey must be 32 bytes');
    });
}); 