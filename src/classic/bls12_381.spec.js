import { describe, it, expect } from 'vitest';
import { bls12_381 as bls } from './bls12_381.js';
import { utils } from '../utils/index.js';
const TEST_VECTOR = {
    message: new Uint8Array([116, 101, 115, 116]), // UTF-8 encoded "test"
    messageString: 'test'
};

describe('bls', () => {
    it('should sign and verify with Uint8Array message', () => {
        const privateKey = bls.generatePrivateKey();
        const publicKey = bls.getPublicKey(privateKey);
        const signature = bls.sign(TEST_VECTOR.message, privateKey);
        expect(bls.verify(signature, TEST_VECTOR.message, publicKey)).toBe(true);
    });

    it('should sign and verify with string message', () => {
        const privateKey = bls.generatePrivateKey();
        const publicKey = bls.getPublicKey(privateKey);
        const signature = bls.sign(utils.formatMessage(TEST_VECTOR.messageString), privateKey);
        expect(bls.verify(signature, utils.formatMessage(TEST_VECTOR.messageString), publicKey)).toBe(true);
    });

    it('should validate key generation input', () => {
        expect(() => bls.generatePrivateKey('invalid'))
            .toThrow('seed must be a Uint8Array');
        expect(() => bls.generatePrivateKey(new Uint8Array(31)))
            .toThrow('seed must be 32 bytes');
    });

    it('should validate signing input', () => {
        const privateKey = bls.generatePrivateKey();
        expect(() => bls.sign({}, privateKey))
            .toThrow('message must be a Uint8Array, use utils.formatMessage() for automatic conversion');
        expect(() => bls.sign(TEST_VECTOR.message, 'invalid'))
            .toThrow('privateKey must be a Uint8Array');
    });

    it('should validate verification input', () => {
        const publicKey = bls.getPublicKey(bls.generatePrivateKey());
        const signature = new Uint8Array(96);
        // expect(() => bls.verify('invalid', TEST_VECTOR.message, publicKey))
            // .toThrow('signature must be a Uint8Array');
        expect(() => bls.verify(signature, {}, publicKey))
            .toThrow('message must be a Uint8Array, use utils.formatMessage() for automatic conversion');
        expect(() => bls.verify(signature, TEST_VECTOR.message, 'invalid'))
            .toThrow('publicKey must be a Uint8Array');
    });

    it('should aggregate signatures and public keys', () => {
        const keys1 = bls.generateKeyPair();
        const keys2 = bls.generateKeyPair();
        const sig1 = bls.sign(TEST_VECTOR.message, keys1.privateKey);
        const sig2 = bls.sign(TEST_VECTOR.message, keys2.privateKey);

        const aggSig = bls.aggregateSignatures([sig1, sig2]);
        const aggPub = bls.aggregatePublicKeys([keys1.publicKey, keys2.publicKey]);
        expect(bls.verify(aggSig, TEST_VECTOR.message, aggPub)).toBe(true);
    });

    it('should validate aggregation input', () => {
        expect(() => bls.aggregateSignatures('invalid'))
            .toThrow('signatures must be an array');
        // expect(() => bls.aggregateSignatures([new Uint8Array(96), 'invalid']))
            // .toThrow('all signatures must be Uint8Array');

        expect(() => bls.aggregatePublicKeys('invalid'))
            .toThrow('publicKeys must be an array');
        expect(() => bls.aggregatePublicKeys([new Uint8Array(48), 'invalid']))
            .toThrow('all public keys must be Uint8Array');
    });
}); 