import { sphincs256 } from '../pq/index.js';
import { fromHex } from '../utils/hex.js';

export const TEST_VECTOR = {
    // Standard message as hex string (UTF-8 encoded 'test message')
    message: fromHex('74657374206d657373616765'),
    messageHash: fromHex('0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b'),
    
    // Seeds for different algorithms
    dilithiumSeed: fromHex('0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210'),
    kyberSeed: fromHex('0123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210'),
    // SPHINCS-192 requires 72-byte seed (144 hex chars)
    sphincs192Seed: fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647'),
    // SPHINCS-192 requires 32-byte seed (64 hex chars)
    // sphincs192Seed: fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
    // sphincs256Seed: fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
    // SPHINCS-256 requires 96-byte seed (192 hex chars)
    sphincs256Seed: fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),
    // Ed25519 seed (32 bytes)
    ed25519Seed: fromHex('0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210'),
    
    // Expected outputs for each algorithm
    dilithium65: {
        publicKeySize: 1952,
        secretKeySize: 4032,
        signatureSize: 3309
    },
    dilithium87: {
        publicKeySize: 2592,
        secretKeySize: 4896,
        signatureSize: 4627
    },
    sphincs192: {
        fast: {
            publicKeySize: 48,
            secretKeySize: 96,
            signatureSize: 35664  // Fast variant has larger signatures
        },
        small: {
            publicKeySize: 48,
            secretKeySize: 96,
            signatureSize: 16224  // Small variant has smaller signatures
        }
    },
    sphincs256: {
        fast: {
            publicKeySize: 64,
            secretKeySize: 128,
            signatureSize: 49856  // Fast variant has larger signatures
        },
        small: {
            publicKeySize: 64,
            secretKeySize: 128,
            signatureSize: 29792  // Small variant has smaller signatures
        }
    },
    kyber768: {
        publicKeySize: 1184,
        secretKeySize: 2400,
        ciphertextSize: 1088,
        sharedSecretSize: 32
    },
    kyber1024: {
        publicKeySize: 1568,
        secretKeySize: 3168,
        ciphertextSize: 1568,
        sharedSecretSize: 32
    },
    ed25519: {
        publicKeySize: 32,
        secretKeySize: 64,  // Ed25519 secret key includes both private key and public key
        signatureSize: 64
    }
}; 