import { Bytes, PublicKey, PrivateKey, SharedSecret, KeyExchange } from '../types.js';

export type KeyExchangeAlgorithm = KeyExchange;

// Classic key exchange
export const ecdh: {
    p256: KeyExchangeAlgorithm;
    p384: KeyExchangeAlgorithm;
    p521: KeyExchangeAlgorithm;
};

// Post-quantum key exchange
export const kyber768: KeyExchangeAlgorithm;
export const kyber1024: KeyExchangeAlgorithm;

// Recommended defaults
export const recommended: KeyExchangeAlgorithm;
export const fast: KeyExchangeAlgorithm;
export const classic: typeof ecdh; 