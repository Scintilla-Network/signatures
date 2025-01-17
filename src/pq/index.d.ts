import { Bytes, PublicKey, PrivateKey, Signature, Signing } from '../types.js';

export type SignatureAlgorithm = Signing;

// Lattice-based signatures
export const dilithium65: SignatureAlgorithm;
export const dilithium87: SignatureAlgorithm;

// Hash-based signatures
export const sphincs192: SignatureAlgorithm & {
    fast: SignatureAlgorithm;
    small: SignatureAlgorithm;
};
export const sphincs256: SignatureAlgorithm & {
    fast: SignatureAlgorithm;
    small: SignatureAlgorithm;
};

// Recommended defaults
export const recommended: SignatureAlgorithm;
export const fast: SignatureAlgorithm;
export const conservative: SignatureAlgorithm; 