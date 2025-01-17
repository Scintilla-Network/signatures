import { Bytes, PublicKey, PrivateKey, Signature, Signing } from '../types.js';

export type SignatureAlgorithm = Signing;

export const secp256k1: SignatureAlgorithm;
export const ed25519: SignatureAlgorithm;
export const bls12_381: SignatureAlgorithm;
export const p256: SignatureAlgorithm;
export const p384: SignatureAlgorithm;
export const p521: SignatureAlgorithm;

// Aliases
export { ed25519 as eddsa };
export { secp256k1 as ecdsa };
export { bls12_381 as bls }; 