declare module '@scintilla-network/signatures' {
    export type Bytes = Uint8Array;
    export type PublicKey = Bytes;
    export type PrivateKey = Bytes;
    export type Signature = Bytes;
    export type SharedSecret = Bytes;

    // Classic signatures
    export namespace classic {
        export interface SignatureAlgorithm {
            generateKeyPair(): Promise<{ publicKey: PublicKey; privateKey: PrivateKey }>;
            sign(message: Bytes, privateKey: PrivateKey): Promise<Signature>;
            verify(message: Bytes, signature: Signature, publicKey: PublicKey): Promise<boolean>;
        }

        export const secp256k1: SignatureAlgorithm;
        export const ed25519: SignatureAlgorithm;
        export const bls12_381: SignatureAlgorithm;
        export const p256: SignatureAlgorithm;
        export const p384: SignatureAlgorithm;
        export const p521: SignatureAlgorithm;
    }

    // Post-quantum signatures
    export namespace pq {
        export interface SignatureAlgorithm {
            generateKeyPair(): Promise<{ publicKey: PublicKey; privateKey: PrivateKey }>;
            sign(message: Bytes, privateKey: PrivateKey): Promise<Signature>;
            verify(message: Bytes, signature: Signature, publicKey: PublicKey): Promise<boolean>;
        }

        export const dilithium65: SignatureAlgorithm;
        export const dilithium87: SignatureAlgorithm;
        export const sphincs192: SignatureAlgorithm;
        export const sphincs256: SignatureAlgorithm;
    }

    // Key exchange
    export namespace kex {
        export interface KeyExchangeAlgorithm {
            generateKeyPair(): Promise<{ publicKey: PublicKey; privateKey: PrivateKey }>;
            deriveSharedSecret(privateKey: PrivateKey, peerPublicKey: PublicKey): Promise<SharedSecret>;
        }

        export const kyber768: KeyExchangeAlgorithm;
        export const kyber1024: KeyExchangeAlgorithm;
        export const ecdh: KeyExchangeAlgorithm;
    }

    // Utilities
    export namespace utils {
        export function bytesToHex(bytes: Bytes): string;
        export function hexToBytes(hex: string): Bytes;
        export function stringToBytes(str: string): Bytes;
        export function bytesToString(bytes: Bytes): string;
        export function jsonToBytes(json: any): Bytes;
        export function bytesToJson<T>(bytes: Bytes): T;
        export function formatPublicKey(publicKey: PublicKey): string;
        export function formatPrivateKey(privateKey: PrivateKey): string;
        export function formatSignature(signature: Signature): string;
        export function parsePublicKey(formatted: string): PublicKey;
        export function parsePrivateKey(formatted: string): PrivateKey;
        export function parseSignature(formatted: string): Signature;
    }
} 