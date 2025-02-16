export type Bytes = Uint8Array;
export type PublicKey = Bytes;
export type PrivateKey = Bytes;
export type Signature = Bytes;
export type SharedSecret = Bytes;
export type ProjectivePoint = any;
export type ExtendedPoint = any;


export interface KeyGeneration {
    generatePrivateKey(seed?: Bytes): PrivateKey;
    generateKeyPair(seed?: Bytes): { publicKey: PublicKey; privateKey: PrivateKey };
    getPublicKey(privateKey: PrivateKey): PublicKey;
}

export interface Signing extends KeyGeneration {
    // ProjectivePoint and ExtendedPoint are optional, depending on the curve
    ProjectivePoint?: any;
    ExtendedPoint?: any;
    sign(message: Bytes, privateKey: PrivateKey): Signature;
    verify(signature: Signature, message: Bytes, publicKey: PublicKey): boolean;
}

export interface KeyExchange extends KeyGeneration {
    deriveSharedSecret(privateKey: PrivateKey, peerPublicKey: PublicKey): SharedSecret;
} 