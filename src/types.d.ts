export type Bytes = Uint8Array;
export type PublicKey = Bytes;
export type PrivateKey = Bytes;
export type Signature = Bytes;
export type SharedSecret = Bytes;

export interface KeyGeneration {
    generatePrivateKey(seed?: Bytes): Promise<PrivateKey>;
    generateKeyPair(seed?: Bytes): Promise<{ publicKey: PublicKey; privateKey: PrivateKey }>;
    getPublicKey(privateKey: PrivateKey): Promise<PublicKey>;
}

export interface Signing extends KeyGeneration {
    sign(message: Bytes, privateKey: PrivateKey): Promise<Signature>;
    verify(message: Bytes, signature: Signature, publicKey: PublicKey): Promise<boolean>;
}

export interface KeyExchange extends KeyGeneration {
    deriveSharedSecret(privateKey: PrivateKey, peerPublicKey: PublicKey): Promise<SharedSecret>;
} 