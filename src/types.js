/**
 * @typedef {Uint8Array} Bytes
 */

/**
 * @typedef {Bytes} PublicKey
 */

/**
 * @typedef {Bytes} PrivateKey
 */

/**
 * @typedef {Bytes} Signature
 */

/**
 * @typedef {Bytes} SharedSecret
 */

/**
 * @typedef {Object} KeyGeneration
 * @property {(seed?: Bytes) => Promise<PrivateKey>} generatePrivateKey
 * @property {(seed?: Bytes) => Promise<{publicKey: PublicKey, privateKey: PrivateKey}>} generateKeyPair
 * @property {(privateKey: PrivateKey) => Promise<PublicKey>} getPublicKey
 */

/**
 * @typedef {Object} Signing
 * @property {(seed?: Bytes) => Promise<PrivateKey>} generatePrivateKey
 * @property {(seed?: Bytes) => Promise<{publicKey: PublicKey, privateKey: PrivateKey}>} generateKeyPair
 * @property {(privateKey: PrivateKey) => Promise<PublicKey>} getPublicKey
 * @property {(message: Bytes, privateKey: PrivateKey) => Promise<Signature>} sign
 * @property {(message: Bytes, signature: Signature, publicKey: PublicKey) => Promise<boolean>} verify
 */

/**
 * @typedef {Object} KeyExchange
 * @property {(seed?: Bytes) => Promise<PrivateKey>} generatePrivateKey
 * @property {(seed?: Bytes) => Promise<{publicKey: PublicKey, privateKey: PrivateKey}>} generateKeyPair
 * @property {(privateKey: PrivateKey) => Promise<PublicKey>} getPublicKey
 * @property {(privateKey: PrivateKey, peerPublicKey: PublicKey) => Promise<SharedSecret>} deriveSharedSecret
 */
