# @scintilla-network/signatures

Enhanced signature and key exchange functions for scintilla and crypto/blockchain use.  
Provides classical cryptographic signatures with quantum-resistant alternatives.

[![npm version](https://badge.fury.io/js/@scintilla-network%2Fsignatures.svg)](https://www.npmjs.com/package/@scintilla-network/signatures)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔒 **Classic Signatures**
  - secp256k1 (Bitcoin/Ethereum)
  - ed25519 (EdDSA)
  - BLS12-381 (Aggregatable signatures)
- 🛡️ **Post-quantum Signatures**
  - ML-DSA/Dilithium (Fast lattice-based)
  - SLH-DSA/SPHINCS+ (Hash-based, conservative)
- 🔑 **Key Exchange**
  - ECDH (Classic elliptic curve)
  - ML-KEM/Kyber (Post-quantum lattice)
- 🔬 **Security**
  - Audited implementations
  - NIST-approved algorithms
  - Zero dependencies beyond noble libraries


## Installation

```bash
npm install @scintilla-network/signatures
```

## Quick Start

```javascript
import { secp256k1 } from '@scintilla-network/signatures/classic';

// Generate a key pair
const privateKey = secp256k1.generatePrivateKey();
const publicKey = secp256k1.getPublicKey(privateKey);

// Sign a message
const message = 'Hello, Scintilla!';
const signature = secp256k1.sign(message, privateKey);

// Verify the signature
const isValid = secp256k1.verify(signature, message, publicKey);
console.log('Signature valid:', isValid); // true
```

## Usage Guide

### Classic Signatures

#### secp256k1 (Bitcoin/Ethereum)
```javascript
import { secp256k1 } from '@scintilla-network/signatures/classic';

// Generate keys
const privateKey = secp256k1.generatePrivateKey();
const publicKey = secp256k1.getPublicKey(privateKey);

// Sign and verify
const signature = secp256k1.sign(message, privateKey);
const isValid = secp256k1.verify(signature, message, publicKey);
```

#### ed25519 (EdDSA)
```javascript
import { ed25519 } from '@scintilla-network/signatures/classic';

// Generate key pair
const { privateKey, publicKey } = ed25519.generateKeyPair();

// Sign and verify
const signature = ed25519.sign(message, privateKey);
const isValid = ed25519.verify(signature, message, publicKey);
```

#### BLS12-381 (Aggregatable)
```javascript
import { bls12_381 } from '@scintilla-network/signatures/classic';

// Generate multiple key pairs
const keys1 = bls12_381.generateKeyPair();
const keys2 = bls12_381.generateKeyPair();

// Sign same message with different keys
const sig1 = bls12_381.sign(message, keys1.privateKey);
const sig2 = bls12_381.sign(message, keys2.privateKey);

// Aggregate signatures and public keys
const aggSig = bls12_381.aggregateSignatures([sig1, sig2]);
const aggPub = bls12_381.aggregatePublicKeys([keys1.publicKey, keys2.publicKey]);

// Verify aggregated signature
const isValid = bls12_381.verify(aggSig, message, aggPub);
```

### Message Formats

All signature functions accept messages in multiple formats:
- `Uint8Array`: Raw bytes
- `string`: UTF-8 encoded text or hex string
- `object`: Automatically JSON stringified

```javascript
// All these are valid
signature = secp256k1.sign(new Uint8Array([1,2,3]), privateKey);
signature = secp256k1.sign("Hello, World!", privateKey);
signature = secp256k1.sign("0123456789abcdef", privateKey); // hex
signature = secp256k1.sign({ foo: "bar" }, privateKey); // object
```

### Utilities

For advanced use cases:

```javascript
import { 
    toHex, 
    fromHex, 
    toUtf8, 
    fromUtf8,
    formatMessage 
} from '@scintilla-network/signatures/utils';

// Convert between formats
const hex = toHex(bytes);
const bytes = fromHex(hex);

// UTF-8 encoding/decoding
const utf8Bytes = fromUtf8("Hello");
const text = toUtf8(utf8Bytes);

// Automatic message formatting
const formatted = formatMessage(message); // works with any format
```

## Security Considerations

### Key Storage
- Never store private keys in plaintext
- Use secure key derivation for deterministic keys
- Consider hardware security modules for production

### Message Formatting
- Use consistent message formatting
- Be careful with hex string inputs
- Validate message lengths where required

### Post-quantum Security
- Classic signatures are not quantum-resistant
- Consider using PQ signatures for long-term security
- Follow NIST recommendations for algorithm selection

## License

MIT License - see the [LICENSE](LICENSE) file for details

## Credits

This library builds upon the excellent work of:
- [noble-curves](https://github.com/paulmillr/noble-curves) by Paul Miller
- [noble-post-quantum](https://github.com/paulmillr/noble-post-quantum) by Paul Miller

Both libraries are audited and maintained with support from various blockchain foundations.