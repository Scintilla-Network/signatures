/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {globalThis.Uint8Array} Uint8Array
 */

import { isUint8Array } from './types.js';

/**
 * Convert number to big-endian bytes
 * @param {number|bigint} n - Number to convert
 * @param {number} length - Number of bytes
 * @returns {Uint8Array} Big-endian bytes
 * @throws {Error} If inputs are invalid
 */
export function numberToBytesBE(n, length) {
    if (typeof n !== 'number' && typeof n !== 'bigint') {
        throw new Error('Input must be a number or bigint');
    }
    if (typeof length !== 'number' || length < 1) {
        throw new Error('Length must be a positive number');
    }
    const hex = n.toString(16).padStart(length * 2, '0');
    return new Uint8Array(hex.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []);
}

/**
 * Convert number to little-endian bytes
 * @param {number|bigint} n - Number to convert
 * @param {number} length - Number of bytes
 * @returns {Uint8Array} Little-endian bytes
 * @throws {Error} If inputs are invalid
 */
export function numberToBytesLE(n, length) {
    return numberToBytesBE(n, length).reverse();
}

/**
 * Convert big-endian bytes to number
 * @param {Uint8Array} bytes - Bytes to convert
 * @returns {bigint} Resulting number
 * @throws {Error} If input is invalid
 */
export function bytesToNumberBE(bytes) {
    if (!isUint8Array(bytes)) {
        throw new Error('Input must be a Uint8Array');
    }
    return bytes.reduce((n, byte) => (n << 8n) + BigInt(byte), 0n);
}

/**
 * Convert little-endian bytes to number
 * @param {Uint8Array} bytes - Bytes to convert
 * @returns {bigint} Resulting number
 * @throws {Error} If input is invalid
 */
export function bytesToNumberLE(bytes) {
    if (!isUint8Array(bytes)) {
        throw new Error('Input must be a Uint8Array');
    }
    return bytesToNumberBE(Uint8Array.from(bytes).reverse());
}

/**
 * Concatenate multiple byte arrays
 * @param {...Uint8Array} arrays - Arrays to concatenate
 * @returns {Uint8Array} Concatenated array
 * @throws {Error} If any input is invalid
 */
export function concatBytes(...arrays) {
    const totalLength = arrays.reduce((sum, arr) => {
        if (!isUint8Array(arr)) {
            throw new Error('All inputs must be Uint8Array');
        }
        return sum + arr.length;
    }, 0);
    
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

/**
 * Compare two byte arrays in constant time
 * @param {Uint8Array} a - First array
 * @param {Uint8Array} b - Second array
 * @returns {boolean} True if arrays are equal
 * @throws {Error} If inputs are invalid
 */
export function equalBytes(a, b) {
    if (!isUint8Array(a) || !isUint8Array(b)) {
        throw new Error('Inputs must be Uint8Array');
    }
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
} 