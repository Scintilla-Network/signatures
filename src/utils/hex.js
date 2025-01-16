import { isHexString } from './types.js';

/**
 * Convert bytes to hex string
 * @param {Uint8Array} bytes - Bytes to convert
 * @returns {string} Hex string
 * @throws {Error} If input is not a Uint8Array
 */
export function toHex(bytes) {
    if (!(bytes instanceof Uint8Array)) {
        throw new Error('Input must be a Uint8Array');
    }
    return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

/**
 * Convert hex string to bytes
 * @param {string} hex - Hex string to convert
 * @returns {Uint8Array} Resulting bytes
 * @throws {Error} If input is not a valid hex string
 */
export function fromHex(hex) {
    if (!isHexString(hex) && hex !== '') {
        throw new Error('Input must be a hex string');
    }
    if (hex === '') {
        return new Uint8Array(0);
    }
    const matches = hex.match(/.{1,2}/g) || [];
    return new Uint8Array(matches.map((byte) => parseInt(byte, 16)));
} 