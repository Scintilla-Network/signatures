import { isUint8Array } from './types.js';

/**
 * Convert JSON object to bytes
 * @param {object} obj - Object to convert
 * @returns {Uint8Array} UTF-8 encoded JSON
 * @throws {Error} If input is not a valid JSON object
 */
export function fromJSON(obj) {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
        throw new Error('Input must be a JSON object');
    }
    return new TextEncoder().encode(JSON.stringify(obj));
}

/**
 * Convert bytes to JSON object
 * @param {Uint8Array} bytes - Bytes to convert
 * @returns {object} Parsed JSON object
 * @throws {Error} If input is not a Uint8Array
 */
export function toJSON(bytes) {
    if (!isUint8Array(bytes)) {
        throw new Error('Input must be a Uint8Array');
    }
    return JSON.parse(new TextDecoder().decode(bytes));
} 