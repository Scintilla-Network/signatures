/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {globalThis.Uint8Array} Uint8Array
 */

import { toHex, fromHex } from './hex.js';
import { toJSON, fromJSON } from './json.js';
import { toUtf8, fromUtf8 } from './utf8.js';
import { formatMessage, formatMessageHash } from './format.js';
import { isHexString, isUint8Array } from './types.js';

/**
 * Convert bytes to/from various formats
 * @namespace utils
 */
export const utils = {
    /**
     * Convert Uint8Array to hex string
     * @param {Uint8Array} bytes - Bytes to convert
     * @returns {string} Hex string
     * @throws {Error} If input is not a Uint8Array
     */
    toHex,

    /**
     * Convert hex string to Uint8Array
     * @param {string} hex - Hex string to convert
     * @returns {Uint8Array} Resulting bytes
     * @throws {Error} If input is not a valid hex string
     */
    fromHex,

    /**
     * Convert Uint8Array to JSON object
     * @param {Uint8Array} bytes - Bytes to convert
     * @returns {object} Parsed JSON object
     * @throws {Error} If input is not a Uint8Array
     */
    toJSON,

    /**
     * Convert JSON object to Uint8Array
     * @param {object} obj - Object to convert
     * @returns {Uint8Array} UTF-8 encoded JSON
     * @throws {Error} If input is not a valid JSON object
     */
    fromJSON,

    /**
     * Convert Uint8Array to UTF-8 string
     * @param {Uint8Array} bytes - Bytes to convert
     * @returns {string} UTF-8 string
     * @throws {Error} If input is not a Uint8Array
     */
    toUtf8,

    /**
     * Convert UTF-8 string to Uint8Array
     * @param {string} str - String to convert
     * @returns {Uint8Array} UTF-8 encoded bytes
     * @throws {Error} If input is not a string
     */
    fromUtf8,

    /**
     * Auto-convert various formats to Uint8Array
     * @param {string|object|Uint8Array} message - Message to format
     * @returns {Uint8Array} Formatted message bytes
     * @throws {Error} If input format is invalid
     */
    formatMessage,

    /**
     * Ensure message hash is 32 bytes
     * @param {string|Uint8Array} messageHash - Hash to format
     * @returns {Uint8Array} 32-byte message hash
     * @throws {Error} If input is not a valid 32-byte hash
     */
    formatMessageHash,

    /**
     * Check if string is valid hex
     * @param {unknown} value - Value to check
     * @returns {boolean} True if valid hex string
     */
    isHexString,

    /**
     * Check if value is Uint8Array
     * @param {unknown} value - Value to check
     * @returns {boolean} True if Uint8Array
     */
    isUint8Array
};

// Re-export individual utilities
export {
    toHex,
    fromHex,
    toJSON,
    fromJSON,
    toUtf8,
    fromUtf8,
    formatMessage,
    formatMessageHash,
    isHexString,
    isUint8Array
};

export default utils; 