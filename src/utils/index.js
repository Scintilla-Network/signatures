/**
 * @typedef {import('../types.js').Bytes} Bytes
 * @typedef {globalThis.Uint8Array} Uint8Array
 */

import { toHex, fromHex } from './hex.js';
import { toJSON, fromJSON } from './json.js';
import { toUtf8, fromUtf8 } from './utf8.js';
import { formatMessage, formatMessageHash } from './format.js';
import { isHexString, isUint8Array } from './types.js';
import { mod } from './mod.js';
import {
    numberToBytesBE,
    numberToBytesLE,
    bytesToNumberBE,
    bytesToNumberLE,
    concatBytes,
    equalBytes
} from './bytes.js';
import {
    isPositiveBigInt,
    inRange,
    assertInRange,
    bitLength,
    getBit,
    setBit,
    bitMask
} from './number.js';

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
    isUint8Array,

    /**
     * Modulo operation
     * @param {number} a - First operand
     * @param {number} b - Second operand
     * @returns {number} Result of modulo operation
     */
    mod,

    /**
     * Convert number to big-endian bytes
     * @param {number|bigint} n - Number to convert
     * @param {number} length - Number of bytes
     * @returns {Uint8Array} Big-endian bytes
     */
    numberToBytesBE,

    /**
     * Convert number to little-endian bytes
     * @param {number|bigint} n - Number to convert
     * @param {number} length - Number of bytes
     * @returns {Uint8Array} Little-endian bytes
     */
    numberToBytesLE,

    /**
     * Convert big-endian bytes to number
     * @param {Uint8Array} bytes - Bytes to convert
     * @returns {bigint} Resulting number
     */
    bytesToNumberBE,

    /**
     * Convert little-endian bytes to number
     * @param {Uint8Array} bytes - Bytes to convert
     * @returns {bigint} Resulting number
     */
    bytesToNumberLE,

    /**
     * Concatenate multiple byte arrays
     * @param {...Uint8Array} arrays - Arrays to concatenate
     * @returns {Uint8Array} Concatenated array
     */
    concatBytes,

    /**
     * Compare two byte arrays in constant time
     * @param {Uint8Array} a - First array
     * @param {Uint8Array} b - Second array
     * @returns {boolean} True if arrays are equal
     */
    equalBytes,

    /**
     * Check if value is a positive bigint
     * @param {unknown} n - Value to check
     * @returns {boolean} True if value is a positive bigint
     */
    isPositiveBigInt,

    /**
     * Check if number is in range [min, max)
     * @param {bigint} n - Number to check
     * @param {bigint} min - Minimum value (inclusive)
     * @param {bigint} max - Maximum value (exclusive)
     * @returns {boolean} True if number is in range
     */
    inRange,

    /**
     * Assert that number is in range [min, max)
     * @param {string} name - Name of value for error message
     * @param {bigint} n - Number to check
     * @param {bigint} min - Minimum value (inclusive)
     * @param {bigint} max - Maximum value (exclusive)
     * @throws {Error} If number is not in range
     */
    assertInRange,

    /**
     * Calculate number of bits in a bigint
     * @param {bigint} n - Number to check
     * @returns {number} Number of bits
     */
    bitLength,

    /**
     * Get bit at position
     * @param {bigint} n - Number to check
     * @param {number} pos - Bit position (0-based)
     * @returns {bigint} Bit value (0n or 1n)
     */
    getBit,

    /**
     * Set bit at position
     * @param {bigint} n - Number to modify
     * @param {number} pos - Bit position (0-based)
     * @param {boolean} value - Bit value
     * @returns {bigint} Modified number
     */
    setBit,

    /**
     * Create bit mask of n bits
     * @param {number} n - Number of bits
     * @returns {bigint} Bit mask
     */
    bitMask
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
    isUint8Array,
    mod,
    numberToBytesBE,
    numberToBytesLE,
    bytesToNumberBE,
    bytesToNumberLE,
    concatBytes,
    equalBytes,
    isPositiveBigInt,
    inRange,
    assertInRange,
    bitLength,
    getBit,
    setBit,
    bitMask
};

export default utils; 