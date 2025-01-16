/**
 * @typedef {globalThis.Uint8Array} Uint8Array
 */

/**
 * Check if string is valid hex
 * @param {unknown} value - Value to check
 * @returns {boolean} True if valid hex string
 */
export function isHexString(value) {
    if (typeof value !== 'string') {
        return false;
    }
    if (value.length === 0 || value.length % 2 !== 0) {
        return false;
    }
    return /^[0-9a-fA-F]+$/.test(value);
}

/**
 * Check if value is Uint8Array
 * @param {unknown} value - Value to check
 * @returns {boolean} True if Uint8Array
 */
export function isUint8Array(value) {
    return value instanceof Uint8Array;
} 