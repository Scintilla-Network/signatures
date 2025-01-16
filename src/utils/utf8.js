/**
 * Convert UTF-8 string to bytes
 * @param {string} str - String to convert
 * @returns {Uint8Array} UTF-8 encoded bytes
 * @throws {Error} If input is not a string
 */
export const fromUtf8 = (str) => {
    if (typeof str !== 'string') {
        throw new Error('Input must be a string, use utils.formatMessage() for automatic conversion');
    }
    return new TextEncoder().encode(str);
};

/**
 * Convert bytes to UTF-8 string
 * @param {Uint8Array} bytes - Bytes to convert
 * @returns {string} UTF-8 string
 * @throws {Error} If input is not a Uint8Array
 */
export const toUtf8 = (bytes) => {
    if (!(bytes instanceof Uint8Array)) {
        throw new Error('Input must be a Uint8Array, use utils.formatMessage() for automatic conversion');
    }
    return new TextDecoder().decode(bytes);
}; 