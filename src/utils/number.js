/**
 * @typedef {import('../types.js').Bytes} Bytes
 */

/**
 * Check if value is a positive bigint
 * @param {unknown} n - Value to check
 * @returns {boolean} True if value is a positive bigint
 */
export function isPositiveBigInt(n) {
    return typeof n === 'bigint' && n >= 0n;
}

/**
 * Check if number is in range [min, max)
 * @param {bigint} n - Number to check
 * @param {bigint} min - Minimum value (inclusive)
 * @param {bigint} max - Maximum value (exclusive)
 * @returns {boolean} True if number is in range
 */
export function inRange(n, min, max) {
    return isPositiveBigInt(n) && isPositiveBigInt(min) && isPositiveBigInt(max) && min <= n && n < max;
}

/**
 * Assert that number is in range [min, max)
 * @param {string} name - Name of value for error message
 * @param {bigint} n - Number to check
 * @param {bigint} min - Minimum value (inclusive)
 * @param {bigint} max - Maximum value (exclusive)
 * @throws {Error} If number is not in range
 */
export function assertInRange(name, n, min, max) {
    if (!inRange(n, min, max)) {
        throw new Error(`${name} must be in range [${min}, ${max})`);
    }
}

/**
 * Calculate number of bits in a bigint
 * @param {bigint} n - Number to check
 * @returns {number} Number of bits
 * @throws {Error} If input is invalid
 */
export function bitLength(n) {
    if (!isPositiveBigInt(n)) {
        throw new Error('Input must be a positive bigint');
    }
    let len = 0;
    while (n > 0n) {
        n >>= 1n;
        len++;
    }
    return len;
}

/**
 * Get bit at position
 * @param {bigint} n - Number to check
 * @param {number} pos - Bit position (0-based)
 * @returns {bigint} Bit value (0n or 1n)
 * @throws {Error} If inputs are invalid
 */
export function getBit(n, pos) {
    if (!isPositiveBigInt(n)) {
        throw new Error('First argument must be a positive bigint');
    }
    if (typeof pos !== 'number' || pos < 0) {
        throw new Error('Position must be a non-negative number');
    }
    return (n >> BigInt(pos)) & 1n;
}

/**
 * Set bit at position
 * @param {bigint} n - Number to modify
 * @param {number} pos - Bit position (0-based)
 * @param {boolean} value - Bit value
 * @returns {bigint} Modified number
 * @throws {Error} If inputs are invalid
 */
export function setBit(n, pos, value) {
    if (!isPositiveBigInt(n)) {
        throw new Error('First argument must be a positive bigint');
    }
    if (typeof pos !== 'number' || pos < 0) {
        throw new Error('Position must be a non-negative number');
    }
    if (typeof value !== 'boolean') {
        throw new Error('Value must be a boolean');
    }
    const mask = 1n << BigInt(pos);
    if (value) {
        return n | mask;  // Set bit using OR
    } else {
        return n & ~mask;  // Clear bit using AND with inverted mask
    }
}

/**
 * Create bit mask of n bits
 * @param {number} n - Number of bits
 * @returns {bigint} Bit mask
 * @throws {Error} If input is invalid
 */
export function bitMask(n) {
    if (typeof n !== 'number' || n < 1) {
        throw new Error('Input must be a positive number');
    }
    return (1n << BigInt(n)) - 1n;
} 