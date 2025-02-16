/**
 * Calculates a modulo b, ensuring the result is always positive
 * @param {bigint} a - The dividend
 * @param {bigint} b - The divisor
 * @returns {bigint} The positive modulo result
 */
export function mod(a, b) {
    const result = a % b;
    return result >= 0n ? result : b + result;
} 