import { describe, it, expect } from 'vitest';
import { 
    isPositiveBigInt,
    inRange,
    assertInRange,
    bitLength,
    getBit,
    setBit,
    bitMask
} from './number.js';

describe('Number utilities', () => {
    describe('isPositiveBigInt', () => {
        it('should return true for positive bigints', () => {
            expect(isPositiveBigInt(0n)).toBe(true);
            expect(isPositiveBigInt(1n)).toBe(true);
            expect(isPositiveBigInt(123n)).toBe(true);
        });

        it('should return false for negative bigints', () => {
            expect(isPositiveBigInt(-1n)).toBe(false);
            expect(isPositiveBigInt(-123n)).toBe(false);
        });

        it('should return false for non-bigints', () => {
            expect(isPositiveBigInt(123)).toBe(false);
            expect(isPositiveBigInt('123')).toBe(false);
            expect(isPositiveBigInt(null)).toBe(false);
            expect(isPositiveBigInt(undefined)).toBe(false);
            expect(isPositiveBigInt({})).toBe(false);
        });
    });

    describe('inRange', () => {
        it('should return true for numbers in range', () => {
            expect(inRange(5n, 0n, 10n)).toBe(true);
            expect(inRange(0n, 0n, 10n)).toBe(true);
            expect(inRange(9n, 0n, 10n)).toBe(true);
        });

        it('should return false for numbers out of range', () => {
            expect(inRange(10n, 0n, 10n)).toBe(false);
            expect(inRange(-1n, 0n, 10n)).toBe(false);
            expect(inRange(11n, 0n, 10n)).toBe(false);
        });

        it('should return false for invalid inputs', () => {
            expect(inRange(5, 0n, 10n)).toBe(false);
            expect(inRange(5n, 0, 10n)).toBe(false);
            expect(inRange(5n, 0n, 10)).toBe(false);
            expect(inRange('5', '0', '10')).toBe(false);
        });
    });

    describe('assertInRange', () => {
        it('should not throw for numbers in range', () => {
            expect(() => assertInRange('test', 5n, 0n, 10n)).not.toThrow();
            expect(() => assertInRange('test', 0n, 0n, 10n)).not.toThrow();
            expect(() => assertInRange('test', 9n, 0n, 10n)).not.toThrow();
        });

        it('should throw for numbers out of range', () => {
            expect(() => assertInRange('test', 10n, 0n, 10n))
                .toThrow('test must be in range [0, 10)');
            expect(() => assertInRange('test', -1n, 0n, 10n))
                .toThrow('test must be in range [0, 10)');
            expect(() => assertInRange('test', 11n, 0n, 10n))
                .toThrow('test must be in range [0, 10)');
        });
    });

    describe('bitLength', () => {
        it('should calculate correct bit length', () => {
            expect(bitLength(0n)).toBe(0);
            expect(bitLength(1n)).toBe(1);
            expect(bitLength(2n)).toBe(2);
            expect(bitLength(3n)).toBe(2);
            expect(bitLength(4n)).toBe(3);
            expect(bitLength(255n)).toBe(8);
            expect(bitLength(256n)).toBe(9);
        });

        it('should throw for invalid inputs', () => {
            expect(() => bitLength(-1n)).toThrow('Input must be a positive bigint');
            expect(() => bitLength(123)).toThrow('Input must be a positive bigint');
            expect(() => bitLength('123')).toThrow('Input must be a positive bigint');
        });
    });

    describe('getBit', () => {
        it('should get correct bit values', () => {
            // Test number: 0b1010 (10 in decimal)
            const n = 10n;
            expect(getBit(n, 0)).toBe(0n); // rightmost bit
            expect(getBit(n, 1)).toBe(1n);
            expect(getBit(n, 2)).toBe(0n);
            expect(getBit(n, 3)).toBe(1n);
            expect(getBit(n, 4)).toBe(0n); // beyond number
        });

        it('should throw for invalid inputs', () => {
            expect(() => getBit(-1n, 0)).toThrow('First argument must be a positive bigint');
            expect(() => getBit(10n, -1)).toThrow('Position must be a non-negative number');
            expect(() => getBit(10n, '0')).toThrow('Position must be a non-negative number');
            expect(() => getBit(123, 0)).toThrow('First argument must be a positive bigint');
        });
    });

    describe('setBit', () => {
        it('should set bits correctly', () => {
            // Start with 0b1010 (10 in decimal)
            const n = 10n;
            expect(setBit(n, 0, true)).toBe(11n);  // 0b1011
            expect(setBit(n, 1, false)).toBe(8n);  // 0b1000
            expect(setBit(n, 2, true)).toBe(14n);  // 0b1110
            expect(setBit(n, 3, false)).toBe(2n);  // 0b0010
            expect(setBit(n, 4, true)).toBe(26n);  // 0b11010
        });

        it('should throw for invalid inputs', () => {
            expect(() => setBit(-1n, 0, true)).toThrow('First argument must be a positive bigint');
            expect(() => setBit(10n, -1, true)).toThrow('Position must be a non-negative number');
            expect(() => setBit(10n, '0', true)).toThrow('Position must be a non-negative number');
            expect(() => setBit(10n, 0, 1)).toThrow('Value must be a boolean');
            expect(() => setBit(123, 0, true)).toThrow('First argument must be a positive bigint');
        });
    });

    describe('bitMask', () => {
        it('should create correct bit masks', () => {
            expect(bitMask(1)).toBe(1n);      // 0b1
            expect(bitMask(2)).toBe(3n);      // 0b11
            expect(bitMask(3)).toBe(7n);      // 0b111
            expect(bitMask(4)).toBe(15n);     // 0b1111
            expect(bitMask(8)).toBe(255n);    // 0b11111111
        });

        it('should throw for invalid inputs', () => {
            expect(() => bitMask(0)).toThrow('Input must be a positive number');
            expect(() => bitMask(-1)).toThrow('Input must be a positive number');
            expect(() => bitMask('1')).toThrow('Input must be a positive number');
            expect(() => bitMask(null)).toThrow('Input must be a positive number');
        });
    });
}); 