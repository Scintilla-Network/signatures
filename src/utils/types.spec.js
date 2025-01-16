import { describe, it, expect } from 'vitest';
import { isHexString, isUint8Array } from './types.js';

describe('Type checking utilities', () => {
    describe('isHexString', () => {
        it('should return true for valid hex strings', () => {
            expect(isHexString('0123456789abcdef')).toBe(true);
            expect(isHexString('0123456789ABCDEF')).toBe(true);
            expect(isHexString('00')).toBe(true);
        });

        it('should return false for invalid hex strings', () => {
            expect(isHexString('0123456789abcdefg')).toBe(false); // invalid char
            expect(isHexString('0')).toBe(false); // odd length
            expect(isHexString('')).toBe(false); // empty
            expect(isHexString(123)).toBe(false); // number
            expect(isHexString(null)).toBe(false); // null
            expect(isHexString(undefined)).toBe(false); // undefined
            expect(isHexString({})).toBe(false); // object
        });
    });

    describe('isUint8Array', () => {
        it('should return true for Uint8Array instances', () => {
            expect(isUint8Array(new Uint8Array())).toBe(true);
            expect(isUint8Array(new Uint8Array([1,2,3]))).toBe(true);
        });

        it('should return false for non-Uint8Array values', () => {
            expect(isUint8Array([])).toBe(false);
            expect(isUint8Array(new Uint16Array())).toBe(false);
            expect(isUint8Array(new Int8Array())).toBe(false);
            expect(isUint8Array(null)).toBe(false);
            expect(isUint8Array(undefined)).toBe(false);
            expect(isUint8Array({})).toBe(false);
            expect(isUint8Array('string')).toBe(false);
            expect(isUint8Array(123)).toBe(false);
        });
    });
}); 