import { describe, it, expect } from 'vitest';
import { 
    numberToBytesBE,
    numberToBytesLE,
    bytesToNumberBE,
    bytesToNumberLE,
    concatBytes,
    equalBytes
} from './bytes.js';

describe('Byte utilities', () => {
    describe('numberToBytesBE', () => {
        it('should convert number to big-endian bytes', () => {
            expect([...numberToBytesBE(0x1234, 2)]).toEqual([0x12, 0x34]);
            expect([...numberToBytesBE(0x12, 2)]).toEqual([0x00, 0x12]);
            expect([...numberToBytesBE(0n, 1)]).toEqual([0]);
            expect([...numberToBytesBE(255n, 2)]).toEqual([0x00, 0xff]);
        });

        it('should throw error for invalid inputs', () => {
            expect(() => numberToBytesBE('123', 2)).toThrow('Input must be a number or bigint');
            expect(() => numberToBytesBE(123, 0)).toThrow('Length must be a positive number');
            expect(() => numberToBytesBE(123, -1)).toThrow('Length must be a positive number');
            expect(() => numberToBytesBE(123, '2')).toThrow('Length must be a positive number');
        });
    });

    describe('numberToBytesLE', () => {
        it('should convert number to little-endian bytes', () => {
            expect([...numberToBytesLE(0x1234, 2)]).toEqual([0x34, 0x12]);
            expect([...numberToBytesLE(0x12, 2)]).toEqual([0x12, 0x00]);
            expect([...numberToBytesLE(0n, 1)]).toEqual([0]);
            expect([...numberToBytesLE(255n, 2)]).toEqual([0xff, 0x00]);
        });

        it('should throw error for invalid inputs', () => {
            expect(() => numberToBytesLE('123', 2)).toThrow('Input must be a number or bigint');
            expect(() => numberToBytesLE(123, 0)).toThrow('Length must be a positive number');
            expect(() => numberToBytesLE(123, -1)).toThrow('Length must be a positive number');
            expect(() => numberToBytesLE(123, '2')).toThrow('Length must be a positive number');
        });
    });

    describe('bytesToNumberBE', () => {
        it('should convert big-endian bytes to number', () => {
            expect(bytesToNumberBE(new Uint8Array([0x12, 0x34]))).toBe(0x1234n);
            expect(bytesToNumberBE(new Uint8Array([0x00, 0x12]))).toBe(0x12n);
            expect(bytesToNumberBE(new Uint8Array([0x00]))).toBe(0n);
            expect(bytesToNumberBE(new Uint8Array([0x00, 0xff]))).toBe(255n);
        });

        it('should throw error for invalid input', () => {
            expect(() => bytesToNumberBE('1234')).toThrow('Input must be a Uint8Array');
            expect(() => bytesToNumberBE(null)).toThrow('Input must be a Uint8Array');
            expect(() => bytesToNumberBE([])).toThrow('Input must be a Uint8Array');
        });
    });

    describe('bytesToNumberLE', () => {
        it('should convert little-endian bytes to number', () => {
            expect(bytesToNumberLE(new Uint8Array([0x34, 0x12]))).toBe(0x1234n);
            expect(bytesToNumberLE(new Uint8Array([0x12, 0x00]))).toBe(0x12n);
            expect(bytesToNumberLE(new Uint8Array([0x00]))).toBe(0n);
            expect(bytesToNumberLE(new Uint8Array([0xff, 0x00]))).toBe(255n);
        });

        it('should throw error for invalid input', () => {
            expect(() => bytesToNumberLE('1234')).toThrow('Input must be a Uint8Array');
            expect(() => bytesToNumberLE(null)).toThrow('Input must be a Uint8Array');
            expect(() => bytesToNumberLE([])).toThrow('Input must be a Uint8Array');
        });
    });

    describe('concatBytes', () => {
        it('should concatenate multiple byte arrays', () => {
            const a = new Uint8Array([1, 2]);
            const b = new Uint8Array([3, 4]);
            const c = new Uint8Array([5]);
            
            expect([...concatBytes(a, b)]).toEqual([1, 2, 3, 4]);
            expect([...concatBytes(a, b, c)]).toEqual([1, 2, 3, 4, 5]);
            expect([...concatBytes(a)]).toEqual([1, 2]);
            expect([...concatBytes()]).toEqual([]);
        });

        it('should throw error for invalid inputs', () => {
            const valid = new Uint8Array([1, 2]);
            expect(() => concatBytes(valid, '34')).toThrow('All inputs must be Uint8Array');
            expect(() => concatBytes(valid, null)).toThrow('All inputs must be Uint8Array');
            expect(() => concatBytes(valid, [])).toThrow('All inputs must be Uint8Array');
        });
    });

    describe('equalBytes', () => {
        it('should compare byte arrays correctly', () => {
            const a = new Uint8Array([1, 2, 3]);
            const b = new Uint8Array([1, 2, 3]);
            const c = new Uint8Array([1, 2, 4]);
            const d = new Uint8Array([1, 2]);
            
            expect(equalBytes(a, b)).toBe(true);
            expect(equalBytes(a, c)).toBe(false);
            expect(equalBytes(a, d)).toBe(false);
            expect(equalBytes(new Uint8Array([]), new Uint8Array([]))).toBe(true);
        });

        it('should throw error for invalid inputs', () => {
            const valid = new Uint8Array([1, 2]);
            expect(() => equalBytes(valid, '12')).toThrow('Inputs must be Uint8Array');
            expect(() => equalBytes('12', valid)).toThrow('Inputs must be Uint8Array');
            expect(() => equalBytes(null, valid)).toThrow('Inputs must be Uint8Array');
            expect(() => equalBytes(valid, [])).toThrow('Inputs must be Uint8Array');
        });
    });
}); 