import { describe, it, expect } from 'vitest';
import { toHex, fromHex } from './hex.js';

describe('Hex utilities', () => {
    describe('toHex', () => {
        it('should convert Uint8Array to hex string', () => {
            const bytes = new Uint8Array([0xca, 0xfe, 0x01, 0x23]);
            expect(toHex(bytes)).toBe('cafe0123');
        });

        it('should handle empty array', () => {
            expect(toHex(new Uint8Array())).toBe('');
        });

        it('should throw error for non-Uint8Array input', () => {
            expect(() => toHex('string')).toThrow('Input must be a Uint8Array');
            expect(() => toHex(123)).toThrow('Input must be a Uint8Array');
            expect(() => toHex(null)).toThrow('Input must be a Uint8Array');
            expect(() => toHex(undefined)).toThrow('Input must be a Uint8Array');
            expect(() => toHex({})).toThrow('Input must be a Uint8Array');
            expect(() => toHex([])).toThrow('Input must be a Uint8Array');
        });
    });

    describe('fromHex', () => {
        it('should convert hex string to Uint8Array', () => {
            const bytes = fromHex('cafe0123');
            expect(bytes).toBeInstanceOf(Uint8Array);
            expect([...bytes]).toEqual([0xca, 0xfe, 0x01, 0x23]);
        });

        it('should handle empty string', () => {
            const bytes = fromHex('');
            expect(bytes).toBeInstanceOf(Uint8Array);
            expect(bytes.length).toBe(0);
        });

        it('should throw error for invalid hex strings', () => {
            expect(() => fromHex('0')).toThrow('Input must be a hex string');
            expect(() => fromHex('0g')).toThrow('Input must be a hex string');
            expect(() => fromHex('xyz')).toThrow('Input must be a hex string');
            expect(() => fromHex(123)).toThrow('Input must be a hex string');
            expect(() => fromHex(null)).toThrow('Input must be a hex string');
            expect(() => fromHex(undefined)).toThrow('Input must be a hex string');
            expect(() => fromHex({})).toThrow('Input must be a hex string');
        });
    });
}); 