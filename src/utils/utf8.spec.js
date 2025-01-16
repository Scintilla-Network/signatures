import { describe, it, expect } from 'vitest';
import { toUtf8, fromUtf8 } from './utf8.js';

describe('UTF-8 utilities', () => {
    describe('fromUtf8', () => {
        it('should convert string to Uint8Array', () => {
            const bytes = fromUtf8('hello');
            expect(bytes).toBeInstanceOf(Uint8Array);
            expect([...bytes]).toEqual([104, 101, 108, 108, 111]);
        });

        it('should handle empty string', () => {
            const bytes = fromUtf8('');
            expect(bytes).toBeInstanceOf(Uint8Array);
            expect(bytes.length).toBe(0);
        });

        it('should handle unicode characters', () => {
            const bytes = fromUtf8('🚀');
            expect(bytes).toBeInstanceOf(Uint8Array);
            expect(bytes.length).toBe(4);
        });

        it('should throw error for non-string input', () => {
            expect(() => fromUtf8(123)).toThrow('Input must be a string');
            expect(() => fromUtf8(null)).toThrow('Input must be a string');
            expect(() => fromUtf8(undefined)).toThrow('Input must be a string');
            expect(() => fromUtf8({})).toThrow('Input must be a string');
            expect(() => fromUtf8([])).toThrow('Input must be a string');
        });
    });

    describe('toUtf8', () => {
        it('should convert Uint8Array to string', () => {
            const bytes = new Uint8Array([104, 101, 108, 108, 111]);
            expect(toUtf8(bytes)).toBe('hello');
        });

        it('should handle empty array', () => {
            expect(toUtf8(new Uint8Array())).toBe('');
        });

        it('should handle unicode characters', () => {
            const bytes = new Uint8Array([240, 159, 154, 128]); // 🚀
            expect(toUtf8(bytes)).toBe('🚀');
        });

        it('should throw error for non-Uint8Array input', () => {
            expect(() => toUtf8('string')).toThrow('Input must be a Uint8Array');
            expect(() => toUtf8(123)).toThrow('Input must be a Uint8Array');
            expect(() => toUtf8(null)).toThrow('Input must be a Uint8Array');
            expect(() => toUtf8(undefined)).toThrow('Input must be a Uint8Array');
            expect(() => toUtf8({})).toThrow('Input must be a Uint8Array');
            expect(() => toUtf8([])).toThrow('Input must be a Uint8Array');
        });
    });
}); 