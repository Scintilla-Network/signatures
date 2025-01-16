import { describe, it, expect } from 'vitest';
import { toJSON, fromJSON } from './json.js';

describe('JSON utilities', () => {
    describe('fromJSON', () => {
        it('should convert object to Uint8Array', () => {
            const obj = { hello: 'world', num: 123 };
            const bytes = fromJSON(obj);
            expect(bytes).toBeInstanceOf(Uint8Array);
            expect(bytes.length).toBeGreaterThan(0);
        });

        it('should handle empty object', () => {
            const bytes = fromJSON({});
            expect(bytes).toBeInstanceOf(Uint8Array);
            expect(bytes.length).toBeGreaterThan(0);
        });

        it('should handle nested objects', () => {
            const obj = { 
                nested: { 
                    array: [1, 2, 3],
                    object: { a: 1, b: 2 }
                }
            };
            const bytes = fromJSON(obj);
            expect(bytes).toBeInstanceOf(Uint8Array);
            expect(bytes.length).toBeGreaterThan(0);
        });

        it('should throw error for non-object input', () => {
            expect(() => fromJSON('string')).toThrow('Input must be a JSON object');
            expect(() => fromJSON(123)).toThrow('Input must be a JSON object');
            expect(() => fromJSON(null)).toThrow('Input must be a JSON object');
            expect(() => fromJSON(undefined)).toThrow('Input must be a JSON object');
            expect(() => fromJSON([])).toThrow('Input must be a JSON object');
        });
    });

    describe('toJSON', () => {
        it('should convert Uint8Array to object', () => {
            const obj = { hello: 'world', num: 123 };
            const bytes = fromJSON(obj);
            const result = toJSON(bytes);
            expect(result).toEqual(obj);
        });

        it('should handle empty object', () => {
            const bytes = fromJSON({});
            const result = toJSON(bytes);
            expect(result).toEqual({});
        });

        it('should handle nested objects', () => {
            const obj = { 
                nested: { 
                    array: [1, 2, 3],
                    object: { a: 1, b: 2 }
                }
            };
            const bytes = fromJSON(obj);
            const result = toJSON(bytes);
            expect(result).toEqual(obj);
        });

        it('should throw error for non-Uint8Array input', () => {
            expect(() => toJSON('string')).toThrow('Input must be a Uint8Array');
            expect(() => toJSON(123)).toThrow('Input must be a Uint8Array');
            expect(() => toJSON(null)).toThrow('Input must be a Uint8Array');
            expect(() => toJSON(undefined)).toThrow('Input must be a Uint8Array');
            expect(() => toJSON({})).toThrow('Input must be a Uint8Array');
            expect(() => toJSON([])).toThrow('Input must be a Uint8Array');
        });

        it('should throw error for invalid JSON bytes', () => {
            const invalidBytes = new Uint8Array([123, 34, 97]); // Invalid JSON
            expect(() => toJSON(invalidBytes)).toThrow();
        });
    });
}); 