import { describe, it, expect } from 'vitest';
import { formatMessage, formatMessageHash } from './format.js';

describe('Format utilities', () => {
    describe('formatMessage', () => {
        it('should pass through Uint8Array', () => {
            const bytes = new Uint8Array([1, 2, 3]);
            const result = formatMessage(bytes);
            expect(result).toBe(bytes);
        });

        it('should convert hex string', () => {
            const result = formatMessage('010203');
            expect(result).toBeInstanceOf(Uint8Array);
            expect([...result]).toEqual([1, 2, 3]);
        });

        it('should convert UTF-8 string', () => {
            const result = formatMessage('hello');
            expect(result).toBeInstanceOf(Uint8Array);
            expect([...result]).toEqual([104, 101, 108, 108, 111]);
        });

        it('should convert JSON object', () => {
            const obj = { hello: 'world' };
            const result = formatMessage(obj);
            expect(result).toBeInstanceOf(Uint8Array);
            expect(result.length).toBeGreaterThan(0);
        });

        it('should throw error for invalid input', () => {
            expect(() => formatMessage(123)).toThrow('Message must be a string');
            expect(() => formatMessage(null)).toThrow('Message must be a string');
            expect(() => formatMessage(undefined)).toThrow('Message must be a string');
        });
    });

    describe('formatMessageHash', () => {
        it('should pass through 32-byte Uint8Array', () => {
            const bytes = new Uint8Array(32).fill(1);
            const result = formatMessageHash(bytes);
            expect(result).toBe(bytes);
        });

        it('should convert 32-byte hex string', () => {
            const hex = '0'.repeat(64);
            const result = formatMessageHash(hex);
            expect(result).toBeInstanceOf(Uint8Array);
            expect(result.length).toBe(32);
        });

        it('should throw error for non-32-byte input', () => {
            const shortBytes = new Uint8Array(16);
            const longBytes = new Uint8Array(64);
            expect(() => formatMessageHash(shortBytes)).toThrow('Message hash must be 32 bytes');
            expect(() => formatMessageHash(longBytes)).toThrow('Message hash must be 32 bytes');
        });

        it('should throw error for invalid input', () => {
            expect(() => formatMessageHash(123)).toThrow('Message must be a string');
            expect(() => formatMessageHash(null)).toThrow('Message must be a string');
            expect(() => formatMessageHash(undefined)).toThrow('Message must be a string');
            expect(() => formatMessageHash({})).toThrow('Message must be a string');
        });
    });
}); 