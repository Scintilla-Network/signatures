import { isHexString } from './types.js';
import { fromHex } from './hex.js';

/**
 * Auto-convert various formats to Uint8Array
 * @param {string|object|Uint8Array} message - Message to format
 * @returns {Uint8Array} Formatted message bytes
 * @throws {Error} If input format is invalid
 */
export function formatMessage(message) {
    if (message instanceof Uint8Array) {
        return message;
    }
    if (typeof message === 'string') {
        if (isHexString(message)) {
            return fromHex(message);
        }
        return new TextEncoder().encode(message);
    }
    if (message && typeof message === 'object' && !Array.isArray(message)) {
        try {
            return new TextEncoder().encode(JSON.stringify(message));
        } catch (e) {
            throw new Error('Message must be a string, Uint8Array, or JSON object');
        }
    }
    throw new Error('Message must be a string, Uint8Array, or JSON object');
}

/**
 * Ensure message hash is 32 bytes
 * @param {string|Uint8Array} messageHash - Hash to format
 * @returns {Uint8Array} 32-byte message hash
 * @throws {Error} If input is not a valid 32-byte hash
 */
export function formatMessageHash(messageHash) {
    if (messageHash instanceof Uint8Array) {
        if (messageHash.length !== 32) {
            throw new Error('Message hash must be 32 bytes');
        }
        return messageHash;
    }
    if (typeof messageHash !== 'string') {
        throw new Error('Message must be a string, Uint8Array, or JSON object');
    }
    if (!isHexString(messageHash)) {
        throw new Error('Message must be a string, Uint8Array, or JSON object');
    }
    const bytes = fromHex(messageHash);
    if (bytes.length !== 32) {
        throw new Error('Message hash must be 32 bytes');
    }
    return bytes;
} 