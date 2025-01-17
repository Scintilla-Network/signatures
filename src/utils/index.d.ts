import { Bytes } from '../types';

export function toHex(bytes: Bytes): string;
export function fromHex(hex: string): Bytes;
export function toJSON<T = unknown>(bytes: Bytes): T;
export function fromJSON<T = unknown>(obj: T): Bytes;
export function toUtf8(bytes: Bytes): string;
export function fromUtf8(str: string): Bytes;
export function formatMessage(message: string | object | Bytes): Bytes;
export function formatMessageHash(messageHash: string | Bytes): Bytes;
export function isHexString(value: unknown): value is string;
export function isUint8Array(value: unknown): value is Uint8Array;

interface Utils {
    toHex: typeof toHex;
    fromHex: typeof fromHex;
    toJSON: typeof toJSON;
    fromJSON: typeof fromJSON;
    toUtf8: typeof toUtf8;
    fromUtf8: typeof fromUtf8;
    formatMessage: typeof formatMessage;
    formatMessageHash: typeof formatMessageHash;
    isHexString: typeof isHexString;
    isUint8Array: typeof isUint8Array;
}

export const utils: Utils;
export default utils; 