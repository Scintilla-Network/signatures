import { Bytes } from '../types.js';
import { mod } from './mod.js';

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

// Byte utilities
export function numberToBytesBE(n: number | bigint, length: number): Bytes;
export function numberToBytesLE(n: number | bigint, length: number): Bytes;
export function bytesToNumberBE(bytes: Bytes): bigint;
export function bytesToNumberLE(bytes: Bytes): bigint;
export function concatBytes(...arrays: Bytes[]): Bytes;
export function equalBytes(a: Bytes, b: Bytes): boolean;

// Number utilities
export function isPositiveBigInt(n: unknown): n is bigint;
export function inRange(n: bigint, min: bigint, max: bigint): boolean;
export function assertInRange(name: string, n: bigint, min: bigint, max: bigint): void;
export function bitLength(n: bigint): number;
export function getBit(n: bigint, pos: number): bigint;
export function setBit(n: bigint, pos: number, value: boolean): bigint;
export function bitMask(n: number): bigint;

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
    mod: typeof mod;
    numberToBytesBE: typeof numberToBytesBE;
    numberToBytesLE: typeof numberToBytesLE;
    bytesToNumberBE: typeof bytesToNumberBE;
    bytesToNumberLE: typeof bytesToNumberLE;
    concatBytes: typeof concatBytes;
    equalBytes: typeof equalBytes;
    isPositiveBigInt: typeof isPositiveBigInt;
    inRange: typeof inRange;
    assertInRange: typeof assertInRange;
    bitLength: typeof bitLength;
    getBit: typeof getBit;
    setBit: typeof setBit;
    bitMask: typeof bitMask;
}

export const utils: Utils;
export default utils; 