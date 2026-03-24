import { describe, expect, it } from 'vitest';
import { BinaryReader } from '../src/binary-reader.js';

describe('BinaryReader', () => {
  it('reads u16 little-endian', () => {
    const buf = Buffer.from([0x01, 0x02]);
    const reader = BinaryReader.from(buf);
    expect(reader.readU16LE()).toBe(0x0201);
    expect(reader.remaining).toBe(0);
  });

  it('reads u32 little-endian', () => {
    const buf = Buffer.from([0x78, 0x56, 0x34, 0x12]);
    const reader = BinaryReader.from(buf);
    expect(reader.readU32LE()).toBe(0x12345678);
    expect(reader.remaining).toBe(0);
  });

  it('reads u64 little-endian', () => {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64LE(0x0102030405060708n);
    const reader = BinaryReader.from(buf);
    expect(reader.readU64LE()).toBe(0x0102030405060708n);
    expect(reader.remaining).toBe(0);
  });

  it('reads bytes', () => {
    const buf = Buffer.from([0xAA, 0xBB, 0xCC, 0xDD]);
    const reader = BinaryReader.from(buf);
    const slice = reader.readBytes(2);
    expect(slice).toEqual(Buffer.from([0xAA, 0xBB]));
    expect(reader.remaining).toBe(2);
  });

  it('skips bytes', () => {
    const buf = Buffer.from([0x01, 0x02, 0x03, 0x04]);
    const reader = BinaryReader.from(buf);
    reader.skip(2);
    expect(reader.offset).toBe(2);
    expect(reader.readU16LE()).toBe(0x0403);
  });

  it('reads length-prefixed u32 data', () => {
    // length = 3 (LE: 03 00 00 00), then 3 bytes of data
    const buf = Buffer.from([0x03, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC]);
    const reader = BinaryReader.from(buf);
    const data = reader.readLengthPrefixedU32();
    expect(data).toEqual(Buffer.from([0xAA, 0xBB, 0xCC]));
    expect(reader.remaining).toBe(0);
  });

  it('throws on EOF for readU16LE', () => {
    const buf = Buffer.from([0x01]);
    const reader = BinaryReader.from(buf);
    expect(() => reader.readU16LE()).toThrow('BinaryReader EOF');
  });

  it('throws on EOF for readU32LE', () => {
    const buf = Buffer.from([0x01, 0x02]);
    const reader = BinaryReader.from(buf);
    expect(() => reader.readU32LE()).toThrow('BinaryReader EOF');
  });

  it('throws on EOF for readBytes', () => {
    const buf = Buffer.from([0x01]);
    const reader = BinaryReader.from(buf);
    expect(() => reader.readBytes(5)).toThrow('BinaryReader EOF');
  });

  it('throws on EOF for skip', () => {
    const buf = Buffer.from([0x01]);
    const reader = BinaryReader.from(buf);
    expect(() => reader.skip(10)).toThrow('BinaryReader EOF');
  });

  it('creates a sub-slice reader', () => {
    const buf = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05]);
    const reader = BinaryReader.from(buf);
    const sub = reader.slice(1, 4);
    expect(sub.remaining).toBe(3);
    expect(sub.readU16LE()).toBe(0x0302);
    expect(sub.remaining).toBe(1);
  });

  it('reads sequential mixed types', () => {
    const buf = Buffer.alloc(14);
    buf.writeUInt16LE(0x1234, 0);
    buf.writeUInt32LE(0xDEADBEEF, 2);
    buf.writeBigUInt64LE(0x0807060504030201n, 6);

    const reader = BinaryReader.from(buf);
    expect(reader.readU16LE()).toBe(0x1234);
    expect(reader.readU32LE()).toBe(0xDEADBEEF);
    expect(reader.readU64LE()).toBe(0x0807060504030201n);
    expect(reader.remaining).toBe(0);
  });

  it('handles empty buffer', () => {
    const reader = BinaryReader.from(Buffer.alloc(0));
    expect(reader.remaining).toBe(0);
    expect(() => reader.readU16LE()).toThrow('BinaryReader EOF');
  });

  it('handles length-prefixed with zero length', () => {
    const buf = Buffer.from([0x00, 0x00, 0x00, 0x00]);
    const reader = BinaryReader.from(buf);
    const data = reader.readLengthPrefixedU32();
    expect(data.length).toBe(0);
    expect(reader.remaining).toBe(0);
  });

  it('reads u8', () => {
    const buf = Buffer.from([0x42]);
    const reader = BinaryReader.from(buf);
    expect(reader.readU8()).toBe(0x42);
    expect(reader.remaining).toBe(0);
  });

  it('throws on EOF for readU8', () => {
    const reader = BinaryReader.from(Buffer.alloc(0));
    expect(() => reader.readU8()).toThrow('BinaryReader EOF');
  });

  it('reads i32 little-endian', () => {
    const buf = Buffer.alloc(4);
    buf.writeInt32LE(-123456, 0);
    const reader = BinaryReader.from(buf);
    expect(reader.readI32LE()).toBe(-123456);
    expect(reader.remaining).toBe(0);
  });

  it('throws on EOF for readI32LE', () => {
    const buf = Buffer.from([0x01, 0x02, 0x03]);
    const reader = BinaryReader.from(buf);
    expect(() => reader.readI32LE()).toThrow('BinaryReader EOF');
  });

  it('reads UTF-8 string', () => {
    const str = 'Hello';
    const buf = Buffer.from(str, 'utf8');
    const reader = BinaryReader.from(buf);
    expect(reader.readUtf8String(5)).toBe('Hello');
    expect(reader.remaining).toBe(0);
  });

  it('throws on EOF for readUtf8String', () => {
    const buf = Buffer.from([0x48, 0x65]);
    const reader = BinaryReader.from(buf);
    expect(() => reader.readUtf8String(5)).toThrow('BinaryReader EOF');
  });

  it('reads UTF-16LE string', () => {
    const str = 'Hi';
    const buf = Buffer.from(str, 'utf16le');
    const reader = BinaryReader.from(buf);
    expect(reader.readUtf16String(4)).toBe('Hi');
    expect(reader.remaining).toBe(0);
  });

  it('throws on EOF for readUtf16String', () => {
    const buf = Buffer.from([0x48, 0x00]);
    const reader = BinaryReader.from(buf);
    expect(() => reader.readUtf16String(4)).toThrow('BinaryReader EOF');
  });

  it('moves to absolute position', () => {
    const buf = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05]);
    const reader = BinaryReader.from(buf);
    reader.moveAt(3);
    expect(reader.offset).toBe(3);
    expect(reader.readU16LE()).toBe(0x0504);
  });

  it('throws on moveAt out of bounds', () => {
    const buf = Buffer.from([0x01, 0x02]);
    const reader = BinaryReader.from(buf);
    expect(() => reader.moveAt(5)).toThrow('BinaryReader EOF');
    expect(() => reader.moveAt(-1)).toThrow('BinaryReader EOF');
  });

  it('creates sub-reader with source', () => {
    const buf = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05]);
    const reader = BinaryReader.from(buf);
    const sub = reader.source(3);
    expect(sub.remaining).toBe(3);
    expect(sub.readU8()).toBe(0x01);
    expect(reader.remaining).toBe(2);
    expect(reader.readU8()).toBe(0x04);
  });

  it('throws on EOF for source', () => {
    const buf = Buffer.from([0x01, 0x02]);
    const reader = BinaryReader.from(buf);
    expect(() => reader.source(5)).toThrow('BinaryReader EOF');
  });
});
