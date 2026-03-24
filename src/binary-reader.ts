/**
 * Cursor-based little-endian binary reader.
 *
 * Replaces Rust's `winnow` parser combinators with an imperative cursor approach.
 */
export class BinaryReader {
  private buf: Buffer;
  private pos: number;

  constructor(buf: Buffer, offset = 0) {
    this.buf = buf;
    this.pos = offset;
  }

  /** Number of bytes remaining from current position. */
  get remaining(): number {
    return Math.max(0, this.buf.length - this.pos);
  }

  /** Current offset into the buffer. */
  get offset(): number {
    return this.pos;
  }

  /** Read an unsigned 8-bit integer. */
  readU8(): number {
    this.ensureAvailable(1);
    const val = this.buf.readUInt8(this.pos);
    this.pos += 1;
    return val;
  }

  /** Read an unsigned 16-bit little-endian integer. */
  readU16LE(): number {
    this.ensureAvailable(2);
    const val = this.buf.readUInt16LE(this.pos);
    this.pos += 2;
    return val;
  }

  /** Read an unsigned 32-bit little-endian integer. */
  readU32LE(): number {
    this.ensureAvailable(4);
    const val = this.buf.readUInt32LE(this.pos);
    this.pos += 4;
    return val;
  }

  /** Read a signed 32-bit little-endian integer. */
  readI32LE(): number {
    this.ensureAvailable(4);
    const val = this.buf.readInt32LE(this.pos);
    this.pos += 4;
    return val;
  }

  /** Read an unsigned 64-bit little-endian integer as BigInt. */
  readU64LE(): bigint {
    this.ensureAvailable(8);
    const val = this.buf.readBigUInt64LE(this.pos);
    this.pos += 8;
    return val;
  }

  /** Read exactly `n` bytes and return a new Buffer (slice, not copy). */
  readBytes(n: number): Buffer {
    this.ensureAvailable(n);
    const slice = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return slice;
  }

  /** Read a UTF-8 string of the given byte length. */
  readUtf8String(size: number): string {
    this.ensureAvailable(size);
    const str = this.buf.toString('utf8', this.pos, this.pos + size);
    this.pos += size;
    return str;
  }

  /** Read a UTF-16LE string of the given byte length. */
  readUtf16String(size: number): string {
    this.ensureAvailable(size);
    const str = this.buf.toString('utf16le', this.pos, this.pos + size);
    this.pos += size;
    return str;
  }

  /** Skip `n` bytes. */
  skip(n: number): void {
    this.ensureAvailable(n);
    this.pos += n;
  }

  /** Move the cursor to an absolute position. */
  moveAt(position: number): void {
    if (position < 0 || position > this.buf.length) {
      throw new Error(
        `BinaryReader EOF: cannot move to position ${position}, buffer length is ${this.buf.length}`,
      );
    }
    this.pos = position;
  }

  /**
   * Read `n` bytes and return a new BinaryReader over them.
   * Advances the current reader's position.
   */
  source(size: number): BinaryReader {
    this.ensureAvailable(size);
    const slice = this.buf.subarray(this.pos, this.pos + size);
    this.pos += size;
    return new BinaryReader(slice);
  }

  /**
   * Read a u32 length prefix, then read that many bytes.
   * Equivalent to Rust's `length_take(le_u32)`.
   */
  readLengthPrefixedU32(): Buffer {
    const len = this.readU32LE();
    return this.readBytes(len);
  }

  /**
   * Create a new BinaryReader over a sub-range of this reader's buffer.
   * Does NOT advance the parent reader's position.
   */
  slice(start: number, end: number): BinaryReader {
    return new BinaryReader(this.buf.subarray(start, end));
  }

  /**
   * Create a new BinaryReader from a Buffer.
   */
  static from(buf: Buffer): BinaryReader {
    return new BinaryReader(buf);
  }

  private ensureAvailable(n: number): void {
    if (this.pos + n > this.buf.length) {
      throw new Error(
        `BinaryReader EOF: need ${n} bytes at offset ${this.pos}, but buffer length is ${this.buf.length}`,
      );
    }
  }
}
