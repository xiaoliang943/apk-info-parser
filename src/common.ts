import { BinaryReader } from "./binary-reader.js";

export enum ChunkType {
  NULL = 0x0000,
  STRING_POOL = 0x0001,
  TABLE = 0x0002,
  XML = 0x0003,
  XML_FIRST_CHUNK = 0x0100,
  XML_START_NAMESPACE = 0x0100,
  XML_END_NAMESPACE = 0x0101,
  XML_START_ELEMENT = 0x0102,
  XML_END_ELEMENT = 0x0103,
  XML_CDATA = 0x0104,
  XML_LAST_CHUNK = 0x017f,
  XML_RESOURCE_MAP = 0x0180,
  TABLE_PACKAGE = 0x0200,
  TABLE_TYPE = 0x0201,
  TABLE_TYPE_SPEC = 0x0202,
  TABLE_LIBRARY = 0x0203,
}

export class Chunk {

  public readonly type: number;
  public readonly headerSize: number;
  public readonly chunkSize: number;
  public readonly headerSource: BinaryReader;
  public readonly chunkSource: BinaryReader;

  constructor(source: BinaryReader, chunkType?: ChunkType) {
    this.type = source.readU16LE();
    if (!chunkType || this.type === chunkType) {
      this.headerSize = source.readU16LE();
      this.chunkSize = source.readU32LE();
      this.headerSource = source.source(this.headerSize - 8);
      this.chunkSource = source.source(this.chunkSize - this.headerSize);
    } else {
      throw Error(`Found incorrect chunk type: ${this.type}, expected: ${chunkType}`);
    }
  }
}

export class StringPool {

  private static readUtf8String(source: BinaryReader): string {
    source.skip(1); // Skip char length
    return source.readUtf8String(source.readU8());
  }

  private static readUtf16String(source: BinaryReader): string {
      return source.readUtf16String(source.readU16LE() * 2);
  }
  public readonly stringCount: number;
  public readonly styleCount: number;
  public readonly flags: number;
  public readonly stringsStart: number;
  public readonly stylesStart: number;
  public readonly values: string[];

  constructor(chunk: Chunk) {
    this.stringCount = chunk.headerSource.readU32LE();
    this.styleCount = chunk.headerSource.readU32LE();
    this.flags = chunk.headerSource.readU32LE();
    this.stringsStart = chunk.headerSource.readU32LE();
    this.stylesStart = chunk.headerSource.readU32LE();
    this.values = [];

    const indexes: number[] = [];
    for (let i = 0; i < this.stringCount; ++i) {
      indexes.push(chunk.chunkSource.readU32LE());
    }

    for (const index of indexes) {
      chunk.chunkSource.moveAt(this.stringsStart - chunk.headerSize + index);
      if (this.flags & 256) {
        this.values.push(StringPool.readUtf8String(chunk.chunkSource));
      } else {
        this.values.push(StringPool.readUtf16String(chunk.chunkSource));
      }
    }
  }
}

enum ResourceType {
  NULL = 0x00,
  REFERENCE = 0x01,
  STRING = 0x03,
  INT_DEC = 0x10,
  INT_BOOLEAN = 0x12,
}

export function parseResourceValue(source: BinaryReader, stringPool: StringPool): any {
  source.skip(3); // Size + res0
  const type = source.readU8();
  switch (type) {
    case ResourceType.REFERENCE:
      return source.readI32LE();
    case ResourceType.STRING: {
      const index = source.readI32LE();
      return index >= 0 ? stringPool.values[index] : null;
    }
    case ResourceType.INT_DEC:
      return source.readI32LE();
    case ResourceType.INT_BOOLEAN:
      return source.readI32LE() === 0 ? false : true;
    default:
      return null;
  }
}
