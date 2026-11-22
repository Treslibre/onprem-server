import protobuf from "protobufjs";

// Direct bigint-safe protobuf codec for Threema D2M messages
export const D2mPayloadType = {
  PROXY: 0x00,
  SERVER_HELLO: 0x10,
  CLIENT_HELLO: 0x11,
  SERVER_INFO: 0x12,
  REFLECTION_QUEUE_DRY: 0x20,
  ROLE_PROMOTED_TO_LEADER: 0x21,
  GET_DEVICES_INFO: 0x30,
  DEVICES_INFO: 0x31,
  DROP_DEVICE: 0x32,
  DROP_DEVICE_ACK: 0x33,
  SET_SHARED_DEVICE_DATA: 0x34,
  BEGIN_TRANSACTION: 0x40,
  BEGIN_TRANSACTION_ACK: 0x41,
  COMMIT_TRANSACTION: 0x42,
  COMMIT_TRANSACTION_ACK: 0x43,
  TRANSACTION_REJECTED: 0x44,
  TRANSACTION_ENDED: 0x45,
  REFLECT: 0x80,
  REFLECT_ACK: 0x81,
  REFLECTED: 0x82,
  REFLECTED_ACK: 0x83
} as const;

export const D2mCloseCode = {
  NORMAL: 1000,
  GOING_AWAY: 1001,
  INTERNAL_ERROR: 1011,
  CHAT_SERVER_CLOSED: 4000,
  CHAT_SERVER_UNREACHABLE: 4001,
  CHAT_SERVER_INTERNAL_ERROR: 4009,
  PROTOCOL_ERROR: 4010,
  TRANSACTION_TTL_REACHED: 4011,
  UNKNOWN_MESSAGE_ACKED: 4012,
  CLIENT_TIMEOUT: 4013,
  UNSUPPORTED_PROTOCOL_VERSION: 4110,
  DEVICE_LIMIT_REACHED: 4111,
  DEVICE_ID_REUSED: 4112,
  DEVICE_DROPPED: 4113,
  REFLECTION_QUEUE_LENGTH_LIMIT_REACHED: 4114,
  EXPECTED_DEVICE_SLOT_STATE_MISMATCH: 4115
} as const;

export function encodeD2mContainer(payloadType: number, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + payload.byteLength);
  out[0] = payloadType & 0xff;
  out.set(payload, 4);
  return out;
}

export function decodeD2mContainer(frame: Uint8Array): { payloadType: number; payload: Uint8Array } {
  if (frame.byteLength < 4 || frame.byteLength > 65536) {
    throw new Error(`Invalid D2M frame size: ${frame.byteLength}`);
  }
  return {
    payloadType: frame[0],
    payload: frame.subarray(4)
  };
}

function writeVarintBigInt(writer: protobuf.Writer, value: bigint): void {
  let v = BigInt.asUintN(64, value);
  while (v >= 0x80n) {
    writer.bytes(new Uint8Array([Number((v & 0x7fn) | 0x80n)]));
    v >>= 7n;
  }
  writer.bytes(new Uint8Array([Number(v)]));
}

// Note: protobufjs Writer.bytes prefixes length! Use raw byte writing for varint/fixed64:
function encodeVarintBigIntBytes(value: bigint): Uint8Array {
  const bytes: number[] = [];
  let v = BigInt.asUintN(64, value);
  while (v >= 0x80n) {
    bytes.push(Number((v & 0x7fn) | 0x80n));
    v >>= 7n;
  }
  bytes.push(Number(v));
  return new Uint8Array(bytes);
}

function encodeFixed64Bytes(value: bigint): Uint8Array {
  const buf = Buffer.allocUnsafe(8);
  buf.writeBigUInt64LE(BigInt.asUintN(64, value), 0);
  return new Uint8Array(buf);
}

function readVarintBigInt(reader: protobuf.Reader): bigint {
  let result = 0n;
  let shift = 0n;
  while (reader.pos < reader.len) {
    const b = BigInt(reader.buf[reader.pos++]);
    result |= (b & 0x7fn) << shift;
    if ((b & 0x80n) === 0n) {
      return result;
    }
    shift += 7n;
    if (shift >= 64n) {
      throw new Error("Varint64 overflow");
    }
  }
  throw new Error("Truncated varint64");
}

function readFixed64BigInt(reader: protobuf.Reader): bigint {
  if (reader.pos + 8 > reader.len) {
    throw new Error("Truncated fixed64");
  }
  const buf = Buffer.from(reader.buf.subarray(reader.pos, reader.pos + 8));
  reader.pos += 8;
  return buf.readBigUInt64LE(0);
}

function appendRawTagAndBytes(parts: Uint8Array[], tag: number, rawBody: Uint8Array): void {
  parts.push(encodeVarintBigIntBytes(BigInt(tag)), rawBody);
}

function concatAll(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.byteLength;
  }
  return out;
}

// 1. ClientUrlInfo
export interface ClientUrlInfoMsg {
  deviceGroupId: Uint8Array;
  serverGroup: string;
}

export function encodeClientUrlInfo(msg: ClientUrlInfoMsg): Uint8Array {
  const w = protobuf.Writer.create();
  if (msg.deviceGroupId.byteLength > 0) w.uint32(10).bytes(msg.deviceGroupId);
  if (msg.serverGroup.length > 0) w.uint32(26).string(msg.serverGroup);
  return w.finish();
}

export function decodeClientUrlInfo(data: Uint8Array): ClientUrlInfoMsg {
  const r = protobuf.Reader.create(data);
  let deviceGroupId: Uint8Array = new Uint8Array(0);
  let serverGroup = "";
  while (r.pos < r.len) {
    const tag = r.uint32();
    switch (tag >>> 3) {
      case 1:
        deviceGroupId = new Uint8Array(r.bytes());
        break;
      case 3:
        serverGroup = r.string();
        break;
      default:
        r.skipType(tag & 7);
        break;
    }
  }
  return { deviceGroupId, serverGroup };
}

// 2. ServerHello
export interface ServerHelloMsg {
  version: number;
  esk: Uint8Array;
  challenge: Uint8Array;
}

export function encodeServerHello(msg: ServerHelloMsg): Uint8Array {
  const w = protobuf.Writer.create();
  w.uint32(8).uint32(msg.version);
  w.uint32(18).bytes(msg.esk);
  w.uint32(26).bytes(msg.challenge);
  return w.finish();
}

export function decodeServerHello(data: Uint8Array): ServerHelloMsg {
  const r = protobuf.Reader.create(data);
  let version = 0;
  let esk: Uint8Array = new Uint8Array(0);
  let challenge: Uint8Array = new Uint8Array(0);
  while (r.pos < r.len) {
    const tag = r.uint32();
    switch (tag >>> 3) {
      case 1:
        version = r.uint32();
        break;
      case 2:
        esk = new Uint8Array(r.bytes());
        break;
      case 3:
        challenge = new Uint8Array(r.bytes());
        break;
      default:
        r.skipType(tag & 7);
        break;
    }
  }
  return { version, esk, challenge };
}

// 3. ClientHello
export interface ClientHelloMsg {
  version: number;
  response: Uint8Array;
  deviceId: bigint;
  deviceSlotsExhaustedPolicy: number;
  deviceSlotExpirationPolicy: number;
  encryptedDeviceInfo: Uint8Array;
  expectedDeviceSlotState: number;
}

export function encodeClientHello(msg: ClientHelloMsg): Uint8Array {
  const parts: Uint8Array[] = [];
  const w = protobuf.Writer.create();
  w.uint32(8).uint32(msg.version);
  w.uint32(18).bytes(msg.response);
  parts.push(w.finish());
  appendRawTagAndBytes(parts, 25, encodeFixed64Bytes(msg.deviceId));
  const w2 = protobuf.Writer.create();
  w2.uint32(32).int32(msg.deviceSlotsExhaustedPolicy);
  w2.uint32(40).int32(msg.deviceSlotExpirationPolicy);
  w2.uint32(50).bytes(msg.encryptedDeviceInfo);
  w2.uint32(56).int32(msg.expectedDeviceSlotState);
  parts.push(w2.finish());
  return concatAll(parts);
}

export function decodeClientHello(data: Uint8Array): ClientHelloMsg {
  const r = protobuf.Reader.create(data);
  const out: ClientHelloMsg = {
    version: 0,
    response: new Uint8Array(0),
    deviceId: 0n,
    deviceSlotsExhaustedPolicy: 0,
    deviceSlotExpirationPolicy: 0,
    encryptedDeviceInfo: new Uint8Array(0),
    expectedDeviceSlotState: 0
  };
  while (r.pos < r.len) {
    const tag = r.uint32();
    switch (tag >>> 3) {
      case 1:
        out.version = r.uint32();
        break;
      case 2:
        out.response = new Uint8Array(r.bytes());
        break;
      case 3:
        out.deviceId = readFixed64BigInt(r);
        break;
      case 4:
        out.deviceSlotsExhaustedPolicy = r.int32();
        break;
      case 5:
        out.deviceSlotExpirationPolicy = r.int32();
        break;
      case 6:
        out.encryptedDeviceInfo = new Uint8Array(r.bytes());
        break;
      case 7:
        out.expectedDeviceSlotState = r.int32();
        break;
      default:
        r.skipType(tag & 7);
        break;
    }
  }
  return out;
}

// 4. ServerInfo
export interface ServerInfoMsg {
  maxDeviceSlots: number;
  deviceSlotState: number;
  encryptedSharedDeviceData: Uint8Array;
  currentTime: bigint;
  reflectionQueueLength: number;
}

export function encodeServerInfo(msg: ServerInfoMsg): Uint8Array {
  const parts: Uint8Array[] = [];
  const w = protobuf.Writer.create();
  w.uint32(8).uint32(msg.maxDeviceSlots);
  w.uint32(16).int32(msg.deviceSlotState);
  w.uint32(26).bytes(msg.encryptedSharedDeviceData);
  parts.push(w.finish());
  appendRawTagAndBytes(parts, 32, encodeVarintBigIntBytes(msg.currentTime));
  const w2 = protobuf.Writer.create();
  w2.uint32(40).uint32(msg.reflectionQueueLength);
  parts.push(w2.finish());
  return concatAll(parts);
}

export function decodeServerInfo(data: Uint8Array): ServerInfoMsg {
  const r = protobuf.Reader.create(data);
  const out: ServerInfoMsg = {
    maxDeviceSlots: 0,
    deviceSlotState: 0,
    encryptedSharedDeviceData: new Uint8Array(0),
    currentTime: 0n,
    reflectionQueueLength: 0
  };
  while (r.pos < r.len) {
    const tag = r.uint32();
    switch (tag >>> 3) {
      case 1:
        out.maxDeviceSlots = r.uint32();
        break;
      case 2:
        out.deviceSlotState = r.int32();
        break;
      case 3:
        out.encryptedSharedDeviceData = new Uint8Array(r.bytes());
        break;
      case 4:
        out.currentTime = readVarintBigInt(r);
        break;
      case 5:
        out.reflectionQueueLength = r.uint32();
        break;
      default:
        r.skipType(tag & 7);
        break;
    }
  }
  return out;
}

// 5. DevicesInfo
export interface AugmentedDeviceInfoMsg {
  encryptedDeviceInfo: Uint8Array;
  connectedSince?: bigint;
  lastDisconnectAt?: bigint;
  deviceSlotExpirationPolicy: number;
}

export function encodeAugmentedDeviceInfo(msg: AugmentedDeviceInfoMsg): Uint8Array {
  const parts: Uint8Array[] = [];
  const w1 = protobuf.Writer.create();
  w1.uint32(10).bytes(msg.encryptedDeviceInfo);
  parts.push(w1.finish());
  if (msg.connectedSince !== undefined) {
    appendRawTagAndBytes(parts, 16, encodeVarintBigIntBytes(msg.connectedSince));
  }
  const w2 = protobuf.Writer.create();
  w2.uint32(24).int32(msg.deviceSlotExpirationPolicy);
  parts.push(w2.finish());
  if (msg.lastDisconnectAt !== undefined) {
    appendRawTagAndBytes(parts, 32, encodeVarintBigIntBytes(msg.lastDisconnectAt));
  }
  return concatAll(parts);
}

export function encodeDevicesInfo(entries: Map<bigint, AugmentedDeviceInfoMsg>): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const [deviceId, info] of entries.entries()) {
    const valBytes = encodeAugmentedDeviceInfo(info);
    const entryParts: Uint8Array[] = [];
    appendRawTagAndBytes(entryParts, 9, encodeFixed64Bytes(deviceId));
    const wVal = protobuf.Writer.create();
    wVal.uint32(18).bytes(valBytes);
    entryParts.push(wVal.finish());
    const entryBytes = concatAll(entryParts);

    const wEntry = protobuf.Writer.create();
    wEntry.uint32(10).bytes(entryBytes);
    parts.push(wEntry.finish());
  }
  return concatAll(parts);
}

export function decodeDevicesInfo(data: Uint8Array): Map<bigint, AugmentedDeviceInfoMsg> {
  const r = protobuf.Reader.create(data);
  const result = new Map<bigint, AugmentedDeviceInfoMsg>();
  while (r.pos < r.len) {
    const tag = r.uint32();
    if ((tag >>> 3) === 1) {
      const entryLen = r.uint32();
      const entryEnd = r.pos + entryLen;
      let key = 0n;
      let info: AugmentedDeviceInfoMsg = {
        encryptedDeviceInfo: new Uint8Array(0),
        deviceSlotExpirationPolicy: 0
      };
      while (r.pos < entryEnd) {
        const etag = r.uint32();
        switch (etag >>> 3) {
          case 1:
            key = readFixed64BigInt(r);
            break;
          case 2: {
            const vLen = r.uint32();
            const vEnd = r.pos + vLen;
            while (r.pos < vEnd) {
              const vtag = r.uint32();
              switch (vtag >>> 3) {
                case 1:
                  info.encryptedDeviceInfo = new Uint8Array(r.bytes());
                  break;
                case 2:
                  info.connectedSince = readVarintBigInt(r);
                  break;
                case 3:
                  info.deviceSlotExpirationPolicy = r.int32();
                  break;
                case 4:
                  info.lastDisconnectAt = readVarintBigInt(r);
                  break;
                default:
                  r.skipType(vtag & 7);
                  break;
              }
            }
            break;
          }
          default:
            r.skipType(etag & 7);
            break;
        }
      }
      result.set(key, info);
    } else {
      r.skipType(tag & 7);
    }
  }
  return result;
}

// 6. DropDevice / DropDeviceAck
export function encodeDeviceIdOnly(deviceId: bigint): Uint8Array {
  const parts: Uint8Array[] = [];
  appendRawTagAndBytes(parts, 9, encodeFixed64Bytes(deviceId));
  return concatAll(parts);
}

export function decodeDeviceIdOnly(data: Uint8Array): bigint {
  const r = protobuf.Reader.create(data);
  let deviceId = 0n;
  while (r.pos < r.len) {
    const tag = r.uint32();
    if ((tag >>> 3) === 1) {
      deviceId = readFixed64BigInt(r);
    } else {
      r.skipType(tag & 7);
    }
  }
  return deviceId;
}

// 7. SetSharedDeviceData
export function decodeSetSharedDeviceData(data: Uint8Array): Uint8Array {
  const r = protobuf.Reader.create(data);
  let out: Uint8Array = new Uint8Array(0);
  while (r.pos < r.len) {
    const tag = r.uint32();
    if ((tag >>> 3) === 1) {
      out = new Uint8Array(r.bytes());
    } else {
      r.skipType(tag & 7);
    }
  }
  return out;
}

// 8. BeginTransaction / TransactionRejected / TransactionEnded
export function encodeBeginTransaction(encryptedScope: Uint8Array, ttl: number): Uint8Array {
  const w = protobuf.Writer.create();
  w.uint32(10).bytes(encryptedScope);
  w.uint32(16).uint32(ttl);
  return w.finish();
}

export function decodeBeginTransaction(data: Uint8Array): { encryptedScope: Uint8Array; ttl: number } {
  const r = protobuf.Reader.create(data);
  let encryptedScope: Uint8Array = new Uint8Array(0);
  let ttl = 30;
  while (r.pos < r.len) {
    const tag = r.uint32();
    switch (tag >>> 3) {
      case 1:
        encryptedScope = new Uint8Array(r.bytes());
        break;
      case 2:
        ttl = r.uint32();
        break;
      default:
        r.skipType(tag & 7);
        break;
    }
  }
  return { encryptedScope, ttl };
}

export function encodeTransactionNotification(deviceId: bigint, encryptedScope: Uint8Array): Uint8Array {
  const parts: Uint8Array[] = [];
  appendRawTagAndBytes(parts, 9, encodeFixed64Bytes(deviceId));
  const w = protobuf.Writer.create();
  w.uint32(18).bytes(encryptedScope);
  parts.push(w.finish());
  return concatAll(parts);
}

export function decodeTransactionNotification(data: Uint8Array): {
  deviceId: bigint;
  encryptedScope: Uint8Array;
} {
  const r = protobuf.Reader.create(data);
  let deviceId = 0n;
  let encryptedScope: Uint8Array = new Uint8Array(0);
  while (r.pos < r.len) {
    const tag = r.uint32();
    switch (tag >>> 3) {
      case 1:
        deviceId = readFixed64BigInt(r);
        break;
      case 2:
        encryptedScope = new Uint8Array(r.bytes());
        break;
      default:
        r.skipType(tag & 7);
        break;
    }
  }
  return { deviceId, encryptedScope };
}

// Keep unused reference silenced cleanly
void writeVarintBigInt;
