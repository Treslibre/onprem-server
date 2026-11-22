export const CspPayloadType = {
  ECHO_REQUEST: 0x00,
  OUTGOING_MESSAGE: 0x01,
  INCOMING_MESSAGE: 0x02,
  UNBLOCK_INCOMING_MESSAGES: 0x03,
  SET_PUSH_NOTIFICATION_TOKEN: 0x20,
  SET_HIGH_PRIO_PUSH_NOTIFICATION_TOKEN: 0x24,
  DELETE_PUSH_NOTIFICATION_TOKEN: 0x25,
  SET_CONNECTION_IDLE_TIMEOUT: 0x30,
  ECHO_RESPONSE: 0x80,
  OUTGOING_MESSAGE_ACK: 0x81,
  INCOMING_MESSAGE_ACK: 0x82,
  QUEUE_SEND_COMPLETE: 0xd0,
  LAST_EPHEMERAL_KEY_HASH: 0xd1,
  DEVICE_COOKIE_CHANGED_INDICATION: 0xd2,
  CLEAR_DEVICE_COOKIE_CHANGED_INDICATION: 0xd3,
  CLOSE_ERROR: 0xe0,
  ALERT: 0xe1
} as const;

export const CspExtensionType = {
  CLIENT_INFO: 0,
  CSP_DEVICE_ID: 1,
  MESSAGE_PAYLOAD_VERSION: 2,
  DEVICE_COOKIE: 3
} as const;

export const CLEVER_EXTENSION_MAGIC = Buffer.from("threema-clever-extension-field", "ascii");

export interface ParsedCspExtensions {
  clientInfo?: string;
  cspDeviceId?: bigint;
  messagePayloadVersion?: number;
  deviceCookie?: Uint8Array;
}

export function parseCspExtensions(buf: Uint8Array): ParsedCspExtensions {
  const result: ParsedCspExtensions = {};
  const nodeBuf = Buffer.from(buf);
  let offset = 0;

  while (offset + 3 <= nodeBuf.byteLength) {
    const type = nodeBuf.readUInt8(offset);
    const len = nodeBuf.readUInt16LE(offset + 1);
    offset += 3;
    if (offset + len > nodeBuf.byteLength) {
      throw new Error("Truncated CSP extension TLV");
    }
    const value = nodeBuf.subarray(offset, offset + len);
    offset += len;

    switch (type) {
      case CspExtensionType.CLIENT_INFO:
        result.clientInfo = value.toString("utf8");
        break;
      case CspExtensionType.CSP_DEVICE_ID:
        if (value.byteLength === 8) {
          result.cspDeviceId = value.readBigUInt64LE(0);
        }
        break;
      case CspExtensionType.MESSAGE_PAYLOAD_VERSION:
        if (value.byteLength >= 1) {
          result.messagePayloadVersion = value.readUInt8(0);
        }
        break;
      case CspExtensionType.DEVICE_COOKIE:
        result.deviceCookie = new Uint8Array(value);
        break;
      default:
        break;
    }
  }

  return result;
}

export function encodeCspContainer(payloadType: number, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + payload.byteLength);
  out[0] = payloadType & 0xff;
  out.set(payload, 4);
  return out;
}

export function decodeCspContainer(plain: Uint8Array): { payloadType: number; payload: Uint8Array } {
  if (plain.byteLength < 4) {
    throw new Error(`CSP container too short: ${plain.byteLength}`);
  }
  return {
    payloadType: plain[0],
    payload: plain.subarray(4)
  };
}

/**
 * Converts a stored CSP message payload to the target client's negotiated message payload version.
 * Version 0 expects `legacy-message` (no metadata box, metadata-length == 0); version >= 1 expects
 * `message-with-metadata-box` (where metadata-length == 0 is already a valid legacy fallback).
 */
export function convertCspMessagePayload(raw: Uint8Array, targetVersion: number): Uint8Array {
  if (targetVersion >= 1 || raw.byteLength < 88) {
    return raw;
  }
  const buf = Buffer.from(raw);
  const metaLen = buf.readUInt16LE(30);
  if (metaLen === 0 || raw.byteLength < 64 + metaLen + 24) {
    return raw;
  }
  const converted = Buffer.allocUnsafe(raw.byteLength - metaLen);
  buf.copy(converted, 0, 0, 64);
  converted.writeUInt16LE(0, 30);
  buf.copy(converted, 64, 64 + metaLen);
  return new Uint8Array(converted);
}
