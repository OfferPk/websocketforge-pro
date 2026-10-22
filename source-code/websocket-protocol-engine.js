/**
 * WebSocketForge Pro - Core Protocol & Wireframe Framing Engine
 * Standard: IETF RFC 6455 (The WebSocket Protocol)
 * IEEE 802.3 Ethernet II + IETF RFC 791 IPv4 + RFC 793 TCP + RFC 1071 Checksum + SHA-1 Handshake
 */

(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.WebSocketProtocolEngine = factory();
  }
})(typeof self !== 'undefined' ? self : this, function() {
  'use strict';

  // RFC 6455 OpCodes
  const OPCODES = {
    CONTINUATION: 0x0,
    TEXT: 0x1,
    BINARY: 0x2,
    CLOSE: 0x8,
    PING: 0x9,
    PONG: 0xA
  };

  const OPCODE_NAMES = {
    0x0: '0x0 Continuation Frame',
    0x1: '0x1 Text Frame (UTF-8)',
    0x2: '0x2 Binary Frame',
    0x8: '0x8 Connection Close',
    0x9: '0x9 Ping',
    0xA: '0xA Pong'
  };

  // RFC 6455 Close Status Codes
  const CLOSE_CODES = {
    NORMAL_CLOSURE: 1000,
    GOING_AWAY: 1001,
    PROTOCOL_ERROR: 1002,
    UNSUPPORTED_DATA: 1003,
    NO_STATUS_RECEIVED: 1005,
    ABNORMAL_CLOSURE: 1006,
    INVALID_FRAME_PAYLOAD: 1007,
    POLICY_VIOLATION: 1008,
    MESSAGE_TOO_BIG: 1009,
    MANDATORY_EXTENSION: 1010,
    INTERNAL_SERVER_ERROR: 1011
  };

  const CLOSE_CODE_NAMES = {
    1000: '1000 Normal Closure',
    1001: '1001 Going Away (Server shutdown or tab closed)',
    1002: '1002 Protocol Error (e.g. unmasked client frame)',
    1003: '1003 Unsupported Data (e.g. binary not accepted)',
    1005: '1005 No Status Received (internal)',
    1006: '1006 Abnormal Closure (connection lost without close frame)',
    1007: '1007 Invalid Frame Payload Data (UTF-8 encoding failure)',
    1008: '1008 Policy Violation (generic refusal)',
    1009: '1009 Message Too Big (payload exceeds server limit)',
    1010: '1010 Mandatory Extension Missing',
    1011: '1011 Internal Server Error'
  };

  const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

  // CRC32 Table for IEEE 802.3 Ethernet Frame Check Sequence
  const CRC32_TABLE = (function() {
    let c, table = [];
    for (let n = 0; n < 256; n++) {
      c = n;
      for (let k = 0; k < 8; k++) {
        c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[n] = c >>> 0;
    }
    return table;
  })();

  function calculateCRC32(bytes) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < bytes.length; i++) {
      crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ bytes[i]) & 0xFF];
    }
    return ((crc ^ 0xFFFFFFFF) >>> 0);
  }

  // RFC 1071 16-bit One's Complement Internet Checksum (IPv4 & TCP)
  function calculateRFC1071Checksum(bytes) {
    let sum = 0;
    for (let i = 0; i < bytes.length; i += 2) {
      let b1 = bytes[i];
      let b2 = (i + 1 < bytes.length) ? bytes[i + 1] : 0;
      sum += (b1 << 8) | b2;
    }
    while (sum >> 16) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (~sum) & 0xFFFF;
  }

  // Pure JavaScript SHA-1 Implementation (RFC 3174) for Sec-WebSocket-Accept calculation
  function sha1(bytes) {
    let words = [];
    for (let i = 0; i < bytes.length; i++) {
      words[i >> 2] |= (bytes[i] & 0xFF) << (24 - (i % 4) * 8);
    }

    let bitLen = bytes.length * 8;
    words[bitLen >> 5] |= 0x80 << (24 - (bitLen % 32));
    words[(((bitLen + 64) >> 9) << 4) + 15] = bitLen;

    let w = new Array(80);
    let a = 0x67452301;
    let b = 0xEFCDAB89;
    let c = 0x98BADCFE;
    let d = 0x10325476;
    let e = 0xC3D2E1F0;

    for (let i = 0; i < words.length; i += 16) {
      let olda = a, oldb = b, oldc = c, oldd = d, olde = e;
      for (let j = 0; j < 80; j++) {
        if (j < 16) {
          w[j] = words[i + j] | 0;
        } else {
          let t = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16];
          w[j] = (t << 1) | (t >>> 31);
        }

        let f, k;
        if (j < 20) {
          f = (b & c) | ((~b) & d);
          k = 0x5A827999;
        } else if (j < 40) {
          f = b ^ c ^ d;
          k = 0x6ED9EBA1;
        } else if (j < 60) {
          f = (b & c) | (b & d) | (c & d);
          k = 0x8F1BBCDC;
        } else {
          f = b ^ c ^ d;
          k = 0xCA62C1D6;
        }

        let temp = (((a << 5) | (a >>> 27)) + f + e + k + w[j]) | 0;
        e = d;
        d = c;
        c = (b << 30) | (b >>> 2);
        b = a;
        a = temp;
      }
      a = (a + olda) | 0;
      b = (b + oldb) | 0;
      c = (c + oldc) | 0;
      d = (d + oldd) | 0;
      e = (e + olde) | 0;
    }

    let out = [];
    let state = [a, b, c, d, e];
    for (let val of state) {
      out.push((val >> 24) & 0xFF);
      out.push((val >> 16) & 0xFF);
      out.push((val >> 8) & 0xFF);
      out.push(val & 0xFF);
    }
    return new Uint8Array(out);
  }

  // Base64 Encoding
  const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  function bytesToBase64(bytes) {
    let result = '';
    let i;
    for (i = 0; i < bytes.length - 2; i += 3) {
      result += B64_CHARS[bytes[i] >> 2];
      result += B64_CHARS[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
      result += B64_CHARS[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
      result += B64_CHARS[bytes[i + 2] & 63];
    }
    if (i < bytes.length) {
      result += B64_CHARS[bytes[i] >> 2];
      if (i === bytes.length - 1) {
        result += B64_CHARS[(bytes[i] & 3) << 4];
        result += '==';
      } else {
        result += B64_CHARS[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
        result += B64_CHARS[(bytes[i + 1] & 15) << 2];
        result += '=';
      }
    }
    return result;
  }

  // Calculate RFC 6455 Sec-WebSocket-Accept Header
  function calculateWebSocketAccept(secWebSocketKey) {
    let combined = secWebSocketKey.trim() + WS_GUID;
    let utf8Bytes = new TextEncoder().encode(combined);
    let hash = sha1(utf8Bytes);
    return bytesToBase64(hash);
  }

  // Apply RFC 6455 Masking (XOR with 4-byte key)
  function applyMask(payloadBytes, maskKey) {
    let out = new Uint8Array(payloadBytes.length);
    for (let i = 0; i < payloadBytes.length; i++) {
      out[i] = payloadBytes[i] ^ maskKey[i % 4];
    }
    return out;
  }

  // Forge an RFC 6455 WebSocket Frame
  function forgeWebSocketFrame(config = {}) {
    const fin = (config.fin !== undefined) ? (config.fin ? 1 : 0) : 1;
    const rsv1 = config.rsv1 ? 1 : 0;
    const rsv2 = config.rsv2 ? 1 : 0;
    const rsv3 = config.rsv3 ? 1 : 0;
    const opcode = (config.opcode !== undefined) ? (config.opcode & 0x0F) : OPCODES.TEXT;
    const isMasked = (config.masked !== undefined) ? Boolean(config.masked) : true;
    const maskKey = config.maskKey ? Array.from(config.maskKey) : [0x37, 0xFA, 0x21, 0x3D];

    // Payload extraction
    let rawPayload = [];
    if (config.closeCode !== undefined) {
      let code = config.closeCode & 0xFFFF;
      rawPayload.push((code >> 8) & 0xFF, code & 0xFF);
      if (config.closeReason) {
        let reasonBytes = new TextEncoder().encode(config.closeReason);
        for (let b of reasonBytes) rawPayload.push(b);
      }
    } else if (typeof config.payload === 'string') {
      rawPayload = Array.from(new TextEncoder().encode(config.payload));
    } else if (Array.isArray(config.payload) || (typeof Uint8Array !== 'undefined' && config.payload instanceof Uint8Array)) {
      rawPayload = Array.from(config.payload);
    }

    let payloadLen = rawPayload.length;
    let frame = [];

    // Byte 0: FIN (1b) | RSV1 (1b) | RSV2 (1b) | RSV3 (1b) | Opcode (4b)
    let b0 = (fin << 7) | (rsv1 << 6) | (rsv2 << 5) | (rsv3 << 4) | opcode;
    frame.push(b0);

    // Byte 1: MASK (1b) | Payload length indicator (7b)
    let maskBit = isMasked ? 0x80 : 0x00;
    if (payloadLen <= 125) {
      frame.push(maskBit | payloadLen);
    } else if (payloadLen <= 65535) {
      frame.push(maskBit | 126);
      frame.push((payloadLen >> 8) & 0xFF);
      frame.push(payloadLen & 0xFF);
    } else {
      frame.push(maskBit | 127);
      // 64-bit length (assuming safe integer range <= 32 bits)
      frame.push(0x00, 0x00, 0x00, 0x00);
      frame.push((payloadLen >> 24) & 0xFF);
      frame.push((payloadLen >> 16) & 0xFF);
      frame.push((payloadLen >> 8) & 0xFF);
      frame.push(payloadLen & 0xFF);
    }

    // Masking Key (4 bytes)
    if (isMasked) {
      for (let i = 0; i < 4; i++) {
        frame.push(maskKey[i] & 0xFF);
      }
    }

    // Mask payload
    let finalPayload = isMasked ? applyMask(new Uint8Array(rawPayload), maskKey) : new Uint8Array(rawPayload);
    for (let b of finalPayload) {
      frame.push(b);
    }

    return new Uint8Array(frame);
  }

  // Dissect an RFC 6455 WebSocket Frame
  function dissectWebSocketFrame(bytes) {
    if (!bytes || bytes.length < 2) {
      throw new Error(`WebSocket frame too short: ${bytes ? bytes.length : 0} bytes (minimum 2 bytes required)`);
    }

    let b0 = bytes[0];
    let fin = Boolean((b0 >> 7) & 0x01);
    let rsv1 = Boolean((b0 >> 6) & 0x01);
    let rsv2 = Boolean((b0 >> 5) & 0x01);
    let rsv3 = Boolean((b0 >> 4) & 0x01);
    let opcode = b0 & 0x0F;
    let opcodeName = OPCODE_NAMES[opcode] || `OpCode 0x${opcode.toString(16)}`;

    let b1 = bytes[1];
    let isMasked = Boolean((b1 >> 7) & 0x01);
    let lenIndicator = b1 & 0x7F;

    let offset = 2;
    let payloadLen = 0;

    if (lenIndicator <= 125) {
      payloadLen = lenIndicator;
    } else if (lenIndicator === 126) {
      if (bytes.length < offset + 2) throw new Error('Truncated 16-bit extended payload length');
      payloadLen = (bytes[offset] << 8) | bytes[offset + 1];
      offset += 2;
    } else if (lenIndicator === 127) {
      if (bytes.length < offset + 8) throw new Error('Truncated 64-bit extended payload length');
      // Read lower 32 bits
      payloadLen = (bytes[offset + 4] << 24) | (bytes[offset + 5] << 16) | (bytes[offset + 6] << 8) | bytes[offset + 7];
      offset += 8;
    }

    let maskKey = null;
    if (isMasked) {
      if (bytes.length < offset + 4) throw new Error('Truncated 4-byte masking key');
      maskKey = Array.from(bytes.slice(offset, offset + 4));
      offset += 4;
    }

    let payloadRaw = bytes.slice(offset, offset + payloadLen);
    let payloadUnmasked = isMasked ? applyMask(payloadRaw, maskKey) : payloadRaw;

    let payloadText = '';
    let closeCode = null;
    let closeReason = '';

    if (opcode === OPCODES.TEXT) {
      try {
        payloadText = new TextDecoder('utf-8', { fatal: true }).decode(payloadUnmasked);
      } catch (_) {
        payloadText = '[INVALID UTF-8 SEQUENCE - RFC 6455 Close 1007 Error]';
      }
    } else if (opcode === OPCODES.CLOSE) {
      if (payloadUnmasked.length >= 2) {
        closeCode = (payloadUnmasked[0] << 8) | payloadUnmasked[1];
        if (payloadUnmasked.length > 2) {
          try {
            closeReason = new TextDecoder('utf-8').decode(payloadUnmasked.slice(2));
          } catch (_) {
            closeReason = '[Malformed reason string]';
          }
        }
      }
      payloadText = `Close Code ${closeCode || 1005} (${CLOSE_CODE_NAMES[closeCode] || 'Unknown'})${closeReason ? ': ' + closeReason : ''}`;
    } else if (opcode === OPCODES.PING || opcode === OPCODES.PONG) {
      payloadText = new TextDecoder('utf-8', { fatal: false }).decode(payloadUnmasked);
    } else {
      payloadText = `[Binary: ${payloadUnmasked.length} bytes]`;
    }

    return {
      fin,
      rsv1,
      rsv2,
      rsv3,
      opcode,
      opcodeName,
      isControl: (opcode & 0x08) !== 0,
      masked: isMasked,
      maskKey,
      maskKeyHex: maskKey ? maskKey.map(b => b.toString(16).padStart(2, '0')).join('') : 'None',
      lenIndicator,
      payloadLength: payloadLen,
      headerLength: offset,
      payloadRaw: Array.from(payloadRaw),
      payloadUnmasked: Array.from(payloadUnmasked),
      payloadText,
      closeCode,
      closeReason,
      totalLength: bytes.length
    };
  }

  // Assemble Complete Ethernet II + IPv4 + TCP + WebSocket Frame
  function forgeEthernetIpTcpWebSocket(wsBytes, config = {}) {
    const srcMac = config.srcMac || [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
    const dstMac = config.dstMac || [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    const srcIp = config.srcIp || [192, 168, 1, 50];
    const dstIp = config.dstIp || [10, 0, 0, 1]; // WebSocket Server IP
    const srcPort = config.srcPort || 51234;
    const dstPort = config.dstPort || 443; // Standard WSS Port (or 80)

    let tcpLength = 20 + wsBytes.length;
    let ipTotalLength = 20 + tcpLength;

    // IPv4 Header (20 bytes)
    let ipHeader = [
      0x45,               // Version 4, IHL 5
      0x00,               // DSCP / ECN
      (ipTotalLength >> 8) & 0xFF, ipTotalLength & 0xFF,
      0x7B, 0x2A,         // Identification
      0x40, 0x00,         // Don't Fragment (DF)
      64,                 // TTL
      6,                  // Protocol: TCP (6)
      0x00, 0x00,         // Checksum placeholder
      srcIp[0], srcIp[1], srcIp[2], srcIp[3],
      dstIp[0], dstIp[1], dstIp[2], dstIp[3]
    ];

    let ipCksum = calculateRFC1071Checksum(ipHeader);
    ipHeader[10] = (ipCksum >> 8) & 0xFF;
    ipHeader[11] = ipCksum & 0xFF;

    // TCP Header (20 bytes)
    let tcpHeader = [
      (srcPort >> 8) & 0xFF, srcPort & 0xFF,
      (dstPort >> 8) & 0xFF, dstPort & 0xFF,
      0x30, 0x00, 0x00, 0x01, // Seq: 0x30000001
      0x40, 0x00, 0x00, 0x01, // Ack: 0x40000001
      0x50,                   // Data Offset (20 bytes)
      0x18,                   // Flags: PSH | ACK
      0xFA, 0xF0,             // Window Size 64240
      0x00, 0x00,             // Checksum placeholder
      0x00, 0x00              // Urgent Pointer
    ];

    // TCP Pseudo-Header
    let pseudoHeader = [
      srcIp[0], srcIp[1], srcIp[2], srcIp[3],
      dstIp[0], dstIp[1], dstIp[2], dstIp[3],
      0x00, 6,
      (tcpLength >> 8) & 0xFF, tcpLength & 0xFF
    ];

    let tcpChecksumPayload = pseudoHeader.concat(tcpHeader).concat(Array.from(wsBytes));
    let tcpCksum = calculateRFC1071Checksum(tcpChecksumPayload);
    tcpHeader[16] = (tcpCksum >> 8) & 0xFF;
    tcpHeader[17] = tcpCksum & 0xFF;

    // Ethernet II Header (14 bytes)
    let ethHeader = dstMac.concat(srcMac).concat([0x08, 0x00]);

    let frameNoFcs = ethHeader.concat(ipHeader).concat(tcpHeader).concat(Array.from(wsBytes));

    // Pad to Ethernet minimum 60 bytes before FCS
    while (frameNoFcs.length < 60) {
      frameNoFcs.push(0x00);
    }

    let fcs = calculateCRC32(frameNoFcs);
    let finalFrame = frameNoFcs.concat([
      (fcs >> 24) & 0xFF,
      (fcs >> 16) & 0xFF,
      (fcs >> 8) & 0xFF,
      fcs & 0xFF
    ]);

    return new Uint8Array(finalFrame);
  }

  // Build standard PCAP file binary buffer
  function buildPcap(frames, timestampSec = 1791000000) {
    let pcapBytes = [];
    pcapBytes.push(0xD4, 0xC3, 0xB2, 0xA1); // Little endian magic
    pcapBytes.push(0x02, 0x00); // Version Major 2
    pcapBytes.push(0x04, 0x00); // Version Minor 4
    pcapBytes.push(0x00, 0x00, 0x00, 0x00); // Thiszone
    pcapBytes.push(0x00, 0x00, 0x00, 0x00); // Sigfigs
    pcapBytes.push(0xFF, 0xFF, 0x00, 0x00); // Snaplen 65535
    pcapBytes.push(0x01, 0x00, 0x00, 0x00); // LINKTYPE_ETHERNET (1)

    for (let i = 0; i < frames.length; i++) {
      let frame = frames[i];
      let len = frame.length;
      let tsSec = timestampSec + i;
      let tsUsec = 100000 * i;

      pcapBytes.push(tsSec & 0xFF, (tsSec >> 8) & 0xFF, (tsSec >> 16) & 0xFF, (tsSec >> 24) & 0xFF);
      pcapBytes.push(tsUsec & 0xFF, (tsUsec >> 8) & 0xFF, (tsUsec >> 16) & 0xFF, (tsUsec >> 24) & 0xFF);
      pcapBytes.push(len & 0xFF, (len >> 8) & 0xFF, (len >> 16) & 0xFF, (len >> 24) & 0xFF);
      pcapBytes.push(len & 0xFF, (len >> 8) & 0xFF, (len >> 16) & 0xFF, (len >> 24) & 0xFF);

      for (let b of frame) {
        pcapBytes.push(b);
      }
    }
    return new Uint8Array(pcapBytes);
  }

  // Format Wireshark-Style Hex Dump
  function formatWiresharkHexDump(bytes) {
    let lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      let offset = i.toString(16).padStart(4, '0');
      let hexPart = [];
      let asciiPart = [];
      for (let j = 0; j < 16; j++) {
        if (i + j < bytes.length) {
          let b = bytes[i + j];
          hexPart.push(b.toString(16).padStart(2, '0'));
          asciiPart.push(b >= 32 && b <= 126 ? String.fromCharCode(b) : '.');
        } else {
          hexPart.push('  ');
          asciiPart.push(' ');
        }
      }
      let leftHalf = hexPart.slice(0, 8).join(' ');
      let rightHalf = hexPart.slice(8, 16).join(' ');
      lines.push(`${offset}   ${leftHalf}  ${rightHalf}   ${asciiPart.join('')}`);
    }
    return lines.join('\n');
  }

  return {
    OPCODES,
    OPCODE_NAMES,
    CLOSE_CODES,
    CLOSE_CODE_NAMES,
    WS_GUID,
    calculateCRC32,
    calculateRFC1071Checksum,
    sha1,
    bytesToBase64,
    calculateWebSocketAccept,
    applyMask,
    forgeWebSocketFrame,
    dissectWebSocketFrame,
    forgeEthernetIpTcpWebSocket,
    buildPcap,
    formatWiresharkHexDump
  };
});
