# WebSocketForge Pro (v1.0.0) — Technical Architecture & Protocol Engineering Manual

## 1\. System Overview

**WebSocketForge Pro** is an enterprise real-time communications engineering and application security studio implementing:

* **IETF RFC 6455**: The WebSocket Protocol.  
* **IETF RFC 3629**: UTF-8, a transformation format of ISO 10646\.  
* **IETF RFC 3174**: US Secure Hash Algorithm 1 (SHA-1) for handshake derivation.  
* **OWASP Top 10 WebSocket Security Risks**: CSWSH defense and frame injection prevention.  
* **IETF RFC 791 (IPv4), RFC 793 (TCP), RFC 1071 (Checksum)**.  
* **IEEE 802.3**: Ethernet II Framing and CRC32 Frame Check Sequence (FCS).

       \+-------------------------------------------------------------+

       |               RFC 6455 WebSocket Frame Header               |

       |  \[Byte 0: FIN (1b) | RSV1..3 (3b) | Opcode (4b)\]            |

       |  \[Byte 1: MASK (1b) | Payload Length Indicator (7b)\]        |

       \+-------------------------------------------------------------+

                                      |

                                      v

       \+-------------------------------------------------------------+

       |               Extended Payload Length (Optional)            |

       |  • 16-bit Unsigned (2 Bytes) if Indicator \== 126            |

       |  • 64-bit Unsigned (8 Bytes) if Indicator \== 127            |

       \+-------------------------------------------------------------+

                                      |

                                      v

       \+-------------------------------------------------------------+

       |               Masking Key (4 Bytes, if MASK \== 1\)           |

       |  • Transformed: octet\[i\] \= orig\[i\] XOR mask\_key\[i % 4\]       |

       \+-------------------------------------------------------------+

                                      |

                                      v

       \+-------------------------------------------------------------+

       |               Application Payload Data                      |

       |  • Text (UTF-8 validated) / Binary / Close / Ping / Pong    |

       \+-------------------------------------------------------------+

---

## 2\. Mathematical Formalisms & Handshake Mechanics

### 2.1 Cryptographic Handshake Key Derivation (RFC 6455 Section 4.2.2)

During the HTTP/1.1 Upgrade handshake, the client sends: \$\$\\text{Sec-WebSocket-Key}: K \\quad (\\text{16-byte random nonce, base64 encoded})\$\$ The server must concatenate the standard GUID constant: \$\$\\text{GUID} \= \\text{"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"}\$\$ \$\$\\text{Input String} \= K ,|, \\text{GUID}\$\$ \$\$\\text{Sec-WebSocket-Accept} \= \\text{Base64}(\\text{SHA-1}(\\text{Input String}))\$\$

### 2.2 Client-to-Server 4-Byte XOR Masking Transformation

RFC 6455 mandates that all frames from client to server MUST be masked with a 4-byte masking key to prevent transparent HTTP proxy cache poisoning: \$\$j \= i \\pmod 4\$\$ \$\$\\text{transformed\_octet}\[i\] \= \\text{original\_octet}\[i\] \\oplus \\text{masking\_key}\[j\]\$\$ Since XOR is involutory (\$X \\oplus Y \\oplus Y \= X\$), the exact same formula is applied by the server to unmask the payload.

### 2.3 Variable-Length Payload Framing

* \$\\text{Length} \\le 125\$: Encoded directly in 7 bits of Byte 1\.  
* \$126 \\le \\text{Length} \\le 65535\$: 7-bit field set to \$126\$, followed by 2 bytes in network byte order.  
* \$\\text{Length} \> 65535\$: 7-bit field set to \$127\$, followed by 8 bytes in network byte order.

---

## 3\. Zero-Trust WebSocket Security Architecture

1. **Anti-CSWSH Origin Validation**: Verifies the `Origin` header during the HTTP Upgrade against an explicit domain whitelist. Drops unauthorized cross-origin requests before socket allocation.  
2. **Mandatory WSS Encrypted Transport (TLS 1.3)**: Prohibits cleartext `ws://` on port 80, eliminating passive sniffing and proxy tampering.  
3. **Strict Client Frame Masking Enforcement**: Drops unmasked client frames immediately with Close Code 1002 (Protocol Error).  
4. **Server Frame Non-Masking**: Strictly transmits unmasked frames from server to client to maintain RFC compliance.  
5. **Payload Size Capping & Rate Limiting**: Caps maximum frame size (\$\\le 64\\text{ KB}\$) and throttles connection requests to defend against denial-of-service (DoS) heap exhaustion.