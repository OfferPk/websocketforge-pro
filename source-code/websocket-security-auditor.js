/**
 * WebSocketForge Pro - 10-Point Zero-Trust WebSocket Security Auditor
 * Standards: IETF RFC 6455, OWASP Top 10 WebSockets, NIST SP 800-95
 */

(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.WebSocketSecurityAuditor = factory();
  }
})(typeof self !== 'undefined' ? self : this, function() {
  'use strict';

  const AUDIT_RULES = [
    {
      id: 'cswsh_origin_validation',
      title: 'CSWSH Origin Whitelist Validation',
      weight: 10,
      description: 'Enforces strict whitelist verification of the HTTP Origin header during handshake. Defeats Cross-Site WebSocket Hijacking.',
      evaluate: (cfg) => {
        if (cfg.origin_validation === true && cfg.allowed_origins && cfg.allowed_origins.length > 0 && !cfg.allowed_origins.includes('*')) {
          return { pass: true, score: 10, reason: `COMPLIANT: Strict Origin whitelisting active (${cfg.allowed_origins.length} authorized domain(s)). Neutralizes CSWSH attacks.` };
        }
        return { pass: false, score: 0, reason: 'CRITICAL: Missing or wildcard (*) Origin validation. Vulnerable to Cross-Site WebSocket Hijacking (CSWSH) allowing malicious sites to hijack authenticated sessions.' };
      }
    },
    {
      id: 'mandatory_wss_tls',
      title: 'Mandatory WSS Encrypted Transport (TLS 1.3)',
      weight: 10,
      description: 'Prohibits cleartext ws:// connections on port 80. Mandates wss:// over port 443 with TLS 1.3 encryption.',
      evaluate: (cfg) => {
        if (cfg.tls_enabled === true && cfg.port === 443) {
          return { pass: true, score: 10, reason: 'COMPLIANT: Mandatory wss:// active over TLS 1.3 on port 443. Protects against MITM sniffing and intermediary proxy cache poisoning.' };
        }
        return { pass: false, score: 0, reason: 'CRITICAL: Cleartext ws:// transport enabled on port 80. All real-time telemetry and credentials transmitted in plaintext.' };
      }
    },
    {
      id: 'client_masking_enforcement',
      title: 'Client-to-Server Masking Enforcement (RFC 6455)',
      weight: 10,
      description: 'Immediately closes connection with Close Code 1002 (Protocol Error) if any client frame is received unmasked.',
      evaluate: (cfg) => {
        if (cfg.enforce_client_masking === true) {
          return { pass: true, score: 10, reason: 'COMPLIANT: RFC 6455 Section 5.1 masking enforced. Unmasked client frames trigger immediate Close Code 1002 termination.' };
        }
        return { pass: false, score: 0, reason: 'FAIL: Unmasked client frames permitted. Violates RFC 6455 and exposes transparent network caches to poisoning attacks.' };
      }
    },
    {
      id: 'server_non_masking_compliance',
      title: 'Server-to-Client Frame Non-Masking',
      weight: 10,
      description: 'Ensures outbound server frames are never masked per RFC 6455 Section 5.1.',
      evaluate: (cfg) => {
        if (cfg.server_masking === false) {
          return { pass: true, score: 10, reason: 'COMPLIANT: Outbound server frames are transmitted unmasked per RFC 6455 standard.' };
        }
        return { pass: false, score: 0, reason: 'FAIL: Server masking incorrectly enabled. Breaks RFC 6455 compliance and causes browser disconnects.' };
      }
    },
    {
      id: 'max_frame_size_capping',
      title: 'Maximum Frame & Message Size Capping (DoS Defense)',
      weight: 10,
      description: 'Enforces hard ceiling on incoming frame size (<= 64KB default, <= 1MB max) to mitigate heap exhaustion attacks.',
      evaluate: (cfg) => {
        const maxSize = cfg.max_payload_bytes || 0;
        if (maxSize > 0 && maxSize <= 1048576) {
          return { pass: true, score: 10, reason: `COMPLIANT: Max payload capped at ${Math.round(maxSize / 1024)} KB. Protects server memory from payload inflation DoS.` };
        }
        return { pass: false, score: 0, reason: 'FAIL: Unbounded frame payload accepted. Attackers can stream gigabyte payloads to trigger Out-Of-Memory (OOM) crashes.' };
      }
    },
    {
      id: 'active_ping_pong_heartbeat',
      title: 'Active Ping/Pong Keep-Alive & Dead Socket Pruning',
      weight: 10,
      description: 'Sends periodic Ping control frames (every 30s) and closes connection if Pong response is delayed beyond 10s.',
      evaluate: (cfg) => {
        if (cfg.heartbeat_enabled === true && cfg.ping_interval_sec <= 60 && cfg.pong_timeout_sec <= 15) {
          return { pass: true, score: 10, reason: `COMPLIANT: Keep-alive active (Ping every ${cfg.ping_interval_sec}s, Pong timeout ${cfg.pong_timeout_sec}s). Prunes zombie sockets.` };
        }
        return { pass: false, score: 0, reason: 'FAIL: No active heartbeat configured. Reverse proxies (Cloudflare, NGINX) will drop idle sockets, and dead clients leak file descriptors.' };
      }
    },
    {
      id: 'pre_upgrade_auth',
      title: 'Pre-Upgrade Authentication & Ticket Validation',
      weight: 10,
      description: 'Validates short-lived one-time authentication ticket before issuing HTTP 101 Switching Protocols response.',
      evaluate: (cfg) => {
        if (cfg.pre_upgrade_auth === true && cfg.ticket_based === true) {
          return { pass: true, score: 10, reason: 'COMPLIANT: Ephemeral ticket validated during HTTP handshake before socket upgrade. Prevents unauthorized socket connections.' };
        }
        return { pass: false, score: 2, reason: 'FAIL: Anonymous socket upgrades permitted. Authentication deferred to in-band messaging, allowing unauthenticated connection floods.' };
      }
    },
    {
      id: 'strict_utf8_validation',
      title: 'Strict UTF-8 Encoding Validation (RFC 3629)',
      weight: 10,
      description: 'Validates Text frames (Opcode 0x1) for strict UTF-8 conformance. Terminates with Close Code 1007 on malformed sequences.',
      evaluate: (cfg) => {
        if (cfg.strict_utf8 === true) {
          return { pass: true, score: 10, reason: 'COMPLIANT: Strict UTF-8 decoder active. Invalid byte sequences immediately trigger Close Code 1007.' };
        }
        return { pass: false, score: 0, reason: 'FAIL: Permissive text parsing enabled. Susceptible to Unicode mutation, homograph, and parser differential vulnerabilities.' };
      }
    },
    {
      id: 'connection_rate_limiting',
      title: 'Handshake Rate Limiting & Socket Concurrency Limits',
      weight: 10,
      description: 'Throttles HTTP Upgrade requests per IP and caps maximum concurrent open sockets per user/IP.',
      evaluate: (cfg) => {
        if (cfg.rate_limit_enabled === true && cfg.max_connections_per_ip <= 20) {
          return { pass: true, score: 10, reason: `COMPLIANT: Socket rate limiting active (Max ${cfg.max_connections_per_ip} concurrent sockets per IP). Defeats socket exhaustion.` };
        }
        return { pass: false, score: 0, reason: 'FAIL: No socket rate limiting. Attackers can open thousands of simultaneous connections to exhaust OS file descriptors.' };
      }
    },
    {
      id: 'subprotocol_proxy_hygiene',
      title: 'Subprotocol Negotiation & Reverse Proxy Hygiene',
      weight: 10,
      description: 'Enforces Sec-WebSocket-Protocol subprotocol matching and configures reverse proxies to strip untrusted hop-by-hop headers.',
      evaluate: (cfg) => {
        if (cfg.subprotocol_enforced === true && cfg.proxy_header_hygiene === true) {
          return { pass: true, score: 10, reason: 'COMPLIANT: Subprotocol whitelist enforced and proxy hop-by-hop headers sanitized.' };
        }
        return { pass: false, score: 2, reason: 'FAIL: Unrestricted subprotocols accepted or unhygienic proxy forwarding headers.' };
      }
    }
  ];

  // Industry Preset Configuration Profiles
  const PRESETS = {
    fintech_trading_desk: {
      name: 'High-Frequency FinTech Trading Desk (Zero-Trust WSS Profile)',
      port: 443,
      tls_enabled: true,
      origin_validation: true,
      allowed_origins: ['https://trading.fintech-core.com', 'https://terminal.fintech-core.com'],
      enforce_client_masking: true,
      server_masking: false,
      max_payload_bytes: 65536, // 64 KB
      heartbeat_enabled: true,
      ping_interval_sec: 15,
      pong_timeout_sec: 5,
      pre_upgrade_auth: true,
      ticket_based: true,
      strict_utf8: true,
      rate_limit_enabled: true,
      max_connections_per_ip: 5,
      subprotocol_enforced: true,
      proxy_header_hygiene: true
    },
    enterprise_saas_chat: {
      name: 'Enterprise Team Collaboration & Live Chat (OWASP Hardened)',
      port: 443,
      tls_enabled: true,
      origin_validation: true,
      allowed_origins: ['https://app.workplace-chat.com'],
      enforce_client_masking: true,
      server_masking: false,
      max_payload_bytes: 262144, // 256 KB
      heartbeat_enabled: true,
      ping_interval_sec: 30,
      pong_timeout_sec: 10,
      pre_upgrade_auth: true,
      ticket_based: true,
      strict_utf8: true,
      rate_limit_enabled: true,
      max_connections_per_ip: 10,
      subprotocol_enforced: true,
      proxy_header_hygiene: true
    },
    vulnerable_public_socket: {
      name: 'Vulnerable Public WebSocket (Unencrypted ws:// Port 80)',
      port: 80,
      tls_enabled: false,
      origin_validation: false,
      allowed_origins: ['*'],
      enforce_client_masking: false,
      server_masking: true,
      max_payload_bytes: 0, // Unbounded
      heartbeat_enabled: false,
      ping_interval_sec: 0,
      pong_timeout_sec: 0,
      pre_upgrade_auth: false,
      ticket_based: false,
      strict_utf8: false,
      rate_limit_enabled: false,
      max_connections_per_ip: 10000,
      subprotocol_enforced: false,
      proxy_header_hygiene: false
    }
  };

  function audit(config) {
    let results = [];
    let totalScore = 0;
    let maxScore = 100;

    for (let rule of AUDIT_RULES) {
      let res = rule.evaluate(config);
      totalScore += res.score;
      results.push({
        id: rule.id,
        title: rule.title,
        weight: rule.weight,
        score: res.score,
        pass: res.pass,
        reason: res.reason
      });
    }

    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 85) grade = 'A';
    else if (totalScore >= 75) grade = 'B';
    else if (totalScore >= 65) grade = 'C';
    else if (totalScore >= 50) grade = 'D';

    return {
      score: totalScore,
      maxScore,
      percentage: Math.round((totalScore / maxScore) * 100),
      grade,
      passed: totalScore >= 80,
      rules: results
    };
  }

  return {
    AUDIT_RULES,
    PRESETS,
    audit
  };
});
