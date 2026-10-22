/**
 * WebSocketForge Pro - Web Application Controller & State Manager
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  // DOM Elements
  const profileSelect = document.getElementById('profileSelect');
  const frameDirection = document.getElementById('frameDirection');
  const frameOpcode = document.getElementById('frameOpcode');
  const finBit = document.getElementById('finBit');
  const maskKeyHex = document.getElementById('maskKeyHex');
  const closeCodeGroup = document.getElementById('closeCodeGroup');
  const closeCodeSelect = document.getElementById('closeCodeSelect');
  const payloadText = document.getElementById('payloadText');
  const btnForge = document.getElementById('btnForge');
  const btnDownloadPcap = document.getElementById('btnDownloadPcap');

  const kpiOpcode = document.getElementById('kpiOpcode');
  const kpiOpcodeSub = document.getElementById('kpiOpcodeSub');
  const kpiWireSize = document.getElementById('kpiWireSize');
  const kpiMask = document.getElementById('kpiMask');
  const kpiAuditScore = document.getElementById('kpiAuditScore');
  const kpiAuditGrade = document.getElementById('kpiAuditGrade');

  const hexDump = document.getElementById('hexDump');
  const decodedTree = document.getElementById('decodedTree');
  const handshakeKeyInput = document.getElementById('handshakeKeyInput');
  const handshakeCombined = document.getElementById('handshakeCombined');
  const handshakeAcceptOutput = document.getElementById('handshakeAcceptOutput');
  const handshakeHeadersPreview = document.getElementById('handshakeHeadersPreview');
  const xorMaskingVisual = document.getElementById('xorMaskingVisual');
  const closeCodeTable = document.getElementById('closeCodeTable');
  const auditList = document.getElementById('auditList');
  const synthPlatform = document.getElementById('synthPlatform');
  const synthOutput = document.getElementById('synthOutput');
  const btnCopySynth = document.getElementById('btnCopySynth');

  let currentWsBytes = null;
  let currentWireFrame = null;
  let currentPcapBytes = null;

  // Tab Navigation
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      const target = document.getElementById(btn.dataset.tab);
      if (target) target.classList.add('active');
    });
  });

  // Toggle Close Code Group based on OpCode
  frameOpcode.addEventListener('change', () => {
    if (frameOpcode.value === '8') {
      closeCodeGroup.style.display = 'block';
    } else {
      closeCodeGroup.style.display = 'none';
    }
  });

  // Profile Change Handler
  profileSelect.addEventListener('change', () => {
    const pKey = profileSelect.value;
    const p = WebSocketSecurityAuditor.PRESETS[pKey];
    if (!p) return;

    if (pKey === 'fintech_trading_desk') {
      frameDirection.value = 'client';
      frameOpcode.value = '1'; // Text
      finBit.value = '1';
      maskKeyHex.value = '37fa213d';
      closeCodeGroup.style.display = 'none';
      payloadText.value = '{"action":"subscribe","channel":"BTC-USD-ORDERBOOK","rate":50}';
    } else if (pKey === 'enterprise_saas_chat') {
      frameDirection.value = 'client';
      frameOpcode.value = '1'; // Text
      finBit.value = '1';
      maskKeyHex.value = 'a4b1c2d3';
      closeCodeGroup.style.display = 'none';
      payloadText.value = '{"event":"chat_msg","room":"incident-war-room","user":"lead_sre","msg":"Core database failover initiated."}';
    } else if (pKey === 'vulnerable_public_socket') {
      frameDirection.value = 'server';
      frameOpcode.value = '8'; // Close
      finBit.value = '1';
      maskKeyHex.value = '';
      closeCodeGroup.style.display = 'block';
      closeCodeSelect.value = '1002'; // Protocol Error
      payloadText.value = 'Protocol Error: Unmasked frame received from client';
    }

    renderAll();
  });

  // Parse Mask Key Hex
  function parseMaskKey(hexStr) {
    let clean = (hexStr || '').replace(/[^0-9a-fA-F]/g, '');
    let bytes = [];
    for (let i = 0; i < 8; i += 2) {
      if (i < clean.length) {
        bytes.push(parseInt(clean.substr(i, 2), 16) || 0);
      } else {
        bytes.push(0);
      }
    }
    return bytes.slice(0, 4);
  }

  // Primary Render Function
  function renderAll() {
    const direction = frameDirection.value;
    const isMasked = (direction === 'client');
    const op = parseInt(frameOpcode.value, 10);
    const fin = (finBit.value === '1');
    const maskBytes = parseMaskKey(maskKeyHex.value);
    const textData = payloadText.value;

    let frameCfg = {
      fin,
      opcode: op,
      masked: isMasked,
      maskKey: maskBytes
    };

    if (op === 8) {
      frameCfg.closeCode = parseInt(closeCodeSelect.value, 10) || 1000;
      frameCfg.closeReason = textData;
    } else {
      frameCfg.payload = textData;
    }

    currentWsBytes = WebSocketProtocolEngine.forgeWebSocketFrame(frameCfg);
    currentWireFrame = WebSocketProtocolEngine.forgeEthernetIpTcpWebSocket(currentWsBytes);
    currentPcapBytes = WebSocketProtocolEngine.buildPcap([currentWireFrame]);

    // Dissect for verification
    const dissected = WebSocketProtocolEngine.dissectWebSocketFrame(currentWsBytes);

    // Update KPI Stats Strip
    let opShort = ['CONT', 'TEXT', 'BIN', 'RSV', 'RSV', 'RSV', 'RSV', 'RSV', 'CLOSE', 'PING', 'PONG'][op] || 'UNKNOWN';
    kpiOpcode.textContent = `0x${op.toString(16).toUpperCase()} (${opShort})`;
    kpiOpcodeSub.textContent = `FIN=${fin ? 1 : 0} | MASK=${isMasked ? 1 : 0}`;
    kpiWireSize.textContent = `${currentWireFrame.length} Bytes`;
    kpiMask.textContent = isMasked ? `0x${dissected.maskKeyHex.toUpperCase()}` : 'Unmasked';
    kpiMask.style.color = isMasked ? 'var(--accent-amber)' : 'var(--text-dim)';

    // Evaluate Security Audit
    const currentPresetKey = profileSelect.value;
    const currentPreset = WebSocketSecurityAuditor.PRESETS[currentPresetKey] || WebSocketSecurityAuditor.PRESETS.fintech_trading_desk;
    const auditRes = WebSocketSecurityAuditor.audit(currentPreset);

    kpiAuditScore.textContent = `${auditRes.score}/100`;
    kpiAuditGrade.textContent = `Grade ${auditRes.grade} (${auditRes.passed ? 'Certified' : 'At-Risk'})`;
    kpiAuditScore.style.color = auditRes.score >= 80 ? 'var(--accent-green)' : 'var(--accent-red)';

    // Tab 1: Hex Dump & Protocol Tree
    hexDump.textContent = WebSocketProtocolEngine.formatWiresharkHexDump(currentWireFrame);

    let b0 = currentWsBytes[0].toString(16).padStart(2, '0').toUpperCase();
    let b1 = currentWsBytes[1].toString(16).padStart(2, '0').toUpperCase();

    let treeHtml = `
      <div><strong>Frame Length:</strong> ${currentWireFrame.length} bytes (IEEE 802.3 Ethernet II + IPv4 + TCP + RFC 6455 WebSocket)</div>
      <div><strong>Header Byte 0 (0x${b0}):</strong> FIN=${dissected.fin ? 1 : 0} | RSV1..3=0 | OpCode=0x${dissected.opcode.toString(16)} (<strong>${dissected.opcodeName}</strong>)</div>
      <div><strong>Header Byte 1 (0x${b1}):</strong> MASK=${dissected.masked ? 1 : 0} | Length Indicator=${dissected.lenIndicator}</div>
      <div><strong>Payload Length:</strong> ${dissected.payloadLength} bytes | <strong>Header Overhead:</strong> ${dissected.headerLength} bytes</div>
      <div><strong>Masking Key:</strong> ${dissected.masked ? '0x' + dissected.maskKeyHex.toUpperCase() + ' (4 Bytes)' : 'None (Server-to-Client Frame)'}</div>
    `;
    if (dissected.masked && dissected.payloadLength > 0) {
      let rawSample = dissected.payloadRaw.slice(0, 16).map(b => b.toString(16).padStart(2, '0')).join(' ');
      treeHtml += `<div><strong>Masked Payload on Wire (First 16B):</strong> <span style="color: var(--accent-amber);">${rawSample}...</span></div>`;
    }
    treeHtml += `<div><strong>Unmasked Application Payload:</strong> <span style="color: var(--accent-green); font-weight: 600;">${dissected.payloadText}</span></div>`;
    decodedTree.innerHTML = treeHtml;

    // Tab 2: Handshake Verification
    renderHandshake(currentPreset);

    // Tab 3: XOR Masking & Close Codes
    renderXorMasking(dissected);
    renderCloseCodeTable();

    // Tab 4: Zero-Trust Security Audit & Synthesizer
    renderSecurityAudit(auditRes);
    renderSynthesizer(currentPreset);
  }

  // Render Handshake Verification Tab
  function renderHandshake(preset) {
    const key = handshakeKeyInput.value.trim() || 'dGhlIHNhbXBsZSBub25jZQ==';
    const combined = key + WebSocketProtocolEngine.WS_GUID;
    const accept = WebSocketProtocolEngine.calculateWebSocketAccept(key);

    handshakeCombined.textContent = combined;
    handshakeAcceptOutput.textContent = accept;

    const allowedOrigin = (preset.allowed_origins && preset.allowed_origins[0]) || 'https://app.workplace-chat.com';

    handshakeHeadersPreview.textContent =
`HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: ${accept}
Sec-WebSocket-Protocol: v1.chat.fintech
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Access-Control-Allow-Origin: ${allowedOrigin}`;
  }

  handshakeKeyInput.addEventListener('input', () => {
    const currentPresetKey = profileSelect.value;
    const currentPreset = WebSocketSecurityAuditor.PRESETS[currentPresetKey] || WebSocketSecurityAuditor.PRESETS.fintech_trading_desk;
    renderHandshake(currentPreset);
  });

  // Render XOR Masking Steps
  function renderXorMasking(dissected) {
    if (!dissected.masked || dissected.payloadLength === 0) {
      xorMaskingVisual.innerHTML = '<div style="color: var(--text-dim); padding: 8px 0;">Frame is unmasked (Server-to-Client frame or empty payload). No XOR transformation applied.</div>';
      return;
    }

    const mask = dissected.maskKey;
    let sampleLen = Math.min(dissected.payloadLength, 8);
    let lines = [];
    lines.push(`<strong>4-Byte Masking Key:</strong> [0x${mask[0].toString(16).padStart(2,'0')}, 0x${mask[1].toString(16).padStart(2,'0')}, 0x${mask[2].toString(16).padStart(2,'0')}, 0x${mask[3].toString(16).padStart(2,'0')}]`);
    lines.push('<br><strong>First Byte Transformations:</strong>');

    for (let i = 0; i < sampleLen; i++) {
      let orig = dissected.payloadUnmasked[i];
      let m = mask[i % 4];
      let masked = dissected.payloadRaw[i];
      let charStr = (orig >= 32 && orig <= 126) ? `'${String.fromCharCode(orig)}'` : 'non-printable';

      lines.push(`• Byte [${i}] (${charStr}): 0x${orig.toString(16).padStart(2,'0')} ^ 0x${m.toString(16).padStart(2,'0')} (Key[${i%4}]) = <span style="color: var(--accent-amber);">0x${masked.toString(16).padStart(2,'0')}</span>`);
    }

    xorMaskingVisual.innerHTML = lines.join('<br>');
  }

  // Render Close Codes Reference Table
  function renderCloseCodeTable() {
    const codes = [
      { code: 1000, name: 'Normal Closure', desc: 'Purpose for which the connection was established has been completed.' },
      { code: 1001, name: 'Going Away', desc: 'Endpoint is going away (server shutting down, or browser navigating away).' },
      { code: 1002, name: 'Protocol Error', desc: 'Endpoint terminating connection due to protocol violation (e.g. unmasked client frame).' },
      { code: 1003, name: 'Unsupported Data', desc: 'Endpoint received a type of data it cannot accept (e.g. binary frame on text-only socket).' },
      { code: 1007, name: 'Invalid Payload Data', desc: 'Endpoint received data within a message that was not consistent with the message type (e.g. non-UTF-8 in text frame).' },
      { code: 1008, name: 'Policy Violation', desc: 'Endpoint terminating connection because it has received a message that violates its policy.' },
      { code: 1009, name: 'Message Too Big', desc: 'Endpoint received a message that is too large for it to process.' },
      { code: 1011, name: 'Internal Server Error', desc: 'Server terminating connection because it encountered an unexpected condition that prevented fulfillment.' }
    ];

    let rows = codes.map(c => `
      <tr style="border-bottom: 1px solid var(--border-color);">
        <td style="padding: 8px; font-family: var(--font-mono); font-weight: 700; color: var(--accent-purple);">${c.code}</td>
        <td style="padding: 8px; font-weight: 600; color: var(--text-main);">${c.name}</td>
        <td style="padding: 8px; color: var(--text-muted); font-size: 11px;">${c.desc}</td>
      </tr>
    `).join('');

    closeCodeTable.innerHTML = `
      <table style="width: 100%; border-collapse: collapse; font-size: 12px; text-align: left;">
        <thead>
          <tr style="border-bottom: 2px solid var(--border-color); color: var(--text-muted);">
            <th style="padding: 8px;">STATUS CODE</th>
            <th style="padding: 8px;">NAME</th>
            <th style="padding: 8px;">RFC 6455 SPECIFICATION &amp; REASON</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    `;
  }

  // Render Security Audit List
  function renderSecurityAudit(auditRes) {
    let items = auditRes.rules.map(r => `
      <div class="audit-item ${r.pass ? 'pass' : 'fail'}">
        <div class="audit-info">
          <h4>${r.title}</h4>
          <p>${r.reason}</p>
        </div>
        <div class="audit-score-pill ${r.pass ? 'pill-pass' : 'pill-fail'}">
          ${r.score}/${r.weight} PTS
        </div>
      </div>
    `).join('');
    auditList.innerHTML = items;
  }

  // Render Synthesizer Output
  function renderSynthesizer(preset) {
    const plat = synthPlatform.value;
    let code = '';
    if (plat === 'nodews') code = WebSocketConfigSynthesizer.generateNodeWs(preset);
    else if (plat === 'pythonws') code = WebSocketConfigSynthesizer.generatePythonWebsockets(preset);
    else if (plat === 'gogorilla') code = WebSocketConfigSynthesizer.generateGoGorilla(preset);
    else if (plat === 'nginx') code = WebSocketConfigSynthesizer.generateNginxConfig(preset);
    synthOutput.textContent = code;
  }

  synthPlatform.addEventListener('change', () => {
    const currentPresetKey = profileSelect.value;
    const currentPreset = WebSocketSecurityAuditor.PRESETS[currentPresetKey] || WebSocketSecurityAuditor.PRESETS.fintech_trading_desk;
    renderSynthesizer(currentPreset);
  });

  btnCopySynth.addEventListener('click', () => {
    navigator.clipboard.writeText(synthOutput.textContent).then(() => {
      btnCopySynth.textContent = 'Copied!';
      setTimeout(() => btnCopySynth.textContent = 'Copy', 1500);
    });
  });

  btnForge.addEventListener('click', () => {
    renderAll();
  });

  // Download PCAP File
  btnDownloadPcap.addEventListener('click', () => {
    if (!currentPcapBytes) renderAll();
    const blob = new Blob([currentPcapBytes], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `websocket_capture_${Date.now()}.pcap`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  // Initial Run
  renderAll();
});
