'use strict';

function sanitize(value) {
  return String(value || '').trim();
}

function normalizeToolId(id) {
  return sanitize(id).replace(/-/g, '_').toLowerCase();
}

function getBaseCommand(command) {
  const cmd = sanitize(command);
  if (!cmd) return '';

  if (/\bwaybackurls\b/.test(cmd)) return 'waybackurls';

  const first = cmd.split(/\s+/)[0] || '';
  if (first === 'echo' && /\|\s*waybackurls\b/.test(cmd)) return 'waybackurls';
  return first.toLowerCase();
}

function resolveBuiltinParser(tool) {
  const id = normalizeToolId(tool && tool.id);
  const cmd = sanitize(tool && tool.command);

  if (id === 'curl_headers' || id === 'curl_dump_full') return 'curl_head';
  if (id === 'dig_any' || id === 'dig_short') return 'dig';
  if (id === 'ping') return 'ping';
  if (id === 'traceroute') return 'traceroute';

  const base = getBaseCommand(cmd);
  if (base === 'curl') return 'curl_head';
  if (base === 'dig') return 'dig';
  if (base === 'ping') return 'ping';
  if (base === 'traceroute') return 'traceroute';

  return null;
}

function resolveAdapterParser(tool) {
  const id = normalizeToolId(tool && tool.id);
  const base = getBaseCommand(tool && tool.command);

  const dedicatedById = new Set([
    'nmap_service',
    'nmap_full_tcp',
    'nmap_vuln',
    'nmap_udp_top',
    'whois',
    'subfinder',
    'amass_passive',
    'gau_passive',
    'waybackurls',
    'httpx_from_subfinder',
    'httpx_probe',
    'nuclei_from_httpx',
    'nuclei_url',
    'nuclei_exposure',
    'whatweb',
    'katana_standard',
    'katana_deep',
    'nikto',
    'gobuster_dir',
    'dirsearch',
    'feroxbuster',
    'ffuf_dir',
    'ffuf_param',
    'ffuf_sqli',
    'ffuf_xss',
    'ffuf_lfi',
    'arjun_get',
    'arjun_post',
    'sqlmap',
    'dalfox',
    'hydra_ssh_combo',
    'hydra_ftp_combo',
    'hydra_http_get_combo',
    'hydra_https_get_combo',
    'searchsploit',
    'wpscan',
  ]);

  if (dedicatedById.has(id)) return id;

  const byCommand = {
    nmap: 'nmap',
    whois: 'whois',
    subfinder: 'subdomains',
    amass: 'subdomains',
    gau: 'url_list',
    waybackurls: 'url_list',
    httpx: 'url_list',
    nuclei: 'nuclei',
    whatweb: 'whatweb',
    katana: 'katana',
    nikto: 'nikto',
    gobuster: 'gobuster',
    dirsearch: 'dirsearch',
    feroxbuster: 'feroxbuster',
    ffuf: 'ffuf',
    arjun: 'arjun',
    sqlmap: 'sqlmap',
    dalfox: 'dalfox',
    hydra: 'hydra',
    searchsploit: 'searchsploit',
    wpscan: 'wpscan',
  };

  return byCommand[base] || null;
}

function resolveJcPlan(tool) {
  const builtIn = resolveBuiltinParser(tool);
  if (builtIn) return { engine: 'jc', parser: builtIn };

  const adapter = resolveAdapterParser(tool);
  if (adapter) return { engine: 'adapter', parser: adapter };

  return null;
}

function resolveJcParser(tool) {
  const plan = resolveJcPlan(tool);
  return plan ? plan.parser : null;
}

module.exports = {
  resolveJcPlan,
  resolveJcParser,
  resolveBuiltinParser,
  resolveAdapterParser,
};
