'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const PROFILE_FILTERS = {
  dir_enum: {
    label: 'DIR ENUM',
    patterns: ['web_discovery_', 'web_directories_', 'web_dirs_', 'web_sensitive_files_']
  },
  subdomain: {
    label: 'SUBDOMAIN',
    patterns: ['subdomains', 'network_subdomains_dns']
  },
  param_fuzz: {
    label: 'PARAM FUZZ',
    patterns: ['fuzzing_parameters_']
  },
  sqli_payloads: {
    label: 'SQLI PAYLOADS',
    patterns: ['payloads_sql_']
  },
  xss_payloads: {
    label: 'XSS PAYLOADS',
    patterns: ['payloads_xss_']
  },
  lfi_payloads: {
    label: 'LFI PAYLOADS',
    patterns: ['payloads_lfi_', 'payloads_directory_traversal']
  },
  ssti_payloads: {
    label: 'SSTI PAYLOADS',
    patterns: ['payloads_ssti_']
  },
  xxe_payloads: {
    label: 'XXE PAYLOADS',
    patterns: ['payloads_xml_injection_xxe']
  },
  dns_resolvers: {
    label: 'DNS RESOLVERS',
    patterns: ['network_dns_resolvers']
  },
  service_users: {
    label: 'SERVICE USERS',
    patterns: ['service_', 'os_linux_users']
  },
  service_passwords: {
    label: 'SERVICE PASSWORDS',
    patterns: ['service_', 'passwords_']
  },
  credential_pairs: {
    label: 'CREDENTIAL PAIRS',
    patterns: ['_defaults', 'default_userpass', 'mysql_defaults', 'iot_', 'db_']
  },
  cms_wp: {
    label: 'CMS WORDPRESS',
    patterns: ['cms_wordpress_']
  },
  cms_joomla: {
    label: 'CMS JOOMLA',
    patterns: ['cms_joomla_']
  },
  tech_specific: {
    label: 'TECH SPECIFIC',
    patterns: ['tech_', 'web_vulns_', 'web_coldfusion_', 'web_apache_']
  }
};

function defaultRoots() {
  const home = os.homedir();
  return [path.join(home, 'Wordlists'), path.join(home, 'Wordlist')];
}

function listTextFiles(dir, out) {
  if (!fs.existsSync(dir)) return;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      listTextFiles(full, out);
    } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.txt')) {
      out.push(full);
    }
  }
}

function matchesPatterns(name, patterns) {
  const lowered = name.toLowerCase();
  return patterns.some((pattern) => lowered.includes(pattern.toLowerCase()));
}

function buildWordlistCatalog(options) {
  const roots = Array.isArray(options && options.roots) ? options.roots : defaultRoots();
  const profile = String((options && options.profile) || '').trim();
  const filter = PROFILE_FILTERS[profile];
  const files = [];

  for (const root of roots) {
    listTextFiles(root, files);
  }

  const unique = [...new Set(files)].sort((a, b) => a.localeCompare(b));
  const selected = filter
    ? unique.filter((filePath) => matchesPatterns(path.basename(filePath), filter.patterns))
    : unique;

  if (!filter) {
    return {
      profile: 'all',
      sections: [{
        id: 'ALL WORDLISTS',
        files: selected.map((filePath) => ({ name: path.basename(filePath), path: filePath }))
      }]
    };
  }

  return {
    profile,
    sections: [{
      id: filter.label,
      files: selected.map((filePath) => ({ name: path.basename(filePath), path: filePath }))
    }]
  };
}

module.exports = {
  PROFILE_FILTERS,
  buildWordlistCatalog
};
