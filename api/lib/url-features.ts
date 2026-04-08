// URL Feature Engineering for LGBM Phishing Detection
// Mirrors the Python feature extraction from the training notebook.

export interface UrlFeatures {
  url_length: number;
  domain_length: number;
  path_length: number;
  query_length: number;
  num_dots: number;
  num_hyphens: number;
  num_underscores: number;
  num_slashes: number;
  num_at_symbols: number;
  num_digits: number;
  num_special_chars: number;
  num_params: number;
  subdomain_count: number;
  has_ip: number;        // 0 or 1
  has_https: number;     // 0 or 1
  has_www: number;       // 0 or 1
  has_port: number;      // 0 or 1
  is_shortened: number;  // 0 or 1
  is_suspicious_tld: number; // 0 or 1
  domain_entropy: number;
  url_entropy: number;
  ratio_digits_url: number;
  ratio_digits_domain: number;
  ratio_vowels: number;
  longest_word_length: number;
  avg_word_length: number;
  has_suspicious_words: number; // 0 or 1
  num_external_redirects: number;
  brand_in_subdomain: number;  // 0 or 1
  brand_in_path: number;       // 0 or 1
  anchors_empty_pct: number;   // 0-1
}

// Known URL shortener domains
const SHORTENER_DOMAINS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
  'buff.ly', 'adf.ly', 'bitly.com', 'tiny.cc', 'rb.gy',
  'shorturl.at', 'cutt.ly', 'is.gd', 'bl.ink', 'snip.ly'
]);

// Suspicious TLDs commonly used in phishing
const SUSPICIOUS_TLDS = new Set([
  '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.online',
  '.site', '.info', '.club', '.top', '.work', '.click',
  '.link', '.download', '.zip', '.review', '.country'
]);

// Major brands that are commonly impersonated
const BRANDS = [
  'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix',
  'facebook', 'instagram', 'twitter', 'linkedin', 'dropbox',
  'wellsfargo', 'chase', 'bankofamerica', 'citibank', 'ebay',
  'whatsapp', 'telegram', 'yahoo', 'outlook', 'office365'
];

// Suspicious words in phishing URLs
const SUSPICIOUS_WORDS = [
  'secure', 'login', 'signin', 'account', 'update', 'verify',
  'confirm', 'banking', 'password', 'credential', 'paypal',
  'suspend', 'limited', 'unusual', 'alert', 'restore',
  'urgent', 'free', 'winner', 'prize', 'claim'
];

// Shannon entropy calculation
function shannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Check if string looks like an IP address
function isIPAddress(str: string): boolean {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^[\da-fA-F:]{4,}$/;
  return ipv4.test(str) || ipv6.test(str);
}

// Count vowels in a string
function countVowels(str: string): number {
  return (str.match(/[aeiouAEIOU]/g) || []).length;
}

// Split URL into "words" (split on -, _, ., /, digits)
function extractWords(str: string): string[] {
  return str.split(/[-_.\/\d=?&%@#!+]+/).filter(w => w.length > 1);
}

// Main feature extraction function
export function extractUrlFeatures(rawUrl: string): UrlFeatures {
  let url: URL;
  let fullUrl = rawUrl;
  
  // Try to parse; add https if missing scheme
  try {
    url = new URL(fullUrl);
  } catch {
    try {
      fullUrl = 'https://' + rawUrl;
      url = new URL(fullUrl);
    } catch {
      // Fallback for truly malformed URLs
      const features: Partial<UrlFeatures> = {};
      for (const key of Object.keys({} as UrlFeatures)) {
        (features as Record<string,number>)[key] = 0;
      }
      return features as UrlFeatures;
    }
  }

  const fullStr = rawUrl;
  const hostname = url.hostname.toLowerCase();
  const path = url.pathname;
  const query = url.search;
  
  // Get TLD
  const hostParts = hostname.split('.');
  const tld = hostParts.length > 1 ? '.' + hostParts[hostParts.length - 1] : '';
  
  // Domain without TLD
  const domain = hostParts.slice(-2).join('.');
  const subdomains = hostParts.slice(0, -2);
  
  // Extract words for length stats
  const words = extractWords(hostname + path);
  const longestWord = words.reduce((max, w) => w.length > max ? w.length : max, 0);
  const avgWord = words.length > 0 ? words.reduce((s, w) => s + w.length, 0) / words.length : 0;
  
  // Digit counts
  const digitsInUrl = (fullStr.match(/\d/g) || []).length;
  const digitsInDomain = (hostname.match(/\d/g) || []).length;
  
  // Brand detection in subdomain
  const subdomainStr = subdomains.join('.').toLowerCase();
  const pathLower = path.toLowerCase();
  const brandInSub = BRANDS.some(b => subdomainStr.includes(b) && !domain.includes(b)) ? 1 : 0;
  const brandInPath = BRANDS.some(b => pathLower.includes(b)) ? 1 : 0;
  
  // Suspicious words check
  const fullLower = fullStr.toLowerCase();
  const hasSuspWord = SUSPICIOUS_WORDS.some(w => fullLower.includes(w)) ? 1 : 0;

  // Count redirects heuristic (presence of 'redirect', 'url=', 'next=', etc.)
  const redirectCount = (query.match(/(?:redirect|url=|next=|goto=|return=)/gi) || []).length;

  return {
    url_length: fullStr.length,
    domain_length: hostname.length,
    path_length: path.length,
    query_length: query.length,
    num_dots: (fullStr.match(/\./g) || []).length,
    num_hyphens: (fullStr.match(/-/g) || []).length,
    num_underscores: (fullStr.match(/_/g) || []).length,
    num_slashes: (fullStr.match(/\//g) || []).length,
    num_at_symbols: (fullStr.match(/@/g) || []).length,
    num_digits: digitsInUrl,
    num_special_chars: (fullStr.match(/[^a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]/g) || []).length,
    num_params: query ? query.split('&').length : 0,
    subdomain_count: subdomains.filter(s => s.length > 0).length,
    has_ip: isIPAddress(hostname) ? 1 : 0,
    has_https: url.protocol === 'https:' ? 1 : 0,
    has_www: hostname.startsWith('www.') ? 1 : 0,
    has_port: url.port ? 1 : 0,
    is_shortened: SHORTENER_DOMAINS.has(hostname) ? 1 : 0,
    is_suspicious_tld: SUSPICIOUS_TLDS.has(tld) ? 1 : 0,
    domain_entropy: shannonEntropy(hostname),
    url_entropy: shannonEntropy(fullStr),
    ratio_digits_url: fullStr.length > 0 ? digitsInUrl / fullStr.length : 0,
    ratio_digits_domain: hostname.length > 0 ? digitsInDomain / hostname.length : 0,
    ratio_vowels: hostname.length > 0 ? countVowels(hostname) / hostname.length : 0,
    longest_word_length: longestWord,
    avg_word_length: avgWord,
    has_suspicious_words: hasSuspWord,
    num_external_redirects: redirectCount,
    brand_in_subdomain: brandInSub,
    brand_in_path: brandInPath,
    anchors_empty_pct: 0, // Can't detect without DOM access
  };
}
