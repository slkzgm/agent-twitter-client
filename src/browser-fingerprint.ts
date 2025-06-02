/**
 * Advanced browser fingerprinting and anti-detection utilities for bypassing Cloudflare and other bot detection systems.
 * Implements sophisticated techniques including request timing, header ordering, and behavioral mimicry.
 */
import { Headers } from "headers-polyfill";
import crypto from "crypto";

export interface BrowserFingerprint {
  userAgent: string;
  acceptLanguage: string;
  acceptEncoding: string;
  accept: string;
  secFetchDest: string;
  secFetchMode: string;
  secFetchSite: string;
  secChUa: string;
  secChUaMobile: string;
  secChUaPlatform: string;
  dnt: string;
  upgradeInsecureRequests: string;
  cacheControl: string;
  pragma: string;
  connection: string;
  // New anti-detection fields
  viewportWidth: number;
  viewportHeight: number;
  timezone: string;
  cookieEnabled: boolean;
  doNotTrack: string;
  sessionId: string;
  requestDelay: number; // Milliseconds to delay before request
}

export interface AntiDetectionConfig {
  enableRequestDelay: boolean;
  enableHeaderRandomization: boolean;
  enableJitter: boolean;
  maxDelayMs: number;
  minDelayMs: number;
}

/**
 * Modern Chrome User-Agents for different platforms
 */
const CHROME_USER_AGENTS = [
  // Windows Chrome
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  
  // macOS Chrome
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  
  // Linux Chrome
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
];

/**
 * Firefox User-Agents for different platforms
 */
const FIREFOX_USER_AGENTS = [
  // Windows Firefox
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
  "Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
  
  // macOS Firefox
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
  
  // Linux Firefox
  "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
];

/**
 * Safari User-Agents
 */
const SAFARI_USER_AGENTS = [
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
];

/**
 * Mobile User-Agents (for occasional mobile requests)
 */
const MOBILE_USER_AGENTS = [
  // iPhone
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
  
  // Android Chrome
  "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
];

const ALL_USER_AGENTS = [
  ...CHROME_USER_AGENTS,
  ...FIREFOX_USER_AGENTS,
  ...SAFARI_USER_AGENTS,
  // Include mobile occasionally (10% chance)
  ...(Math.random() < 0.1 ? MOBILE_USER_AGENTS : []),
];

/**
 * Language preferences with realistic weights
 */
const ACCEPT_LANGUAGES = [
  "en-US,en;q=0.9",
  "en-US,en;q=0.9,es;q=0.8",
  "en-US,en;q=0.9,fr;q=0.8",
  "en-GB,en;q=0.9",
  "en-US,en;q=0.9,de;q=0.8",
  "en,en-US;q=0.9",
  "en-US,en;q=0.8,es;q=0.7",
];

/**
 * Get Sec-CH-UA header based on User-Agent
 */
function getSecChUa(userAgent: string): string {
  if (userAgent.includes('Chrome/120')) {
    return '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"';
  } else if (userAgent.includes('Chrome/119')) {
    return '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"';
  } else if (userAgent.includes('Chrome/118')) {
    return '"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"';
  } else if (userAgent.includes('Firefox')) {
    return ''; // Firefox doesn't send sec-ch-ua
  } else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) {
    return ''; // Safari doesn't send sec-ch-ua
  }
  return '"Not_A Brand";v="8", "Chromium";v="120"';
}

/**
 * Get Sec-CH-UA-Platform based on User-Agent
 */
function getSecChUaPlatform(userAgent: string): string {
  if (userAgent.includes('Windows NT 10.0')) return '"Windows"';
  if (userAgent.includes('Windows NT 11.0')) return '"Windows"';
  if (userAgent.includes('Macintosh')) return '"macOS"';
  if (userAgent.includes('Linux')) return '"Linux"';
  if (userAgent.includes('iPhone')) return '"iOS"';
  if (userAgent.includes('Android')) return '"Android"';
  return '"Windows"';
}

/**
 * Determine if User-Agent is mobile
 */
function isMobile(userAgent: string): boolean {
  return userAgent.includes('Mobile') || userAgent.includes('iPhone') || userAgent.includes('Android');
}

/**
 * Generate a random but realistic browser fingerprint with advanced anti-detection features
 */
export function generateBrowserFingerprint(): BrowserFingerprint {
  const userAgent = ALL_USER_AGENTS[Math.floor(Math.random() * ALL_USER_AGENTS.length)];
  const acceptLanguage = ACCEPT_LANGUAGES[Math.floor(Math.random() * ACCEPT_LANGUAGES.length)];
  const mobile = isMobile(userAgent);
  
  // Generate realistic viewport dimensions
  const commonResolutions = [
    [1920, 1080], [1366, 768], [1440, 900], [1536, 864], [1280, 720],
    [1600, 900], [1024, 768], [1280, 800], [1680, 1050], [2560, 1440]
  ];
  const [viewportWidth, viewportHeight] = commonResolutions[Math.floor(Math.random() * commonResolutions.length)];
  
  // Generate realistic timezone
  const timezones = [
    "America/New_York", "America/Los_Angeles", "America/Chicago", "America/Denver",
    "Europe/London", "Europe/Paris", "Europe/Berlin", "Asia/Tokyo", "Australia/Sydney"
  ];
  const timezone = timezones[Math.floor(Math.random() * timezones.length)];
  
  // Generate session ID
  const sessionId = crypto.randomBytes(16).toString('hex');
  
  // Calculate request delay (100-2000ms with realistic distribution)
  const requestDelay = Math.floor(Math.random() * 1900) + 100;
  
  return {
    userAgent,
    acceptLanguage,
    acceptEncoding: "gzip, deflate, br",
    accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    secFetchDest: "document",
    secFetchMode: "navigate",
    secFetchSite: "none",
    secChUa: getSecChUa(userAgent),
    secChUaMobile: mobile ? "?1" : "?0",
    secChUaPlatform: getSecChUaPlatform(userAgent),
    dnt: Math.random() < 0.3 ? "1" : "0", // 30% chance of DNT
    upgradeInsecureRequests: "1",
    cacheControl: Math.random() < 0.1 ? "no-cache" : "max-age=0", // Occasionally no-cache
    pragma: Math.random() < 0.1 ? "no-cache" : "",
    connection: "keep-alive",
    // New anti-detection fields
    viewportWidth,
    viewportHeight,
    timezone,
    cookieEnabled: Math.random() < 0.95, // 95% have cookies enabled
    doNotTrack: Math.random() < 0.2 ? "1" : "0", // 20% enable DNT
    sessionId,
    requestDelay,
  };
}

/**
 * Apply browser fingerprint headers to a Headers object
 */
export function applyBrowserHeaders(headers: Headers, fingerprint: BrowserFingerprint, url?: string): void {
  headers.set("User-Agent", fingerprint.userAgent);
  headers.set("Accept-Language", fingerprint.acceptLanguage);
  headers.set("Accept-Encoding", fingerprint.acceptEncoding);
  headers.set("Accept", fingerprint.accept);
  headers.set("DNT", fingerprint.dnt);
  headers.set("Upgrade-Insecure-Requests", fingerprint.upgradeInsecureRequests);
  headers.set("Connection", fingerprint.connection);
  
  // Only add Sec-Fetch headers for HTTPS requests
  if (!url || url.startsWith('https://')) {
    headers.set("Sec-Fetch-Dest", fingerprint.secFetchDest);
    headers.set("Sec-Fetch-Mode", fingerprint.secFetchMode);
    headers.set("Sec-Fetch-Site", fingerprint.secFetchSite);
  }
  
  // Only add Sec-CH-UA headers for Chromium-based browsers
  if (fingerprint.secChUa) {
    headers.set("Sec-CH-UA", fingerprint.secChUa);
    headers.set("Sec-CH-UA-Mobile", fingerprint.secChUaMobile);
    headers.set("Sec-CH-UA-Platform", fingerprint.secChUaPlatform);
  }
  
  // Add cache control headers
  if (fingerprint.cacheControl) {
    headers.set("Cache-Control", fingerprint.cacheControl);
  }
  if (fingerprint.pragma) {
    headers.set("Pragma", fingerprint.pragma);
  }
}

/**
 * Singleton class to manage browser fingerprint rotation with advanced anti-detection
 */
class BrowserFingerprintManager {
  private currentFingerprint: BrowserFingerprint | null = null;
  private lastRotation: number = 0;
  private readonly rotationInterval: number = 300000; // 5 minutes
  private requestCount: number = 0;
  private lastRequestTime: number = 0;

  /**
   * Get current fingerprint, rotating if necessary
   */
  getCurrentFingerprint(): BrowserFingerprint {
    const now = Date.now();
    if (!this.currentFingerprint || (now - this.lastRotation) > this.rotationInterval) {
      this.currentFingerprint = generateBrowserFingerprint();
      this.lastRotation = now;
      this.requestCount = 0; // Reset request count on rotation
    }
    return this.currentFingerprint;
  }

  /**
   * Force fingerprint rotation
   */
  rotateFingerprint(): BrowserFingerprint {
    this.currentFingerprint = generateBrowserFingerprint();
    this.lastRotation = Date.now();
    this.requestCount = 0;
    return this.currentFingerprint;
  }

  /**
   * Get request delay with jitter to avoid detection
   */
  getRequestDelay(): number {
    this.requestCount++;
    const fingerprint = this.getCurrentFingerprint();
    
    // Add jitter based on request count to avoid patterns
    const baseDelay = fingerprint.requestDelay;
    const jitter = Math.random() * 500; // 0-500ms jitter
    const countMultiplier = Math.min(this.requestCount * 50, 1000); // Increase delay with request count
    
    return baseDelay + jitter + countMultiplier;
  }

  /**
   * Check if we should delay before making a request
   */
  async waitForRequest(): Promise<void> {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    const requiredDelay = this.getRequestDelay();
    
    if (timeSinceLastRequest < requiredDelay) {
      const waitTime = requiredDelay - timeSinceLastRequest;
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
    
    this.lastRequestTime = Date.now();
  }
}

export const browserFingerprintManager = new BrowserFingerprintManager();

/**
 * Apply advanced anti-detection headers in realistic order
 */
export function applyAdvancedBrowserHeaders(headers: Headers, fingerprint: BrowserFingerprint, url?: string): void {
  // Headers should be applied in a specific order that matches real browsers
  const orderedHeaders = [
    ["Host", new URL(url || "https://api.twitter.com").host],
    ["User-Agent", fingerprint.userAgent],
    ["Accept", fingerprint.accept],
    ["Accept-Language", fingerprint.acceptLanguage],
    ["Accept-Encoding", fingerprint.acceptEncoding],
    ["DNT", fingerprint.dnt],
    ["Connection", fingerprint.connection],
    ["Upgrade-Insecure-Requests", fingerprint.upgradeInsecureRequests],
  ];

  // Add Sec-Fetch headers for HTTPS requests (Chromium browsers)
  if (!url || url.startsWith('https://')) {
    orderedHeaders.push(
      ["Sec-Fetch-Dest", fingerprint.secFetchDest],
      ["Sec-Fetch-Mode", fingerprint.secFetchMode],
      ["Sec-Fetch-Site", fingerprint.secFetchSite]
    );
  }

  // Add Sec-CH-UA headers for Chromium-based browsers
  if (fingerprint.secChUa) {
    orderedHeaders.push(
      ["Sec-CH-UA", fingerprint.secChUa],
      ["Sec-CH-UA-Mobile", fingerprint.secChUaMobile],
      ["Sec-CH-UA-Platform", fingerprint.secChUaPlatform]
    );
  }

  // Add cache control headers
  if (fingerprint.cacheControl) {
    orderedHeaders.push(["Cache-Control", fingerprint.cacheControl]);
  }
  if (fingerprint.pragma) {
    orderedHeaders.push(["Pragma", fingerprint.pragma]);
  }

  // Apply headers in order
  for (const [key, value] of orderedHeaders) {
    if (value) {
      headers.set(key, value);
    }
  }

  // Add some randomization to header casing (some servers check this)
  if (Math.random() < 0.1) {
    const userAgent = headers.get("User-Agent");
    if (userAgent) {
      headers.delete("User-Agent");
      headers.set("user-agent", userAgent);
    }
  }
}

/**
 * Get headers optimized for Twitter API requests with advanced anti-detection
 */
export async function getTwitterApiHeaders(baseHeaders?: Record<string, string>): Promise<Headers> {
  // Wait for appropriate delay before making request
  await browserFingerprintManager.waitForRequest();
  
  const fingerprint = browserFingerprintManager.getCurrentFingerprint();
  const headers = new Headers(baseHeaders);
  
  // Apply advanced browser fingerprint with realistic header ordering
  applyAdvancedBrowserHeaders(headers, fingerprint, "https://api.twitter.com");
  
  // Twitter-specific headers with realistic values
  headers.set("Referer", "https://twitter.com/");
  headers.set("Origin", "https://twitter.com");
  headers.set("X-Twitter-Active-User", "yes");
  headers.set("X-Twitter-Client-Language", "en");
  
  // Adjust accept header for API requests
  headers.set("Accept", "application/json, text/plain, */*");
  
  // Add realistic timing headers
  headers.set("X-Requested-With", "XMLHttpRequest");
  
  // Add session-based headers
  headers.set("X-Client-Transaction-Id", fingerprint.sessionId);
  
  // Occasionally add additional anti-bot headers
  if (Math.random() < 0.3) {
    headers.set("Purpose", "prefetch");
  }
  
  if (Math.random() < 0.2) {
    headers.set("X-Forwarded-For", generateRandomIP());
  }
  
  return headers;
}

/**
 * Get headers for Twitter web requests (non-API)
 */
export async function getTwitterWebHeaders(baseHeaders?: Record<string, string>): Promise<Headers> {
  await browserFingerprintManager.waitForRequest();
  
  const fingerprint = browserFingerprintManager.getCurrentFingerprint();
  const headers = new Headers(baseHeaders);
  
  // Apply browser fingerprint
  applyAdvancedBrowserHeaders(headers, fingerprint, "https://twitter.com");
  
  // Web-specific headers
  headers.set("Referer", "https://twitter.com/home");
  headers.set("Origin", "https://twitter.com");
  
  return headers;
}

/**
 * Generate a random IP address for X-Forwarded-For header
 */
function generateRandomIP(): string {
  const ranges = [
    // Common residential IP ranges
    [10, 0, 0, 0], [172, 16, 0, 0], [192, 168, 0, 0],
    // Common ISP ranges (safe examples)
    [24, 0, 0, 0], [76, 0, 0, 0], [98, 0, 0, 0]
  ];
  
  const range = ranges[Math.floor(Math.random() * ranges.length)];
  return `${range[0]}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
}

/**
 * Force rotation of browser fingerprint (useful after detection)
 */
export function rotateBrowserFingerprint(): void {
  browserFingerprintManager.rotateFingerprint();
}

/**
 * Get current fingerprint info (for debugging)
 */
export function getCurrentFingerprintInfo(): BrowserFingerprint {
  return browserFingerprintManager.getCurrentFingerprint();
}
