/**
 * Virux Cypher API Configuration
 * 
 * Controls backend target and mock/live switching.
 */

const STORAGE_KEY_USE_MOCK = 'virux_use_mock';
const STORAGE_KEY_BASE_URL = 'virux_base_url';

export const API_CONFIG = {
  defaultBaseUrl: 'http://127.0.0.1:8000',
  defaultUseMock: true,
};

export function getApiBaseUrl(): string {
  return localStorage.getItem(STORAGE_KEY_BASE_URL) || API_CONFIG.defaultBaseUrl;
}

export function setApiBaseUrl(url: string): void {
  localStorage.setItem(STORAGE_KEY_BASE_URL, url.trim());
}

export function isMockEnabled(): boolean {
  const stored = localStorage.getItem(STORAGE_KEY_USE_MOCK);
  if (stored === null) return API_CONFIG.defaultUseMock;
  return stored === 'true';
}

export function setMockEnabled(enabled: boolean): void {
  localStorage.setItem(STORAGE_KEY_USE_MOCK, String(enabled));
}
