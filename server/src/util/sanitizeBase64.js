import base64Regex from './base64Regex.js';

const DEFAULT_MIN_LENGTH = 16;
const DEFAULT_MAX_LENGTH = 512;

export default function sanitizeBase64(
  value,
  { minLength = DEFAULT_MIN_LENGTH, maxLength = DEFAULT_MAX_LENGTH, maxBytes } = {}
) {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  if (trimmed !== value) {
    return null;
  }
  if (trimmed.length < minLength || trimmed.length > maxLength) {
    return null;
  }
  if (trimmed.length % 4 !== 0) {
    return null;
  }
  if (!base64Regex.test(trimmed)) {
    return null;
  }

  try {
    const decoded = Buffer.from(trimmed, 'base64');
    if (decoded.length === 0) {
      return null;
    }
    if (typeof maxBytes === 'number' && maxBytes > 0 && decoded.length > maxBytes) {
      return null;
    }
    if (decoded.toString('base64') !== trimmed) {
      return null;
    }
    return trimmed;
  } catch {
    return null;
  }
}
