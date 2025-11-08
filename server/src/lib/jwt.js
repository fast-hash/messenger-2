import jwt from 'jsonwebtoken';

import config from '../config.js';

const SUPPORTED_ALGORITHMS = new Set(['HS256', 'RS256']);
const DEFAULT_CLOCK_TOLERANCE_SEC = 120;

function getConfigValue(path) {
  if (typeof config?.has === 'function' && config.has(path)) {
    return config.get(path);
  }
  return undefined;
}

function normalizeMultiline(value) {
  return typeof value === 'string' ? value.replace(/\\n/g, '\n') : value;
}

export function getJwtAlgorithm() {
  const fromEnv = process.env.JWT_ALGORITHM;
  const fromConfig = getConfigValue('jwt.algorithm');
  const resolved = (fromEnv ?? fromConfig ?? 'HS256').toUpperCase();
  if (!SUPPORTED_ALGORITHMS.has(resolved)) {
    throw new Error(`Unsupported JWT algorithm: ${resolved}`);
  }
  return resolved;
}

export function getJwtKeyId() {
  return process.env.JWT_KID ?? getConfigValue('jwt.keyId');
}

export function getJwtSecret() {
  const secret = process.env.JWT_SECRET ?? getConfigValue('jwt.secret');
  if (!secret) {
    throw new Error('JWT_SECRET not configured');
  }
  return secret;
}

export function getJwtPublicKey() {
  const key = process.env.JWT_PUBLIC_KEY ?? getConfigValue('jwt.publicKey');
  if (!key) {
    throw new Error('JWT_PUBLIC_KEY not configured');
  }
  return normalizeMultiline(key);
}

export function getJwtPrivateKey() {
  const key = process.env.JWT_PRIVATE_KEY ?? getConfigValue('jwt.privateKey');
  if (!key) {
    throw new Error('JWT_PRIVATE_KEY not configured');
  }
  return normalizeMultiline(key);
}

export function getJwtExpiresIn() {
  return process.env.JWT_EXPIRES_IN ?? getConfigValue('jwt.expiresIn');
}

export function getClockToleranceSec() {
  const fromEnv = process.env.JWT_CLOCK_TOLERANCE_SEC;
  const fromConfig = getConfigValue('jwt.clockToleranceSec');
  const parsed = parseInt(fromEnv ?? fromConfig ?? DEFAULT_CLOCK_TOLERANCE_SEC, 10);
  if (Number.isNaN(parsed) || parsed < 0) {
    return DEFAULT_CLOCK_TOLERANCE_SEC;
  }
  return parsed;
}

export function signAccessToken(payload, options = {}) {
  const algorithm = getJwtAlgorithm();
  const signingKey = algorithm === 'HS256' ? getJwtSecret() : getJwtPrivateKey();
  const keyid = getJwtKeyId();
  const tokenOptions = { ...options, algorithm };
  if (!('expiresIn' in tokenOptions)) {
    const configuredExpires = getJwtExpiresIn();
    if (configuredExpires) {
      tokenOptions.expiresIn = configuredExpires;
    }
  }
  if (keyid && !('keyid' in tokenOptions)) {
    tokenOptions.keyid = keyid;
  }
  return jwt.sign(payload, signingKey, tokenOptions);
}

export function verifyAccess(token, verifyOptions = {}) {
  if (!token) {
    throw new Error('NO_TOKEN');
  }
  const algorithm = getJwtAlgorithm();
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || typeof decoded.header !== 'object') {
    throw new Error('INVALID_TOKEN');
  }
  const { alg, kid } = decoded.header;
  if (alg !== algorithm) {
    throw new Error('UNEXPECTED_ALG');
  }
  const expectedKid = getJwtKeyId();
  if (expectedKid) {
    if (kid !== expectedKid) {
      throw new Error('UNEXPECTED_KID');
    }
  } else if (kid) {
    throw new Error('UNEXPECTED_KID');
  }

  const verificationKey = algorithm === 'HS256' ? getJwtSecret() : getJwtPublicKey();
  const options = { ...verifyOptions };
  options.algorithms = [algorithm];
  if (!('clockTolerance' in options)) {
    options.clockTolerance = getClockToleranceSec();
  }
  return jwt.verify(token, verificationKey, options);
}
