import { Router } from 'express';
import mongoose from 'mongoose';

import KeyBundle from '../models/KeyBundle.js';
import Chat from '../models/Chat.js';
import base64Regex from '../util/base64Regex.js';

const REQUIRE_ALLOWLIST = process.env.KEYBUNDLE_REQUIRE_ALLOWLIST !== 'false';

function validateOneTimePreKeys(items) {
  if (!Array.isArray(items)) {
    return false;
  }

  for (const entry of items) {
    if (typeof entry !== 'object' || entry === null) {
      return false;
    }

    const { keyId, publicKey } = entry;

    if (!Number.isInteger(keyId) || keyId < 0) {
      return false;
    }

    if (typeof publicKey !== 'string' || publicKey.length === 0 || !base64Regex.test(publicKey)) {
      return false;
    }
  }

  return true;
}

function parseAllowedRequesters(raw) {
  if (raw === undefined) {
    return [];
  }
  if (!Array.isArray(raw)) {
    return null;
  }
  const results = [];
  const unique = new Set();
  for (const value of raw) {
    if (typeof value !== 'string' || !mongoose.Types.ObjectId.isValid(value)) {
      return null;
    }
    const objectId = new mongoose.Types.ObjectId(value);
    const key = objectId.toHexString();
    if (unique.has(key)) {
      continue;
    }
    unique.add(key);
    results.push(objectId);
  }
  return results;
}

export default function keybundleRouter(auth) {
  const router = Router();

  router.post('/', auth, async (req, res) => {
    const userId = req.user?.id;
    const { identityKey, signedPreKey, oneTimePreKeys, allowAnyRequester, allowedRequesters } =
      req.body || {};
    if (!userId || !identityKey || !signedPreKey || !Array.isArray(oneTimePreKeys)) {
      return res.status(400).json({ error: 'invalid_payload' });
    }

    if (!validateOneTimePreKeys(oneTimePreKeys)) {
      return res.status(400).json({ error: 'invalid_payload' });
    }

    const allowAny = Boolean(allowAnyRequester);
    const parsedAllowed = parseAllowedRequesters(allowedRequesters);
    if (parsedAllowed === null) {
      return res.status(400).json({ error: 'invalid_allowedRequesters' });
    }

    try {
      await KeyBundle.findOneAndUpdate(
        { userId },
        {
          userId,
          identityKey,
          signedPreKey,
          oneTimePreKeys: oneTimePreKeys.map((k) => ({
            keyId: k.keyId,
            publicKey: k.publicKey,
            used: false,
          })),
          allowAnyRequester: allowAny,
          allowedRequesters: parsedAllowed,
        },
        { upsert: true, new: true, setDefaultsOnInsert: true, runValidators: true, context: 'query' }
      );
      return res.sendStatus(204);
    } catch (err) {
      req.app?.locals?.logger?.error?.('keybundle.save_failed', err);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  router.get('/:userId', auth, async (req, res) => {
    const targetId = req.params.userId;

    if (!mongoose.Types.ObjectId.isValid(targetId)) {
      return res.status(400).json({ error: 'invalid_userId' });
    }

    const targetObjectId = new mongoose.Types.ObjectId(targetId);
    const requesterId = req.user?.id;
    if (!requesterId) {
      return res.status(401).json({ error: 'unauthenticated' });
    }

    const isSelfRequest = requesterId === targetId;
    const chatScope = req.query?.chatId;

    try {
      const bundle = await KeyBundle.findOne({ userId: targetObjectId }).lean();
      if (!bundle) {
        return res.status(404).json({ error: 'not_found' });
      }

      if (!isSelfRequest && REQUIRE_ALLOWLIST) {
        let allowed = Boolean(bundle.allowAnyRequester);
        if (!allowed && Array.isArray(bundle.allowedRequesters) && bundle.allowedRequesters.length > 0) {
          allowed = bundle.allowedRequesters.some((allowedId) => allowedId?.toString?.() === requesterId);
        }

        if (!allowed) {
          if (chatScope && mongoose.Types.ObjectId.isValid(chatScope)) {
            const chatId = chatScope;
            const [requesterMember, targetMember] = await Promise.all([
              Chat.isMember(chatId, requesterId),
              Chat.isMember(chatId, targetObjectId),
            ]);
            if (!requesterMember || !targetMember) {
              return res.status(403).json({ error: 'forbidden' });
            }
          } else {
            return res.status(403).json({ error: 'forbidden' });
          }
        }
      }

      const otp = bundle.oneTimePreKeys.find((k) => !k.used);
      if (!otp) {
        return res.status(410).json({ error: 'no_prekeys' });
      }

      const updateResult = await KeyBundle.updateOne(
        { userId: targetObjectId, 'oneTimePreKeys.keyId': otp.keyId, 'oneTimePreKeys.used': false },
        { $set: { 'oneTimePreKeys.$.used': true } }
      );

      if (updateResult.modifiedCount !== 1) {
        return res.status(409).json({ error: 'conflict' });
      }

      return res.json({
        identityKey: bundle.identityKey,
        signedPreKey: bundle.signedPreKey,
        oneTimePreKey: { keyId: otp.keyId, publicKey: otp.publicKey },
      });
    } catch (err) {
      req.app?.locals?.logger?.error?.('keybundle.fetch_failed', err);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  return router;
}
