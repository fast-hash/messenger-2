import { Router } from 'express';

import KeyBundle from '../models/KeyBundle.js';
import base64Regex from '../util/base64Regex.js';

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

export default function keybundleRouter(auth) {
  const router = Router();

  router.post('/', auth, async (req, res) => {
    const userId = req.user?.id;
    const { identityKey, signedPreKey, oneTimePreKeys } = req.body || {};
    if (!userId || !identityKey || !signedPreKey || !Array.isArray(oneTimePreKeys)) {
      return res.status(400).json({ error: 'invalid_payload' });
    }

    if (!validateOneTimePreKeys(oneTimePreKeys)) {
      return res.status(400).json({ error: 'invalid_payload' });
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

    try {
      const bundle = await KeyBundle.findOne({ userId: targetId }).lean();
      if (!bundle) {
        return res.status(404).json({ error: 'not_found' });
      }

      const otp = bundle.oneTimePreKeys.find((k) => !k.used);
      if (!otp) {
        return res.status(410).json({ error: 'no_prekeys' });
      }

      await KeyBundle.updateOne(
        { userId: targetId, 'oneTimePreKeys.keyId': otp.keyId },
        { $set: { 'oneTimePreKeys.$.used': true } }
      );

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
