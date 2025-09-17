import express from 'express';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';

export function mountTestBootstrap(app) {
  if (process.env.NODE_ENV !== 'test') return;

  const router = express.Router();

  router.post('/__test__/bootstrap', async (_req, res) => {
    const Users = mongoose.connection.collection('users');
    const Chats = mongoose.connection.collection('chats');

    const userA = new mongoose.Types.ObjectId();
    const userB = new mongoose.Types.ObjectId();
    const chatId = new mongoose.Types.ObjectId();

    await Users.insertMany([
      { _id: userA, username: 'userA', createdAt: new Date() },
      { _id: userB, username: 'userB', createdAt: new Date() },
    ]);

    await Chats.insertOne({
      _id: chatId,
      participants: [userA.toString(), userB.toString()],
      createdAt: new Date(),
    });

    const sign = (sub) =>
      jwt.sign(
        { sub, aud: process.env.JWT_AUDIENCE || 'aud', iss: process.env.JWT_ISSUER || 'iss' },
        process.env.JWT_SECRET || 'secret',
        { algorithm: 'HS256' }
      );

    return res.json({
      chatId: chatId.toString(),
      tokenA: sign(userA.toString()),
      tokenB: sign(userB.toString()),
    });
  });

  app.use(router);
}
