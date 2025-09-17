import React, { useContext, useEffect, useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import { io } from 'socket.io-client';

import { getBundle, sendMessage as sendCiphertext, history as fetchHistory } from '../api/api.js';
import { ChatWindow } from '../components/ChatWindow';
import MessageInput from '../components/MessageInput';
import { AuthContext } from '../contexts/AuthContext';
import { initSession, decryptMessage } from '../crypto/signal.js';

export default function ChatPage() {
  const { token, userId, logout } = useContext(AuthContext);
  const { chatId: routeChatId } = useParams();

  const chatId = useMemo(() => routeChatId, [routeChatId]);
  const [messages, setMessages] = useState([]);
  const [historyCursor, setHistoryCursor] = useState(null);
  const [hasMoreHistory, setHasMoreHistory] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [sessionReady, setSessionReady] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setSessionReady(false);

    setMessages([]);
    setHistoryCursor(null);
    setHasMoreHistory(false);
    setLoadingHistory(false);

    (async () => {
      try {
        const bundle = await getBundle(chatId);
        if (cancelled) return;
        await initSession(chatId, bundle);
        if (!cancelled) {
          setSessionReady(true);
        }
      } catch (err) {
        console.error('Failed to initialise Signal session:', err);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [chatId]);

  useEffect(() => {
    if (!sessionReady) return undefined;
    let cancelled = false;

    setLoadingHistory(true);
    (async () => {
      try {
        const {
          messages: historyMessages,
          nextCursor,
          hasMore,
        } = await fetchHistory(chatId, {
          limit: 50,
        });
        if (cancelled) return;
        setMessages(historyMessages);
        setHistoryCursor(nextCursor);
        setHasMoreHistory(hasMore);
      } catch (err) {
        console.error('Failed to load chat history:', err);
      } finally {
        if (!cancelled) {
          setLoadingHistory(false);
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [chatId, sessionReady]);

  useEffect(() => {
    if (!token || !sessionReady) return undefined;

    const socket = io(import.meta.env.VITE_API_URL || 'http://localhost:3000', {
      auth: { token },
    });

    socket.emit('join', chatId);

    const handler = async (message) => {
      try {
        const text = await decryptMessage(message.encryptedPayload);
        setMessages((prev) => {
          const key = message.id || message._id || message.createdAt;
          if (
            prev.some((existing) => (existing.id || existing._id || existing.createdAt) === key)
          ) {
            return prev;
          }
          return [...prev, { ...message, text }];
        });
      } catch (err) {
        console.error('Failed to decrypt incoming message:', err);
      }
    };

    socket.on('message', handler);

    return () => {
      socket.off('message', handler);
      socket.disconnect();
    };
  }, [chatId, sessionReady, token]);

  const handleSend = async (plainText) => {
    if (!sessionReady || !plainText) return;
    try {
      const { encryptedPayload } = await sendCiphertext(chatId, plainText);
      setMessages((prev) => {
        const createdAt = new Date().toISOString();
        return [
          ...prev,
          {
            chatId,
            senderId: userId,
            encryptedPayload,
            text: plainText,
            createdAt,
          },
        ];
      });
    } catch (err) {
      console.error('Failed to send message:', err);
    }
  };

  const handleLoadMore = async () => {
    if (!hasMoreHistory || loadingHistory || !historyCursor) {
      return;
    }
    setLoadingHistory(true);
    try {
      const {
        messages: olderMessages,
        nextCursor,
        hasMore,
      } = await fetchHistory(chatId, {
        limit: 50,
        cursor: historyCursor,
      });
      setMessages((prev) => {
        const existingKeys = new Set(prev.map((msg) => msg.id || msg._id || msg.createdAt));
        const deduped = [];
        for (const message of olderMessages) {
          const key = message.id || message._id || message.createdAt;
          if (existingKeys.has(key)) {
            continue;
          }
          existingKeys.add(key);
          deduped.push(message);
        }
        return deduped.length ? [...deduped, ...prev] : prev;
      });
      setHistoryCursor(nextCursor);
      setHasMoreHistory(hasMore);
    } catch (err) {
      console.error('Failed to load earlier messages:', err);
    } finally {
      setLoadingHistory(false);
    }
  };

  return (
    <div style={{ padding: 20 }}>
      <button onClick={logout}>Выйти</button>
      <h3>
        Чат <em>{chatId}</em>
      </h3>
      <ChatWindow
        messages={messages}
        currentUserId={userId}
        onLoadMore={handleLoadMore}
        hasMore={hasMoreHistory}
        loadingMore={loadingHistory}
      />
      <MessageInput onSend={handleSend} />
    </div>
  );
}
