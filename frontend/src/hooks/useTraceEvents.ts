"use client";

import { useEffect, useState, useCallback, useRef } from 'react';

export type TraceEvent = {
  event: string;
  payload: any;
  timestamp: string;
};

const defaultWsUrl = process.env.NEXT_PUBLIC_ORCHESTRATOR_WS_URL || 'ws://localhost:3000/ws/live';

export function useTraceEvents(url: string = defaultWsUrl) {
  const [events, setEvents] = useState<TraceEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const socketRef = useRef<WebSocket | null>(null);

  const connect = useCallback(() => {
    if (socketRef.current?.readyState === WebSocket.OPEN) return;

    const socket = new WebSocket(url);

    socket.onopen = () => {
      console.log('Connected to TraceTree Orchestrator');
      setIsConnected(true);
    };

    socket.onmessage = (message) => {
      try {
        const data = JSON.parse(message.data);
        setEvents((prev) => [
          {
            ...data,
            timestamp: new Date().toISOString(),
          },
          ...prev,
        ].slice(0, 100)); // Keep last 100 events
      } catch (err) {
        console.error('Failed to parse WebSocket message', err);
      }
    };

    socket.onclose = () => {
      console.log('Disconnected from TraceTree Orchestrator');
      setIsConnected(false);
      // Simple reconnect logic
      setTimeout(connect, 3000);
    };

    socket.onerror = (err) => {
      console.error('WebSocket Error:', err);
      socket.close();
    };

    socketRef.current = socket;
  }, [url]);

  useEffect(() => {
    connect();
    return () => {
      socketRef.current?.close();
    };
  }, [connect]);

  return { events, isConnected };
}
