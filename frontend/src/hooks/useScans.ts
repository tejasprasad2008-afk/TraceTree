"use client";

import { useEffect, useState, useCallback } from 'react';

export interface ScanRecord {
  id: string;
  userId: string;
  target: string;
  verdict: 'MALICIOUS' | 'CLEAN' | 'UNKNOWN';
  confidence: number;
  findings: string;
  createdAt: string;
}

const orchestratorUrl = process.env.NEXT_PUBLIC_ORCHESTRATOR_URL || 'http://localhost:3000';

export function useScans(userId: string | null) {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const cacheKey = userId ? `tracetree_scans_${userId}` : null;

  const loadFromCache = useCallback(() => {
    if (!cacheKey) return;
    try {
      const cached = localStorage.getItem(cacheKey);
      if (cached) setScans(JSON.parse(cached));
    } catch {}
  }, [cacheKey]);

  const fetchScans = useCallback(async () => {
    if (!userId) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${orchestratorUrl}/api/scans?userId=${encodeURIComponent(userId)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const records: ScanRecord[] = data.scans ?? [];
      setScans(records);
      if (cacheKey) {
        localStorage.setItem(cacheKey, JSON.stringify(records));
      }
    } catch (err: any) {
      setError(err.message);
      loadFromCache();
    } finally {
      setLoading(false);
    }
  }, [userId, cacheKey, loadFromCache]);

  useEffect(() => {
    loadFromCache();
    fetchScans();
  }, [fetchScans, loadFromCache]);

  return { scans, loading, error, refetch: fetchScans };
}
