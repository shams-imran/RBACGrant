import { useEffect, useRef, useState } from 'react';
import { api } from './api/client';
import { Bundle, Catalog, Finding } from './api/types';

export interface Discovery {
  namespaces: string[];
  groups: { name: string; displayName: string;
    resources: { name: string; verbs: string[] }[] }[];
  serviceAccounts: { name: string; namespace: string }[];
  clusterRoles: string[];
  roles: { name: string; namespace: string }[];
  version: { minor: string; gitVersion: string };
  catalog: Catalog | null;
  caNotAfter?: string | null; // expiry of the cluster CA certificate
  apiServerCertNotAfter?: string | null; // expiry of the API server serving cert
}

// Live discovery as a Catalog: real API groups, resources, subresources and
// CRDs straight from the cluster — richer than the offline catalog.
export function liveCatalog(discovery: Discovery | null): Catalog | null {
  if (!discovery?.groups?.length) return null;
  return {
    minor: discovery.version?.minor ?? '',
    verbs: discovery.catalog?.verbs ?? [
      'get', 'list', 'watch', 'create', 'update', 'patch', 'delete',
      'deletecollection', 'use', 'bind', 'escalate', 'impersonate', 'approve', 'sign',
    ],
    groups: discovery.groups,
  };
}

const discoveryCache: Record<string, Discovery> = {};

// Discovery-driven pickers (namespaces, SAs, roles) for the active cluster.
export function useDiscovery(clusterName: string | null | undefined) {
  const [discovery, setDiscovery] = useState<Discovery | null>(
    clusterName ? discoveryCache[clusterName] ?? null : null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!clusterName) {
      setDiscovery(null);
      return;
    }
    // Stale-while-revalidate: show the cached snapshot immediately, but always
    // refetch so roles/SAs created since (e.g. just applied) show up in pickers.
    const cached = discoveryCache[clusterName];
    if (cached) setDiscovery(cached);
    let cancelled = false;
    if (!cached) setLoading(true);
    setError('');
    api<Discovery>(`/api/clusters/${clusterName}/discovery`)
      .then((d) => {
        discoveryCache[clusterName] = d;
        if (!cancelled) setDiscovery(d);
      })
      .catch((e) => { if (!cancelled && !cached) setError(String((e as Error).message)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [clusterName]);

  return { discovery, loading, error };
}

export function useCatalog(): Catalog | null {
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  useEffect(() => {
    (async () => {
      try {
        const idx = await api<{ minors: string[] }>('/api/catalog');
        const newest = idx.minors[idx.minors.length - 1];
        setCatalog(await api<Catalog>(`/api/catalog/${newest}`));
      } catch {
        setCatalog(null);
      }
    })();
  }, []);
  return catalog;
}

export interface AppConfig {
  brandName: string;
  maxTokenTtlSeconds: number;
  defaultTokenTtlSeconds: number;
  maxCertTtlSeconds: number;
  defaultCertTtlSeconds: number;
}

let appConfigCache: AppConfig | null = null;

// Server-side limits (TTL caps etc.) for the UI to respect up front.
export function useAppConfig(): AppConfig | null {
  const [config, setConfig] = useState<AppConfig | null>(appConfigCache);
  useEffect(() => {
    if (appConfigCache) return;
    let cancelled = false;
    api<AppConfig>('/api/config')
      .then((c) => { appConfigCache = c; if (!cancelled) setConfig(c); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);
  return config;
}

export interface PreviewState {
  yaml: string;
  findings: Finding[];
  score: number;
  error: string | null;
}

// Debounced live preview.
export function usePreview(bundle: Bundle, enabled = true): PreviewState {
  const [state, setState] = useState<PreviewState>({ yaml: '', findings: [], score: 100, error: null });
  const timer = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => {
    if (!enabled) return;
    clearTimeout(timer.current);
    timer.current = setTimeout(async () => {
      const empty = !bundle.roles.length && !bundle.bindings.length && !bundle.serviceAccounts.length;
      if (empty) {
        setState({ yaml: '', findings: [], score: 100, error: null });
        return;
      }
      try {
        const resp = await api<{ yaml: string; findings: Finding[]; score: number }>(
          '/api/preview', { method: 'POST', body: bundle });
        setState({ ...resp, error: null });
      } catch (e) {
        setState((s) => ({ ...s, error: String((e as Error).message) }));
      }
    }, 250);
    return () => clearTimeout(timer.current);
  }, [JSON.stringify(bundle), enabled]);
  return state;
}
