import React, { createContext, useContext, useEffect, useState } from 'react';
import { api } from './api/client';
import { ClusterMeta } from './api/types';
import { useAuth } from './AuthContext';

interface ClusterState {
  clusters: ClusterMeta[];
  active: ClusterMeta | null;
  setActive: (name: string | null) => void;
  reload: () => Promise<void>;
}

const ClusterContext = createContext<ClusterState>(null as unknown as ClusterState);
export const useCluster = () => useContext(ClusterContext);

export function ClusterProvider({ children }: { children: React.ReactNode }) {
  const { session } = useAuth();
  const [clusters, setClusters] = useState<ClusterMeta[]>([]);
  // Persist the selection so a page refresh keeps the active cluster.
  const [activeName, setActiveName] = useState<string | null>(() => {
    try {
      return localStorage.getItem('rbac-ui:active-cluster');
    } catch {
      return null;
    }
  });

  const reload = async () => {
    if (!session) return;
    try {
      const resp = await api<{ clusters: { metadata: ClusterMeta }[] }>('/api/clusters');
      setClusters(resp.clusters.map((c) => c.metadata).filter((m) => m.serverUrl));
    } catch {
      setClusters([]);
    }
  };

  useEffect(() => { reload(); }, [session?.username]);

  const active = clusters.find((c) => c.name === activeName) ?? null;

  // Switching clusters clears pickers and discovery state.
  const setActive = (name: string | null) => {
    setActiveName(name);
    try {
      if (name) localStorage.setItem('rbac-ui:active-cluster', name);
      else localStorage.removeItem('rbac-ui:active-cluster');
    } catch { /* private mode etc. — selection just won't persist */ }
    window.dispatchEvent(new CustomEvent('rbac-ui:cluster-switched'));
  };

  return (
    <ClusterContext.Provider value={{ clusters, active, setActive, reload }}>
      {children}
    </ClusterContext.Provider>
  );
}
