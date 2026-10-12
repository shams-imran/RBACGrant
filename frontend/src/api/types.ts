// Shared API types mirroring the backend pydantic models.

export interface PolicyRule {
  apiGroups: string[];
  resources: string[];
  verbs: string[];
  resourceNames: string[];
  nonResourceURLs: string[];
}

export interface RoleSpec {
  kind: 'Role' | 'ClusterRole';
  metadata: {
    name: string;
    namespace?: string | null;
    labels: Record<string, string>;
    annotations: Record<string, string>;
  };
  rules: PolicyRule[];
  aggregationRule?: { clusterRoleSelectors: unknown[] } | null;
}

export interface Subject {
  kind: 'User' | 'Group' | 'ServiceAccount';
  name: string;
  namespace?: string | null;
}

export interface BindingSpec {
  kind: 'RoleBinding' | 'ClusterRoleBinding';
  name: string;
  namespaces: string[];
  labels: Record<string, string>;
  annotations: Record<string, string>;
  roleRef: { kind: 'Role' | 'ClusterRole'; name: string };
  subjects: Subject[];
}

export interface ServiceAccountSpec {
  name: string;
  namespace: string;
  labels: Record<string, string>;
  annotations: Record<string, string>;
  automountServiceAccountToken: boolean;
}

export interface Bundle {
  roles: RoleSpec[];
  bindings: BindingSpec[];
  serviceAccounts: ServiceAccountSpec[];
}

export interface Finding {
  rule_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  message: string;
  object_kind: string;
  object_name: string;
  object_namespace?: string | null;
  suggestion?: string | null;
}

export interface CatalogResource { name: string; verbs: string[] }
export interface CatalogGroup { name: string; displayName: string; resources: CatalogResource[] }
export interface Catalog { minor: string; verbs: string[]; groups: CatalogGroup[] }

export interface ClusterMeta {
  name: string;
  displayName: string;
  environment: 'prod' | 'staging' | 'dev' | 'other';
  description: string;
  serverUrl: string;
  publicApiUrl?: string | null;
  caSha256: string;
  identity: string;
  credentialType: string;
  credentialExpiry?: string | null;
  addedBy: string;
  addedAt?: string | null;
  storeBackend: string;
  managedByConfig: boolean;
  tlsVerified: boolean;
}

export interface SessionInfo {
  username: string;
  role: 'viewer' | 'editor' | 'admin';
  csrfToken: string;
  stepUpFresh: boolean;
  authMode: 'local' | 'none' | 'oidc';
}

export const emptyBundle = (): Bundle => ({ roles: [], bindings: [], serviceAccounts: [] });

export const emptyRule = (): PolicyRule => ({
  apiGroups: [''], resources: [], verbs: [], resourceNames: [], nonResourceURLs: [],
});
