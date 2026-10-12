// Kubeconfig merge/split logic. Pure functions, processed entirely in the
// browser — uploaded kubeconfigs contain credentials and never reach the server.
import { parse, stringify } from 'yaml';

export interface NamedItem { name: string; [key: string]: unknown }

export interface Kubeconfig {
  apiVersion?: string;
  kind?: string;
  'current-context'?: string;
  clusters?: NamedItem[];
  users?: NamedItem[];
  contexts?: NamedItem[];
  [key: string]: unknown;
}

export function parseKubeconfig(text: string): Kubeconfig {
  const doc = parse(text);
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new Error('not a YAML mapping');
  }
  const cfg = doc as Kubeconfig;
  if (!cfg.clusters?.length && !cfg.users?.length && !cfg.contexts?.length) {
    throw new Error('no clusters, users or contexts found — is this a kubeconfig?');
  }
  for (const section of SECTIONS) {
    const bad = (cfg[section] ?? []).find((i) => !i || typeof i.name !== 'string');
    if (bad !== undefined) throw new Error(`an entry in "${section}" has no name`);
  }
  return cfg;
}

const SECTIONS = ['clusters', 'users', 'contexts'] as const;
export type SectionKind = 'cluster' | 'user' | 'context';
const KIND_OF: Record<(typeof SECTIONS)[number], SectionKind> = {
  clusters: 'cluster', users: 'user', contexts: 'context',
};

export interface Conflict {
  id: string; // `${fileIndex}:${kind}:${originalName}` — stable across re-merges
  kind: SectionKind;
  name: string;
  file: string;
  fileIndex: number;
}

export type Resolution =
  | { action: 'keep-existing' }
  | { action: 'rename'; newName: string };

export interface MergeInput { label: string; config: Kubeconfig }

export interface MergeResult {
  merged: Kubeconfig;
  conflicts: Conflict[]; // unresolved (or still-colliding after a bad rename)
  notes: string[];
}

// Fold the inputs left to right. Identical duplicates are deduplicated;
// same-name-different-content entries become conflicts the caller resolves
// via `resolutions` (keep the earlier one, or rename the incoming one —
// renames of clusters/users rewrite the contexts of the same file).
export function mergeKubeconfigs(
  inputs: MergeInput[],
  resolutions: Record<string, Resolution> = {},
): MergeResult {
  const merged: Kubeconfig = {
    apiVersion: 'v1', kind: 'Config', clusters: [], users: [], contexts: [],
  };
  const conflicts: Conflict[] = [];
  const notes: string[] = [];

  inputs.forEach((input, fileIndex) => {
    const renames: Record<SectionKind, Record<string, string>> = {
      cluster: {}, user: {}, context: {},
    };
    for (const section of SECTIONS) {
      const kind = KIND_OF[section];
      for (const item of input.config[section] ?? []) {
        let candidate = JSON.parse(JSON.stringify(item)) as NamedItem;
        if (section === 'contexts') {
          const ctx = candidate.context as Record<string, string> | undefined;
          if (ctx) {
            if (renames.cluster[ctx.cluster]) ctx.cluster = renames.cluster[ctx.cluster];
            if (renames.user[ctx.user]) ctx.user = renames.user[ctx.user];
          }
        }
        const id = `${fileIndex}:${kind}:${item.name}`;
        const res = resolutions[id];
        let name = item.name;
        if (res?.action === 'rename' && res.newName.trim()) {
          name = res.newName.trim();
          renames[kind][item.name] = name;
          candidate = { ...candidate, name };
        }
        const existing = merged[section]!.find((e) => e.name === name);
        if (!existing) {
          merged[section]!.push(candidate);
          continue;
        }
        if (JSON.stringify(existing) === JSON.stringify(candidate)) {
          notes.push(`${kind} “${name}” from ${input.label} is identical to an earlier entry — deduplicated`);
          continue;
        }
        if (res?.action === 'keep-existing') {
          notes.push(`${kind} “${name}”: kept the earlier definition, dropped the one from ${input.label}`);
          continue;
        }
        conflicts.push({ id, kind, name: item.name, file: input.label, fileIndex });
      }
    }
  });

  for (const input of inputs) {
    const cc = input.config['current-context'];
    if (cc && merged.contexts!.some((c) => c.name === cc)) {
      merged['current-context'] = cc;
      break;
    }
  }
  return { merged, conflicts, notes };
}

export interface SplitEntry {
  context: string;
  cluster: string;
  user: string;
  namespace: string | null;
  missing: string[]; // dangling references, if the source file was incomplete
  yaml: string;
}

// One standalone kubeconfig per context, each carrying only its own
// cluster + user, with current-context preset.
export function splitKubeconfig(cfg: Kubeconfig): SplitEntry[] {
  return (cfg.contexts ?? []).map((ctxItem) => {
    const ctx = (ctxItem.context ?? {}) as Record<string, string>;
    const cluster = (cfg.clusters ?? []).find((c) => c.name === ctx.cluster);
    const user = (cfg.users ?? []).find((u) => u.name === ctx.user);
    const missing = [
      ...(cluster ? [] : [`cluster “${ctx.cluster}”`]),
      ...(user ? [] : [`user “${ctx.user}”`]),
    ];
    const single: Kubeconfig = {
      apiVersion: 'v1',
      kind: 'Config',
      'current-context': ctxItem.name,
      clusters: cluster ? [cluster] : [],
      contexts: [ctxItem],
      users: user ? [user] : [],
    };
    return {
      context: ctxItem.name,
      cluster: ctx.cluster ?? '',
      user: ctx.user ?? '',
      namespace: ctx.namespace ?? null,
      missing,
      yaml: stringify(single),
    };
  });
}

export function toYaml(cfg: Kubeconfig): string {
  return stringify(cfg);
}

export function safeFilename(name: string): string {
  return name.replace(/[^a-zA-Z0-9._-]+/g, '_') || 'kubeconfig';
}
