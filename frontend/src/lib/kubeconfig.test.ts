import { describe, expect, it } from 'vitest';
import { Kubeconfig, mergeKubeconfigs, parseKubeconfig, splitKubeconfig } from './kubeconfig';

const cfg = (name: string, server: string, user = `${name}-admin`): Kubeconfig => ({
  apiVersion: 'v1',
  kind: 'Config',
  'current-context': name,
  clusters: [{ name, cluster: { server } }],
  users: [{ name: user, user: { token: `tok-${name}` } }],
  contexts: [{ name, context: { cluster: name, user, namespace: 'default' } }],
});

describe('parseKubeconfig', () => {
  it('rejects non-kubeconfig YAML', () => {
    expect(() => parseKubeconfig('just: a map')).toThrow(/is this a kubeconfig/);
    expect(() => parseKubeconfig('- a\n- list')).toThrow(/mapping/);
  });
});

describe('mergeKubeconfigs', () => {
  it('merges disjoint configs and keeps the first current-context', () => {
    const r = mergeKubeconfigs([
      { label: 'a.yaml', config: cfg('alpha', 'https://a:6443') },
      { label: 'b.yaml', config: cfg('beta', 'https://b:6443') },
    ]);
    expect(r.conflicts).toHaveLength(0);
    expect(r.merged.clusters!.map((c) => c.name)).toEqual(['alpha', 'beta']);
    expect(r.merged['current-context']).toBe('alpha');
  });

  it('deduplicates identical entries without a conflict', () => {
    const r = mergeKubeconfigs([
      { label: 'a.yaml', config: cfg('alpha', 'https://a:6443') },
      { label: 'copy.yaml', config: cfg('alpha', 'https://a:6443') },
    ]);
    expect(r.conflicts).toHaveLength(0);
    expect(r.merged.clusters).toHaveLength(1);
    expect(r.notes.some((n) => n.includes('deduplicated'))).toBe(true);
  });

  it('flags same-name different-content as a conflict', () => {
    const r = mergeKubeconfigs([
      { label: 'a.yaml', config: cfg('alpha', 'https://a:6443') },
      { label: 'b.yaml', config: cfg('alpha', 'https://OTHER:6443') },
    ]);
    expect(r.conflicts.length).toBeGreaterThan(0);
    expect(r.conflicts[0]).toMatchObject({ kind: 'cluster', name: 'alpha', file: 'b.yaml' });
  });

  it('rename resolution rewrites the same file’s contexts', () => {
    const inputs = [
      { label: 'a.yaml', config: cfg('alpha', 'https://a:6443') },
      { label: 'b.yaml', config: cfg('alpha', 'https://OTHER:6443') },
    ];
    // Renames can surface follow-up conflicts (the rewritten context now
    // differs from the duplicate it was deduplicated against) — resolve
    // iteratively, as the UI does.
    const resolutions: Record<string, { action: 'rename'; newName: string }> = {};
    let r = mergeKubeconfigs(inputs, resolutions);
    for (let round = 0; r.conflicts.length && round < 3; round++) {
      for (const c of r.conflicts) {
        resolutions[c.id] = { action: 'rename', newName: `${c.name}-b` };
      }
      r = mergeKubeconfigs(inputs, resolutions);
    }
    expect(r.conflicts).toHaveLength(0);
    expect(r.merged.clusters!.map((c) => c.name).sort()).toEqual(['alpha', 'alpha-b']);
    const renamedCtx = r.merged.contexts!.find((c) => c.name === 'alpha-b');
    expect((renamedCtx!.context as { cluster: string }).cluster).toBe('alpha-b');
  });

  it('keep-existing resolution drops the newcomer', () => {
    const inputs = [
      { label: 'a.yaml', config: cfg('alpha', 'https://a:6443') },
      { label: 'b.yaml', config: cfg('alpha', 'https://OTHER:6443') },
    ];
    const first = mergeKubeconfigs(inputs);
    const resolutions = Object.fromEntries(first.conflicts.map((c) => [
      c.id, { action: 'keep-existing' as const },
    ]));
    const r = mergeKubeconfigs(inputs, resolutions);
    expect(r.conflicts).toHaveLength(0);
    expect(r.merged.clusters).toHaveLength(1);
    expect((r.merged.clusters![0].cluster as { server: string }).server).toBe('https://a:6443');
  });

  it('a rename that still collides stays a conflict', () => {
    const inputs = [
      { label: 'a.yaml', config: cfg('alpha', 'https://a:6443') },
      { label: 'b.yaml', config: cfg('alpha', 'https://OTHER:6443') },
    ];
    const first = mergeKubeconfigs(inputs);
    const clusterConflict = first.conflicts.find((c) => c.kind === 'cluster')!;
    const r = mergeKubeconfigs(inputs, {
      [clusterConflict.id]: { action: 'rename', newName: 'alpha' },
    });
    expect(r.conflicts.some((c) => c.id === clusterConflict.id)).toBe(true);
  });
});

describe('splitKubeconfig', () => {
  it('produces one standalone config per context', () => {
    const { merged } = mergeKubeconfigs([
      { label: 'a', config: cfg('alpha', 'https://a:6443') },
      { label: 'b', config: cfg('beta', 'https://b:6443') },
    ]);
    const entries = splitKubeconfig(merged);
    expect(entries.map((e) => e.context)).toEqual(['alpha', 'beta']);
    const alpha = parseKubeconfig(entries[0].yaml);
    expect(alpha['current-context']).toBe('alpha');
    expect(alpha.clusters).toHaveLength(1);
    expect(alpha.users).toHaveLength(1);
    expect(entries[0].missing).toHaveLength(0);
  });

  it('reports dangling cluster/user references', () => {
    const broken: Kubeconfig = {
      contexts: [{ name: 'x', context: { cluster: 'nope', user: 'ghost' } }],
      clusters: [], users: [],
    };
    const [entry] = splitKubeconfig(broken);
    expect(entry.missing).toHaveLength(2);
  });
});
