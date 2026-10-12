import { ActionIcon, Button, Checkbox, Group, MultiSelect, Paper, SimpleGrid,
  Stack, TagsInput, Text, Tooltip } from '@mantine/core';
import { Catalog, PolicyRule, emptyRule } from '../api/types';

// Rule editor with add / remove / duplicate / reorder.
const SPECIAL_VERBS = ['use', 'bind', 'escalate', 'impersonate', 'approve', 'sign'];
const BASIC_VERBS = ['get', 'list', 'watch', 'create', 'update', 'patch', 'delete', 'deletecollection'];

export function RuleEditor({ rules, onChange, catalog, clusterScope }: {
  rules: PolicyRule[];
  onChange: (rules: PolicyRule[]) => void;
  catalog: Catalog | null;
  clusterScope: boolean; // ClusterRole allows nonResourceURLs
}) {
  const groupOptions = (catalog?.groups ?? []).map((g) => ({
    value: g.name, label: g.displayName,
  }));

  const resourcesFor = (apiGroups: string[]): string[] => {
    if (!catalog) return [];
    const set = new Set<string>();
    for (const g of catalog.groups) {
      if (apiGroups.length === 0 || apiGroups.includes('*')
          || apiGroups.includes(g.name)) {
        g.resources.forEach((r) => set.add(r.name));
      }
    }
    return [...set].sort();
  };
  // Every catalog resource — used to tell "known but out of the selected
  // groups" (drop on group change) from "custom/CRD entry" (always keep).
  const catalogAll = resourcesFor([]);

  // Group each resource with its subresources (pods, pods/exec, pods/log, …)
  // so the picker reads like the API does. Resources without subresources
  // stay as plain items in the same alphabetical order.
  const groupedResourcesFor = (apiGroups: string[]) => {
    const byBase = new Map<string, string[]>();
    for (const name of resourcesFor(apiGroups)) {
      const base = name.split('/')[0];
      byBase.set(base, [...(byBase.get(base) ?? []), name]);
    }
    return [...byBase.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([base, items]) => (items.length > 1
        ? { group: base, items: items.sort() }
        : items[0]));
  };

  const update = (i: number, patch: Partial<PolicyRule>) => {
    const next = rules.slice();
    next[i] = { ...next[i], ...patch };
    onChange(next);
  };

  const move = (i: number, dir: -1 | 1) => {
    const j = i + dir;
    if (j < 0 || j >= rules.length) return;
    const next = rules.slice();
    [next[i], next[j]] = [next[j], next[i]];
    onChange(next);
  };

  return (
    <Stack gap="sm">
      {rules.map((rule, i) => {
        const nonResource = rule.nonResourceURLs.length > 0;
        return (
          <Paper key={i} withBorder p="sm">
            <Group justify="space-between" mb="xs">
              <Text size="sm" fw={600}>Rule {i + 1}</Text>
              <Group gap={4}>
                <ActionIcon variant="subtle" size="sm" aria-label="Move up"
                  onClick={() => move(i, -1)}>↑</ActionIcon>
                <ActionIcon variant="subtle" size="sm" aria-label="Move down"
                  onClick={() => move(i, 1)}>↓</ActionIcon>
                <ActionIcon variant="subtle" size="sm" aria-label="Duplicate rule"
                  onClick={() => onChange([...rules.slice(0, i + 1),
                    JSON.parse(JSON.stringify(rule)), ...rules.slice(i + 1)])}>⧉</ActionIcon>
                <ActionIcon variant="subtle" color="red" size="sm" aria-label="Remove rule"
                  onClick={() => onChange(rules.filter((_, k) => k !== i))}>✕</ActionIcon>
              </Group>
            </Group>
            {!nonResource && (
              <SimpleGrid cols={{ base: 1, md: 2 }} spacing="xs">
                <MultiSelect label="API groups" searchable
                  data={[{ value: '*', label: '* (all API groups)' }, ...groupOptions]}
                  value={rule.apiGroups}
                  onChange={(v) => update(i, {
                    apiGroups: v,
                    // keep wildcard and custom/CRD entries; drop only known
                    // resources that fell outside the selected groups
                    resources: rule.resources.filter((r) => r === '*'
                      || resourcesFor(v).includes(r) || !catalogAll.includes(r)),
                  })}
                  placeholder={rule.apiGroups.length ? undefined : 'core'} />
                <TagsInput label="Resources (incl. subresources)"
                  data={[{ group: 'wildcard', items: ['*'] },
                    ...groupedResourcesFor(rule.apiGroups)]}
                  value={rule.resources}
                  onChange={(v) => update(i, { resources: v })}
                  placeholder={rule.resources.length ? undefined
                    : 'pick from the list, or type any resource (CRDs too)'} />
              </SimpleGrid>
            )}
            <Stack gap={4} mt="xs">
              <Text size="sm" fw={500}>Verbs</Text>
              <Group gap="xs">
                {BASIC_VERBS.map((v) => (
                  <Checkbox key={v} label={v} size="xs"
                    checked={rule.verbs.includes(v)}
                    onChange={(e) => update(i, {
                      verbs: e.currentTarget.checked
                        ? [...rule.verbs, v] : rule.verbs.filter((x) => x !== v),
                    })} />
                ))}
              </Group>
              <Group gap="xs">
                {SPECIAL_VERBS.map((v) => (
                  <Tooltip key={v} label="special verb — review the linter findings">
                    <Checkbox label={v} size="xs" color="yellow"
                      checked={rule.verbs.includes(v)}
                      onChange={(e) => update(i, {
                        verbs: e.currentTarget.checked
                          ? [...rule.verbs, v] : rule.verbs.filter((x) => x !== v),
                      })} />
                  </Tooltip>
                ))}
              </Group>
            </Stack>
            {!nonResource && (
              <TagsInput label="resourceNames (optional least-privilege narrowing)"
                mt="xs" value={rule.resourceNames}
                onChange={(v) => update(i, { resourceNames: v })}
                placeholder="specific object names" />
            )}
            {clusterScope && (
              <TagsInput label="nonResourceURLs (ClusterRole only, e.g. /metrics)"
                mt="xs" value={rule.nonResourceURLs}
                onChange={(v) => update(i, {
                  nonResourceURLs: v,
                  ...(v.length ? { apiGroups: [], resources: [], resourceNames: [] } : {}),
                })} />
            )}
          </Paper>
        );
      })}
      <Button variant="light" size="xs" onClick={() => onChange([...rules, emptyRule()])}>
        + Add rule
      </Button>
    </Stack>
  );
}
