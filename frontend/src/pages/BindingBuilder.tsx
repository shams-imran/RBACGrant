import { useMemo, useState } from 'react';
import { ActionIcon, Alert, Autocomplete, Button, Checkbox, Grid, Group, Paper,
  SegmentedControl, Select, Stack, Switch, Tabs, TagsInput, Text, TextInput,
  Title } from '@mantine/core';
import { DateTimePicker, DateTimePickerProps } from '@mantine/dates';
import { BindingSpec, Bundle, ServiceAccountSpec, Subject, emptyBundle } from '../api/types';
import { ApplyToCluster } from '../components/ApplyToCluster';
import { ExportBar } from '../components/ExportBar';
import { FindingsList } from '../components/Findings';
import { YamlPreview } from '../components/YamlPreview';
import { useDiscovery, usePreview } from '../hooks';
import { useCluster } from '../ClusterContext';
import { showAllFilter } from '../components/pickers';

const BUILT_IN_ROLES = ['view', 'edit', 'admin', 'cluster-admin'];

export default function BindingBuilderPage() {
  const { active } = useCluster();
  const { discovery, error: discoveryError } = useDiscovery(active?.name);
  // RoleBinding is the default.
  const [kind, setKind] = useState<'RoleBinding' | 'ClusterRoleBinding'>('RoleBinding');
  const [name, setName] = useState('');
  const [namespaces, setNamespaces] = useState<string[]>(['default']);
  const [refKind, setRefKind] = useState<'Role' | 'ClusterRole'>('Role');
  const [refName, setRefName] = useState('');
  const [subjects, setSubjects] = useState<Subject[]>([
    { kind: 'Group', name: '', namespace: null },
  ]);
  const [owner, setOwner] = useState('');
  const [description, setDescription] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [createSa, setCreateSa] = useState(false);
  const [saAutomount, setSaAutomount] = useState(false);

  // The Role name picker is fed from cluster discovery, scoped by the
  // selected roleRef kind and (for Roles) by every selected namespace.
  const effectiveRefKind = kind === 'ClusterRoleBinding' ? 'ClusterRole' : refKind;
  const selectedNs = namespaces.filter(Boolean);
  const roleOptions = useMemo(() => {
    if (effectiveRefKind === 'ClusterRole') {
      const live = (discovery?.clusterRoles ?? []).filter((r) => !r.startsWith('system:'));
      const unique = [...new Set(live)].filter((r) => !BUILT_IN_ROLES.includes(r));
      return [
        ...BUILT_IN_ROLES.map((r) => ({ value: r, label: `${r} (built-in)` })),
        ...unique.sort().map((r) => ({ value: r, label: r })),
      ];
    }
    const inScope = (discovery?.roles ?? []).filter(
      (r) => !selectedNs.length || selectedNs.includes(r.namespace));
    const byName = new Map<string, string[]>();
    for (const r of inScope) byName.set(r.name, [...(byName.get(r.name) ?? []), r.namespace]);
    return [...byName.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([roleName, nss]) => ({
        value: roleName,
        label: selectedNs.length === 1 ? roleName
          : `${roleName} (${nss.sort().join(', ')})`,
      }));
  }, [discovery, effectiveRefKind, selectedNs.join(',')]);

  // One RoleBinding per namespace needs the Role in each of them.
  const missingRoleNs = effectiveRefKind === 'Role' && refName && discovery
    ? selectedNs.filter((ns) =>
        !discovery.roles.some((r) => r.name === refName && r.namespace === ns))
    : [];

  const annotations: Record<string, string> = {};
  if (owner) annotations['rbac-builder/owner'] = owner;
  if (description) annotations['rbac-builder/description'] = description;
  if (expiresAt) annotations['rbac-builder/expires-at'] = expiresAt;

  const validSubjects = subjects.filter((s) => s.name);
  const binding: BindingSpec | null = name && refName && validSubjects.length
    ? {
        kind, name,
        namespaces: kind === 'RoleBinding' ? namespaces.filter(Boolean) : [],
        labels: {}, annotations,
        roleRef: { kind: kind === 'ClusterRoleBinding' ? 'ClusterRole' : refKind, name: refName },
        subjects: validSubjects,
      }
    : null;

  // Create the SA in the same bundle when asked.
  const saSubject = validSubjects.find((s) => s.kind === 'ServiceAccount');
  const serviceAccounts: ServiceAccountSpec[] = createSa && saSubject?.namespace
    ? [{ name: saSubject.name, namespace: saSubject.namespace, labels: {},
         annotations: {}, automountServiceAccountToken: saAutomount }]
    : [];

  const bundle: Bundle = { ...emptyBundle(), bindings: binding ? [binding] : [], serviceAccounts };
  const preview = usePreview(bundle);

  const updateSubject = (i: number, patch: Partial<Subject>) => {
    const next = subjects.slice();
    next[i] = { ...next[i], ...patch };
    setSubjects(next);
  };

  return (
    <Stack mt="md">
      <Title order={3}>Binding builder</Title>
      {discoveryError && (
        <Alert color="red" py={6}>
          Could not connect to {active?.displayName || active?.name}: {discoveryError}
          {' '}— role and namespace pickers will be empty; names can still be typed.
        </Alert>
      )}
      <Grid>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Stack gap="sm">
            <SegmentedControl value={kind} data={['RoleBinding', 'ClusterRoleBinding']}
              onChange={(v) => { setKind(v as typeof kind); setRefName(''); }} />
            {kind === 'ClusterRoleBinding' && (
              <Alert color="yellow" py={6}>
                Does this really need cluster-wide scope? A RoleBinding per
                namespace is usually narrower.
              </Alert>
            )}
            <TextInput label="Binding name" value={name} placeholder="team-devs"
              onChange={(e) => setName(e.currentTarget.value.toLowerCase())} />
            {kind === 'RoleBinding' && (
              <TagsInput label="Namespaces (several = one RoleBinding each)"
                value={namespaces} onChange={setNamespaces} placeholder="default"
                data={discovery?.namespaces ?? []} />
            )}
            <Group grow>
              {kind === 'RoleBinding' && (
                <Select label="roleRef kind" data={['Role', 'ClusterRole']} value={refKind}
                  onChange={(v) => {
                    setRefKind((v as 'Role' | 'ClusterRole') ?? 'Role');
                    setRefName('');
                  }} />
              )}
              <Select label="Role name" searchable value={refName || null}
                data={roleOptions}
                onChange={(v) => setRefName(v ?? '')}
                onSearchChange={(v) => { if (v) setRefName(v); }}
                placeholder={active
                  ? `pick a ${effectiveRefKind} from the cluster or type a name`
                  : 'type a name (no cluster selected)'}
                nothingFoundMessage={effectiveRefKind === 'Role' && selectedNs.length
                  ? `no Roles found in ${selectedNs.join(', ')} — type a name to reference one anyway`
                  : 'nothing found — type a name'}
                limit={30} />
            </Group>
            {missingRoleNs.length > 0 && (
              <Alert color="yellow" py={6}>
                Role <b>{refName}</b> does not exist in namespace
                {missingRoleNs.length > 1 ? 's' : ''} <b>{missingRoleNs.join(', ')}</b> on
                the cluster — the RoleBinding there would reference a missing
                Role until you create it.
              </Alert>
            )}
            <Alert color="blue" py={6}>
              roleRef is immutable after creation — changing it later means
              delete and recreate.
            </Alert>

            <Text fw={600} size="sm">Subjects</Text>
            {subjects.map((s, i) => (
              <Paper key={i} withBorder p="xs">
                <Group align="flex-end" gap="xs">
                  <Select w={150} label="Kind" data={['User', 'Group', 'ServiceAccount']}
                    value={s.kind}
                    onChange={(v) => updateSubject(i, {
                      kind: (v as Subject['kind']) ?? 'Group',
                      namespace: v === 'ServiceAccount' ? (s.namespace ?? 'default') : null })} />
                  {s.kind === 'ServiceAccount' ? (
                    <Autocomplete style={{ flex: 1 }} label="Name" value={s.name}
                      data={[...new Set((discovery?.serviceAccounts ?? [])
                        .filter((sa) => !s.namespace || sa.namespace === s.namespace)
                        .map((sa) => sa.name))]}
                      limit={50} filter={showAllFilter}
                      onChange={(v) => updateSubject(i, { name: v })} />
                  ) : (
                    <TextInput style={{ flex: 1 }} label="Name" value={s.name}
                      onChange={(e) => updateSubject(i, { name: e.currentTarget.value })} />
                  )}
                  {s.kind === 'ServiceAccount' && (
                    <Autocomplete w={160} label="Namespace" value={s.namespace ?? ''}
                      data={discovery?.namespaces ?? []} limit={50}
                      filter={showAllFilter}
                      onChange={(v) => updateSubject(i, { namespace: v })} />
                  )}
                  <ActionIcon color="red" variant="subtle" aria-label="Remove subject"
                    onClick={() => setSubjects(subjects.filter((_, k) => k !== i))}>✕</ActionIcon>
                </Group>
                {s.kind === 'User' && (
                  <Text size="xs" c="dimmed" mt={4}>
                    Prefer binding Groups over individual Users.
                  </Text>
                )}
              </Paper>
            ))}
            <Button variant="light" size="xs"
              onClick={() => setSubjects([...subjects, { kind: 'Group', name: '', namespace: null }])}>
              + Add subject
            </Button>

            {saSubject && (
              <Paper withBorder p="xs">
                <Switch label={`Create ServiceAccount ${saSubject.namespace ?? '?'}/${saSubject.name} in this bundle`}
                  checked={createSa} onChange={(e) => setCreateSa(e.currentTarget.checked)} />
                {createSa && (
                  <Checkbox mt="xs" label="automountServiceAccountToken (off is safer)"
                    checked={saAutomount}
                    onChange={(e) => setSaAutomount(e.currentTarget.checked)} />
                )}
              </Paper>
            )}

            <Text fw={600} size="sm">Ownership</Text>
            <Group grow>
              <TextInput label="Owner" value={owner} placeholder="team-platform"
                onChange={(e) => setOwner(e.currentTarget.value)} />
              <DateTimePicker label="Expires at" clearable
                value={expiresAt ? new Date(expiresAt) : null}
                minDate={new Date()}
                valueFormat="YYYY-MM-DD HH:mm"
                placeholder="pick a date and time"
                // The popup's time field only re-reads the value when the
                // popup closes — control it so the 11:59 PM default shows.
                // Mantine's types omit `value` here, but the spread honors it.
                timeInputProps={{ value: expiresAt
                  ? new Date(expiresAt).toTimeString().slice(0, 5) : '' } as
                  DateTimePickerProps['timeInputProps']}
                // The annotation stays an ISO-8601 UTC timestamp, as before.
                onChange={(d) => {
                  if (!d) return setExpiresAt('');
                  const picked = new Date(d);
                  // First pick of a date defaults the time to 11:59 PM.
                  if (!expiresAt && picked.getHours() === 0 && picked.getMinutes() === 0) {
                    picked.setHours(23, 59, 0, 0);
                  }
                  setExpiresAt(picked.toISOString().replace(/\.\d{3}Z$/, 'Z'));
                }} />
            </Group>
            <TextInput label="Description" value={description}
              placeholder="why this access is needed (or a ticket ref)"
              onChange={(e) => setDescription(e.currentTarget.value)} />
          </Stack>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Tabs defaultValue="yaml">
            <Tabs.List>
              <Tabs.Tab value="yaml">YAML preview</Tabs.Tab>
              <Tabs.Tab value="lint">
                Linter {preview.findings.length ? `(${preview.findings.length})` : ''}
              </Tabs.Tab>
            </Tabs.List>
            <Tabs.Panel value="yaml" pt="xs">
              {preview.error && <Alert color="red" mb="xs">{preview.error}</Alert>}
              <YamlPreview yaml={preview.yaml || '# fill in the form to see YAML'} />
              <Group mt="xs">
                <ExportBar bundle={bundle} disabled={!preview.yaml} />
                <ApplyToCluster bundle={bundle} disabled={!preview.yaml} />
              </Group>
            </Tabs.Panel>
            <Tabs.Panel value="lint" pt="xs">
              <FindingsList findings={preview.findings} score={preview.score} />
            </Tabs.Panel>
          </Tabs>
        </Grid.Col>
      </Grid>
    </Stack>
  );
}
