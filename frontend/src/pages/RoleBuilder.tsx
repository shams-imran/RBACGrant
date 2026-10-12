import { useState } from 'react';
import { Autocomplete, Button, Grid, Group, Menu, SegmentedControl, Stack, Tabs,
  TextInput, Textarea, Title, Modal, Alert } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { apiText } from '../api/client';
import { Bundle, PolicyRule, RoleSpec, emptyBundle } from '../api/types';
import { ApplyToCluster } from '../components/ApplyToCluster';
import { ExportBar } from '../components/ExportBar';
import { FindingsList } from '../components/Findings';
import { RuleEditor } from '../components/RuleEditor';
import { YamlPreview } from '../components/YamlPreview';
import { liveCatalog, useCatalog, useDiscovery, usePreview } from '../hooks';
import { useCluster } from '../ClusterContext';
import { showAllFilter } from '../components/pickers';

// Quick presets. Risky ones are flagged by the linter automatically.
const PRESETS: Record<string, PolicyRule[]> = {
  'Read-only': [
    { apiGroups: [''], resources: ['pods', 'services', 'configmaps'], verbs: ['get', 'list', 'watch'], resourceNames: [], nonResourceURLs: [] },
    { apiGroups: ['apps'], resources: ['deployments', 'replicasets', 'statefulsets'], verbs: ['get', 'list', 'watch'], resourceNames: [], nonResourceURLs: [] },
  ],
  'Read-write': [
    { apiGroups: [''], resources: ['pods', 'services', 'configmaps'], verbs: ['get', 'list', 'watch', 'create', 'update', 'patch', 'delete'], resourceNames: [], nonResourceURLs: [] },
    { apiGroups: ['apps'], resources: ['deployments', 'replicasets', 'statefulsets'], verbs: ['get', 'list', 'watch', 'create', 'update', 'patch', 'delete'], resourceNames: [], nonResourceURLs: [] },
  ],
  'Namespace developer': [
    { apiGroups: [''], resources: ['pods', 'pods/log', 'services', 'configmaps'], verbs: ['get', 'list', 'watch', 'create', 'update', 'patch', 'delete'], resourceNames: [], nonResourceURLs: [] },
    { apiGroups: ['apps'], resources: ['deployments', 'replicasets'], verbs: ['get', 'list', 'watch', 'create', 'update', 'patch', 'delete'], resourceNames: [], nonResourceURLs: [] },
    { apiGroups: ['batch'], resources: ['jobs', 'cronjobs'], verbs: ['get', 'list', 'watch', 'create', 'delete'], resourceNames: [], nonResourceURLs: [] },
  ],
  'CI deployer': [
    { apiGroups: ['apps'], resources: ['deployments', 'statefulsets'], verbs: ['get', 'list', 'watch', 'create', 'update', 'patch'], resourceNames: [], nonResourceURLs: [] },
    { apiGroups: [''], resources: ['services', 'configmaps'], verbs: ['get', 'list', 'watch', 'create', 'update', 'patch'], resourceNames: [], nonResourceURLs: [] },
  ],
  'Logs + exec (high risk)': [
    { apiGroups: [''], resources: ['pods', 'pods/log'], verbs: ['get', 'list', 'watch'], resourceNames: [], nonResourceURLs: [] },
    { apiGroups: [''], resources: ['pods/exec'], verbs: ['create'], resourceNames: [], nonResourceURLs: [] },
  ],
  'View secrets (flagged)': [
    { apiGroups: [''], resources: ['secrets'], verbs: ['get', 'list'], resourceNames: [], nonResourceURLs: [] },
  ],
};

export default function RoleBuilderPage() {
  const offlineCatalog = useCatalog();
  const { active } = useCluster();
  const { discovery, error: discoveryError } = useDiscovery(active?.name);
  // With an active cluster, use live discovery (incl. CRDs);
  // fall back to the version-matched offline catalog, then the newest.
  const catalog = liveCatalog(discovery) ?? discovery?.catalog ?? offlineCatalog;
  const [kind, setKind] = useState<'Role' | 'ClusterRole'>('Role');
  const [name, setName] = useState('');
  const [namespace, setNamespace] = useState('default');
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState('');

  const role: RoleSpec | null = name
    ? {
        kind,
        metadata: {
          name,
          namespace: kind === 'Role' ? namespace : null,
          labels: {}, annotations: {},
        },
        rules,
      }
    : null;

  const bundle: Bundle = { ...emptyBundle(), roles: role && rules.length ? [role] : [] };
  const preview = usePreview(bundle);

  const doImport = async () => {
    try {
      const { objects } = await apiText<{ objects: Record<string, unknown>[] }>(
        '/api/import-yaml', importText);
      const roleObj = objects.find((o: { kind?: string }) =>
        o.kind === 'Role' || o.kind === 'ClusterRole') as {
        kind: 'Role' | 'ClusterRole';
        metadata: { name: string; namespace?: string };
        rules?: PolicyRule[];
      } | undefined;
      if (!roleObj) throw new Error('no Role/ClusterRole in the YAML');
      setKind(roleObj.kind);
      setName(roleObj.metadata.name);
      if (roleObj.metadata.namespace) setNamespace(roleObj.metadata.namespace);
      setRules((roleObj.rules ?? []).map((r) => ({
        apiGroups: r.apiGroups ?? [], resources: r.resources ?? [],
        verbs: r.verbs ?? [], resourceNames: r.resourceNames ?? [],
        nonResourceURLs: r.nonResourceURLs ?? [],
      })));
      setImportOpen(false);
      notifications.show({ color: 'green', message: 'Imported into the form' });
    } catch (e) {
      notifications.show({ color: 'red', message: String((e as Error).message) });
    }
  };

  return (
    <Stack mt="md">
      <Group justify="space-between">
        <Title order={3}>Role / ClusterRole builder</Title>
        <Group>
          <Menu>
            <Menu.Target><Button variant="light" size="xs">Presets ▾</Button></Menu.Target>
            <Menu.Dropdown>
              {Object.entries(PRESETS).map(([label, preset]) => (
                <Menu.Item key={label} onClick={() => setRules(JSON.parse(JSON.stringify(preset)))}>
                  {label}
                </Menu.Item>
              ))}
            </Menu.Dropdown>
          </Menu>
          <Button variant="light" size="xs" onClick={() => setImportOpen(true)}>
            Import YAML
          </Button>
        </Group>
      </Group>

      {discoveryError && (
        <Alert color="red" py={6}>
          Could not connect to {active?.displayName || active?.name}: {discoveryError}
          {' '}— pickers fall back to the offline catalog.
        </Alert>
      )}

      <Grid>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Stack gap="sm">
            <SegmentedControl value={kind} data={['Role', 'ClusterRole']}
              onChange={(v) => setKind(v as 'Role' | 'ClusterRole')} />
            <Group grow>
              <TextInput label="Name" value={name} placeholder="pod-reader"
                onChange={(e) => setName(e.currentTarget.value.toLowerCase())} />
              {kind === 'Role' && (
                <Autocomplete label="Namespace" value={namespace}
                  data={discovery?.namespaces ?? []} limit={50}
                  filter={showAllFilter}
                  onChange={(v) => setNamespace(v.toLowerCase())} />
              )}
            </Group>
            <RuleEditor rules={rules} onChange={setRules} catalog={catalog}
              clusterScope={kind === 'ClusterRole'} />
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

      <Modal opened={importOpen} onClose={() => setImportOpen(false)}
        title="Import Role / ClusterRole YAML" size="lg">
        <Stack>
          <Textarea minRows={12} autosize value={importText} styles={{
            input: { fontFamily: 'var(--font-mono)' } }}
            onChange={(e) => setImportText(e.currentTarget.value)}
            placeholder="Paste Role or ClusterRole YAML here" />
          <Button onClick={doImport}>Import into the form</Button>
        </Stack>
      </Modal>
    </Stack>
  );
}
