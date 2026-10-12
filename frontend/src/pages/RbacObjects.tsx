import { useEffect, useMemo, useState } from 'react';
import { ActionIcon, Alert, Autocomplete, Badge, Button, Code, Drawer, Grid,
  Group, Loader, Modal, Paper, SegmentedControl, Select, Stack, Switch, Table,
  Tabs, Text, TextInput, Title } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { api, ApiError } from '../api/client';
import { Bundle, Finding, PolicyRule, Subject, emptyBundle } from '../api/types';
import { showAllFilter } from '../components/pickers';
import { useCluster } from '../ClusterContext';
import { ApplyToCluster } from '../components/ApplyToCluster';
import { FindingsList, SeverityBadge } from '../components/Findings';
import { RuleEditor } from '../components/RuleEditor';
import { StepUpModal } from '../components/StepUpModal';
import { YamlPreview } from '../components/YamlPreview';
import { liveCatalog, useCatalog, useDiscovery, usePreview } from '../hooks';
import { stringify } from 'yaml';

interface K8sObject {
  kind?: string;
  metadata: { name: string; namespace?: string; creationTimestamp?: string;
    labels?: Record<string, string>; annotations?: Record<string, string>;
    managedFields?: unknown; resourceVersion?: string; uid?: string };
  rules?: unknown[];
  roleRef?: { kind: string; name: string };
  subjects?: { kind: string; name: string; namespace?: string }[];
  aggregationRule?: unknown;
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function worstFinding(findings: Finding[], name: string, kind: string): Finding | null {
  const mine = findings.filter((f) => f.object_name === name && f.object_kind === kind);
  if (!mine.length) return null;
  return mine.sort((a, b) =>
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))[0];
}

function isSystem(obj: K8sObject): boolean {
  return obj.metadata.name.startsWith('system:')
    || obj.metadata.labels?.['kubernetes.io/bootstrapping'] === 'rbac-defaults';
}

function cleanForYaml(obj: K8sObject, showManaged: boolean): K8sObject {
  if (showManaged) return obj;
  const copy = JSON.parse(JSON.stringify(obj)) as K8sObject;
  delete copy.metadata.managedFields;
  delete copy.metadata.resourceVersion;
  delete copy.metadata.uid;
  delete (copy.metadata as Record<string, unknown>).creationTimestamp;
  return copy;
}

// Live rules come straight from the API server; normalize them for the editor.
function toPolicyRule(r: unknown): PolicyRule {
  const o = (r ?? {}) as Partial<PolicyRule>;
  return {
    apiGroups: o.apiGroups ?? [],
    resources: o.resources ?? [],
    verbs: o.verbs ?? [],
    resourceNames: o.resourceNames ?? [],
    nonResourceURLs: o.nonResourceURLs ?? [],
  };
}

export default function RbacObjectsPage() {
  const { active } = useCluster();
  const [data, setData] = useState<Record<string, K8sObject[]> | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState('');
  const [hideSystem, setHideSystem] = useState(true); // default on
  const [detail, setDetail] = useState<{ obj: K8sObject; kind: string } | null>(null);
  const [showManaged, setShowManaged] = useState(false);
  // Kind filters per tab: show both kinds, or just the namespaced / cluster-wide one.
  const [roleKind, setRoleKind] = useState<'all' | 'Role' | 'ClusterRole'>('all');
  const [bindingKind, setBindingKind] =
    useState<'all' | 'RoleBinding' | 'ClusterRoleBinding'>('all');

  // --- edit / delete state ---
  const [editRules, setEditRules] = useState<PolicyRule[] | null>(null);
  const [editSubjects, setEditSubjects] = useState<Subject[] | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [stepUpOpen, setStepUpOpen] = useState(false);

  const offlineCatalog = useCatalog();
  const { discovery } = useDiscovery(active?.name);
  const catalog = liveCatalog(discovery) ?? discovery?.catalog ?? offlineCatalog;

  const load = async () => {
    if (!active) return;
    setLoading(true);
    setError('');
    try {
      const r = await api<{ objects: Record<string, K8sObject[]>; findings: Finding[] }>(
        `/api/clusters/${active.name}/rbac`);
      const withKinds: Record<string, K8sObject[]> = {};
      const kindNames: Record<string, string> = {
        roles: 'Role', clusterroles: 'ClusterRole',
        rolebindings: 'RoleBinding', clusterrolebindings: 'ClusterRoleBinding',
      };
      for (const [key, objs] of Object.entries(r.objects)) {
        withKinds[key] = objs.map((o) => ({ ...o, kind: o.kind ?? kindNames[key] }));
      }
      setData(withKinds);
      setFindings(r.findings);
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setData(null);
    load();
  }, [active?.name]);

  const closeDetail = () => {
    setDetail(null);
    setEditRules(null);
    setEditSubjects(null);
  };

  const isRoleKind = detail?.kind === 'Role' || detail?.kind === 'ClusterRole';
  const isBindingKind = detail?.kind === 'RoleBinding'
    || detail?.kind === 'ClusterRoleBinding';
  const editable = !!detail && isRoleKind && !detail.obj.aggregationRule;

  // Rebuild the object with the edited rules/subjects; server-side apply
  // (force) replaces them on the cluster while keeping labels/annotations.
  const editBundle: Bundle = useMemo(() => {
    if (!detail) return emptyBundle();
    const annotations = { ...(detail.obj.metadata.annotations ?? {}) };
    delete annotations['kubectl.kubernetes.io/last-applied-configuration'];
    if (editRules && isRoleKind) {
      return {
        ...emptyBundle(),
        roles: [{
          kind: detail.kind as 'Role' | 'ClusterRole',
          metadata: {
            name: detail.obj.metadata.name,
            namespace: detail.kind === 'Role' ? detail.obj.metadata.namespace : null,
            labels: detail.obj.metadata.labels ?? {},
            annotations,
          },
          rules: editRules,
        }],
      };
    }
    if (editSubjects && isBindingKind && detail.obj.roleRef) {
      return {
        ...emptyBundle(),
        bindings: [{
          kind: detail.kind as 'RoleBinding' | 'ClusterRoleBinding',
          name: detail.obj.metadata.name,
          namespaces: detail.kind === 'RoleBinding' && detail.obj.metadata.namespace
            ? [detail.obj.metadata.namespace] : [],
          labels: detail.obj.metadata.labels ?? {},
          annotations,
          roleRef: {
            kind: detail.obj.roleRef.kind as 'Role' | 'ClusterRole',
            name: detail.obj.roleRef.name,
          },
          subjects: editSubjects.filter((s) => s.name),
        }],
      };
    }
    return emptyBundle();
  }, [detail, editRules, editSubjects, isRoleKind, isBindingKind]);
  const rulesValid = !!editRules && editRules.every(
    (r) => r.verbs.length && (r.resources.length || r.nonResourceURLs.length));
  const subjectsValid = !!editSubjects
    && editSubjects.some((s) => s.name)
    && editSubjects.filter((s) => s.name)
      .every((s) => s.kind !== 'ServiceAccount' || !!s.namespace);
  const editPreview = usePreview(editBundle, !!editRules || !!editSubjects);

  const updateSubject = (i: number, patch: Partial<Subject>) => {
    if (!editSubjects) return;
    const next = editSubjects.slice();
    next[i] = { ...next[i], ...patch };
    setEditSubjects(next);
  };

  const doDelete = async () => {
    if (!active || !detail) return;
    setBusy(true);
    try {
      await api(`/api/clusters/${active.name}/delete-object`, {
        method: 'POST',
        body: {
          kind: detail.kind,
          name: detail.obj.metadata.name,
          namespace: detail.obj.metadata.namespace ?? null,
          confirmClusterName: deleteConfirm || null,
        },
      });
      notifications.show({ color: 'green',
        message: `Deleted ${detail.kind}/${detail.obj.metadata.name}` });
      setDeleteOpen(false);
      closeDetail();
      load();
    } catch (e) {
      const err = e as ApiError;
      if (err.stepUpRequired) {
        setStepUpOpen(true);
        return;
      }
      const d = err.detail;
      notifications.show({ color: 'red',
        message: typeof d === 'string' ? d : String(err.message) });
    } finally {
      setBusy(false);
    }
  };

  const rows = (key: string, kind: string) => {
    const objs = (data?.[key] ?? [])
      .filter((o) => !hideSystem || !isSystem(o))
      .filter((o) => !filter
        || o.metadata.name.includes(filter)
        || (o.metadata.namespace ?? '').includes(filter)
        || (o.subjects ?? []).some((s) => s.name.includes(filter)));
    return objs.map((o) => {
      const worst = worstFinding(findings, o.metadata.name, kind);
      return (
        <Table.Tr key={`${kind}/${o.metadata.namespace ?? ''}/${o.metadata.name}`}
          style={{ cursor: 'pointer' }}
          onClick={() => { setEditRules(null); setEditSubjects(null); setDetail({ obj: o, kind }); }}>
          <Table.Td>{o.metadata.name}</Table.Td>
          <Table.Td>
            <Badge variant="light" radius="sm"
              color={kind.startsWith('Cluster') ? 'grape' : 'blue'}>
              {kind}
            </Badge>
          </Table.Td>
          <Table.Td>{o.metadata.namespace ?? '—'}</Table.Td>
          <Table.Td>
            {o.rules ? `${(o.rules ?? []).length} rules${o.aggregationRule ? ' (aggregated)' : ''}`
              : `${o.roleRef?.kind}/${o.roleRef?.name} ← ${(o.subjects ?? []).length} subjects`}
          </Table.Td>
          <Table.Td>{worst ? <SeverityBadge severity={worst.severity} /> :
            <Badge color="green" variant="light" radius="sm">✓ clean</Badge>}</Table.Td>
        </Table.Tr>
      );
    });
  };

  if (!active) {
    return (
      <Alert color="blue" mt="md">
        Select a cluster on the Clusters page to view live RBAC objects.
        Offline, use Import YAML in the Role Builder instead.
      </Alert>
    );
  }

  const isProd = active.environment === 'prod';

  return (
    <Stack mt="md">
      <Group justify="space-between">
        <Title order={3}>RBAC objects on {active.displayName || active.name}</Title>
        <Button variant="light" size="xs" onClick={load} loading={loading}>Refresh</Button>
      </Group>
      <Group>
        <TextInput placeholder="filter by name, namespace or subject" value={filter}
          onChange={(e) => setFilter(e.currentTarget.value)} style={{ flex: 1 }} />
        <Switch label="Hide system objects" checked={hideSystem}
          onChange={(e) => setHideSystem(e.currentTarget.checked)} />
      </Group>
      {error && <Alert color="red">{error}</Alert>}
      {loading && !data && <Loader />}
      {data && (
        <Tabs defaultValue="roles">
          <Tabs.List>
            <Tabs.Tab value="roles">Roles / ClusterRoles</Tabs.Tab>
            <Tabs.Tab value="bindings">Bindings</Tabs.Tab>
            <Tabs.Tab value="findings">
              Cluster lint ({findings.length})
            </Tabs.Tab>
          </Tabs.List>
          <Tabs.Panel value="roles" pt="xs">
            <SegmentedControl size="xs" mb="xs" value={roleKind}
              onChange={(v) => setRoleKind(v as typeof roleKind)}
              data={[
                { label: 'All', value: 'all' },
                { label: 'Roles', value: 'Role' },
                { label: 'ClusterRoles', value: 'ClusterRole' },
              ]} />
            <Table highlightOnHover>
              <Table.Thead><Table.Tr>
                <Table.Th>Name</Table.Th><Table.Th>Kind</Table.Th>
                <Table.Th>Namespace</Table.Th>
                <Table.Th>Rules</Table.Th><Table.Th>Risk</Table.Th>
              </Table.Tr></Table.Thead>
              <Table.Tbody>
                {roleKind !== 'ClusterRole' && rows('roles', 'Role')}
                {roleKind !== 'Role' && rows('clusterroles', 'ClusterRole')}
              </Table.Tbody>
            </Table>
          </Tabs.Panel>
          <Tabs.Panel value="bindings" pt="xs">
            <SegmentedControl size="xs" mb="xs" value={bindingKind}
              onChange={(v) => setBindingKind(v as typeof bindingKind)}
              data={[
                { label: 'All', value: 'all' },
                { label: 'RoleBindings', value: 'RoleBinding' },
                { label: 'ClusterRoleBindings', value: 'ClusterRoleBinding' },
              ]} />
            <Table highlightOnHover>
              <Table.Thead><Table.Tr>
                <Table.Th>Name</Table.Th><Table.Th>Kind</Table.Th>
                <Table.Th>Namespace</Table.Th>
                <Table.Th>roleRef / subjects</Table.Th><Table.Th>Risk</Table.Th>
              </Table.Tr></Table.Thead>
              <Table.Tbody>
                {bindingKind !== 'ClusterRoleBinding' && rows('rolebindings', 'RoleBinding')}
                {bindingKind !== 'RoleBinding' && rows('clusterrolebindings', 'ClusterRoleBinding')}
              </Table.Tbody>
            </Table>
          </Tabs.Panel>
          <Tabs.Panel value="findings" pt="xs">
            <FindingsList findings={findings} />
          </Tabs.Panel>
        </Tabs>
      )}

      <Drawer opened={!!detail && !editRules && !editSubjects} onClose={closeDetail} position="right"
        size="xl" title={detail ? `${detail.kind} ${detail.obj.metadata.name}` : ''}>
        {detail && !editRules && (
          <Stack>
            <FindingsList findings={findings.filter(
              (f) => f.object_name === detail.obj.metadata.name
                && f.object_kind === detail.kind)} />
            <Switch label="Show server-managed fields" checked={showManaged}
              onChange={(e) => setShowManaged(e.currentTarget.checked)} />
            <YamlPreview yaml={stringify(cleanForYaml(detail.obj, showManaged))}
              height={420} />
            <Group>
              {editable && (
                <Button size="xs" onClick={() =>
                  setEditRules((detail.obj.rules ?? [emptyRuleLike()]).map(toPolicyRule))}>
                  Edit rules
                </Button>
              )}
              {isRoleKind && !!detail.obj.aggregationRule && (
                <Text size="xs" c="dimmed">
                  Aggregated ClusterRole — its rules are combined by the
                  controller and cannot be edited directly.
                </Text>
              )}
              {isBindingKind && (
                <Button size="xs" onClick={() =>
                  setEditSubjects((detail.obj.subjects ?? []).map((s) => ({
                    kind: s.kind as Subject['kind'], name: s.name,
                    namespace: s.namespace ?? null,
                  })))}>
                  Edit subjects
                </Button>
              )}
              <Button size="xs" color="red" variant="light"
                onClick={() => { setDeleteConfirm(''); setDeleteOpen(true); }}>
                Delete…
              </Button>
            </Group>
            {isSystem(detail.obj) && (
              <Text size="xs" c="dimmed">
                ⚠ This is a system object — changing or deleting it can break
                the cluster.
              </Text>
            )}
          </Stack>
        )}
      </Drawer>

      {/* Builder-style editor in a modal, pre-filled from the live object. */}
      <Modal opened={!!detail && (!!editRules || !!editSubjects)}
        onClose={() => { setEditRules(null); setEditSubjects(null); }}
        size="90%" title={detail
          ? `Edit ${detail.kind} ${detail.obj.metadata.name}` : ''}>
        {detail && (editRules || editSubjects) && (
          <Grid>
            <Grid.Col span={{ base: 12, lg: 6 }}>
              {editRules && (
                <Stack gap="sm">
                  <SegmentedControl value={detail.kind} data={['Role', 'ClusterRole']}
                    readOnly />
                  <Group grow>
                    <TextInput label="Name" value={detail.obj.metadata.name} readOnly
                      description="the name cannot change — that would create a new object" />
                    {detail.kind === 'Role' && (
                      <TextInput label="Namespace"
                        value={detail.obj.metadata.namespace ?? ''} readOnly />
                    )}
                  </Group>
                  <RuleEditor rules={editRules} onChange={setEditRules}
                    catalog={catalog} clusterScope={detail.kind === 'ClusterRole'} />
                </Stack>
              )}
              {editSubjects && (
                <Stack gap="sm">
                  <SegmentedControl value={detail.kind}
                    data={['RoleBinding', 'ClusterRoleBinding']} readOnly />
                  <Group grow>
                    <TextInput label="Binding name" value={detail.obj.metadata.name}
                      readOnly
                      description="the name cannot change — that would create a new object" />
                    {detail.kind === 'RoleBinding' && (
                      <TextInput label="Namespace"
                        value={detail.obj.metadata.namespace ?? ''} readOnly />
                    )}
                  </Group>
                  <TextInput label="roleRef"
                    value={`${detail.obj.roleRef?.kind}/${detail.obj.roleRef?.name}`}
                    readOnly
                    description="roleRef is immutable in Kubernetes — to change it, delete and recreate the binding" />
                  <Text fw={600} size="sm">Subjects</Text>
                  {editSubjects.map((s, i) => (
                    <Paper key={i} withBorder p="xs">
                      <Group align="flex-end" gap="xs">
                        <Select w={150} label="Kind"
                          data={['User', 'Group', 'ServiceAccount']} value={s.kind}
                          onChange={(v) => updateSubject(i, {
                            kind: (v as Subject['kind']) ?? 'User',
                            namespace: v === 'ServiceAccount'
                              ? (s.namespace ?? 'default') : null })} />
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
                          onClick={() => setEditSubjects(
                            editSubjects.filter((_, k) => k !== i))}>✕</ActionIcon>
                      </Group>
                    </Paper>
                  ))}
                  <Button variant="light" size="xs"
                    onClick={() => setEditSubjects([...editSubjects,
                      { kind: 'User', name: '', namespace: null }])}>
                    + Add subject
                  </Button>
                  {!subjectsValid && (
                    <Text size="xs" c="dimmed">
                      Keep at least one named subject; ServiceAccount subjects
                      need a namespace.
                    </Text>
                  )}
                </Stack>
              )}
            </Grid.Col>
            <Grid.Col span={{ base: 12, lg: 6 }}>
              <Tabs defaultValue="yaml">
                <Tabs.List>
                  <Tabs.Tab value="yaml">YAML preview</Tabs.Tab>
                  <Tabs.Tab value="lint">
                    Linter {editPreview.findings.length ? `(${editPreview.findings.length})` : ''}
                  </Tabs.Tab>
                </Tabs.List>
                <Tabs.Panel value="yaml" pt="xs">
                  {editPreview.error && <Alert color="red" mb="xs">{editPreview.error}</Alert>}
                  <YamlPreview yaml={editPreview.yaml
                    || (editRules ? '# every rule needs verbs and resources'
                      : '# add at least one named subject')} height={420} />
                </Tabs.Panel>
                <Tabs.Panel value="lint" pt="xs">
                  <FindingsList findings={editPreview.findings} score={editPreview.score} />
                </Tabs.Panel>
              </Tabs>
              <Group justify="flex-end" mt="sm">
                <Button variant="default" size="xs"
                  onClick={() => { setEditRules(null); setEditSubjects(null); }}>
                  Cancel
                </Button>
                <ApplyToCluster bundle={editBundle}
                  disabled={(editRules ? !rulesValid : !subjectsValid) || !editPreview.yaml}
                  onApplied={() => { closeDetail(); load(); }} />
              </Group>
            </Grid.Col>
          </Grid>
        )}
      </Modal>

      <Modal opened={deleteOpen} onClose={() => setDeleteOpen(false)}
        title={`Delete ${detail?.kind} ${detail?.obj.metadata.name}`}>
        <Stack>
          <Text size="sm">
            This permanently deletes <Code>{detail?.kind}/{detail?.obj.metadata.name}</Code>
            {detail?.obj.metadata.namespace && <> in namespace <Code>{detail.obj.metadata.namespace}</Code></>}
            {' '}from <b>{active.displayName || active.name}</b>.
            {(detail?.kind === 'Role' || detail?.kind === 'ClusterRole')
              && ' Bindings that reference it will stop granting access.'}
          </Text>
          {isProd && (
            <TextInput label={`Type "${active.name}" to confirm (PROD cluster)`}
              value={deleteConfirm}
              onChange={(e) => setDeleteConfirm(e.currentTarget.value)} />
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setDeleteOpen(false)} data-autofocus>
              Cancel
            </Button>
            <Button color="red" loading={busy}
              disabled={isProd && deleteConfirm !== active.name}
              onClick={doDelete}>
              Delete
            </Button>
          </Group>
        </Stack>
      </Modal>

      <StepUpModal opened={stepUpOpen} onClose={() => setStepUpOpen(false)}
        onSuccess={doDelete} />
    </Stack>
  );
}

// A role with no rules yet still needs one editable row to start from.
function emptyRuleLike(): PolicyRule {
  return { apiGroups: [''], resources: [], verbs: [], resourceNames: [], nonResourceURLs: [] };
}
