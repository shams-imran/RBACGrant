import { useState } from 'react';
import { Alert, Autocomplete, Badge, Button, Group, SegmentedControl, Select,
  Stack, TextInput, Title } from '@mantine/core';
import { api } from '../api/client';
import { useCluster } from '../ClusterContext';
import { useDiscovery } from '../hooks';
import { showAllFilter } from '../components/pickers';

// SubjectAccessReview — the `kubectl auth can-i --as` equivalent.
export default function CanIPage() {
  const { active } = useCluster();
  const { discovery } = useDiscovery(active?.name);
  const [subjectType, setSubjectType] = useState<'user' | 'sa'>('user');
  const [user, setUser] = useState('');
  const [groups, setGroups] = useState('');
  const [saNamespace, setSaNamespace] = useState('default');
  const [saName, setSaName] = useState('');
  const [verb, setVerb] = useState<string | null>('get');
  const [resource, setResource] = useState('pods');
  const [apiGroup, setApiGroup] = useState('');
  const [namespace, setNamespace] = useState('');
  const [result, setResult] = useState<{ allowed: boolean; reason: string } | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  if (!active) {
    return <Alert color="blue" mt="md">Select a cluster to run can-i checks.</Alert>;
  }

  const run = async () => {
    setBusy(true);
    setError('');
    setResult(null);
    try {
      const r = await api<{ allowed: boolean; reason: string }>(
        `/api/clusters/${active.name}/can-i`, {
          method: 'POST',
          body: {
            user: subjectType === 'user' ? user : null,
            groups: subjectType === 'user' && groups
              ? groups.split(',').map((g) => g.trim()) : [],
            serviceAccount: subjectType === 'sa' ? `${saNamespace}:${saName}` : null,
            verb, resource, apiGroup, namespace: namespace || null, name: null,
          },
        });
      setResult(r);
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack mt="md" maw={720}>
      <Title order={3}>Can-I check on {active.displayName || active.name}</Title>
      <SegmentedControl value={subjectType}
        data={[{ value: 'user', label: 'User / Group' }, { value: 'sa', label: 'ServiceAccount' }]}
        onChange={(v) => setSubjectType(v as 'user' | 'sa')} />
      {subjectType === 'user' ? (
        <Group grow>
          <TextInput label="User" value={user} placeholder="alice"
            onChange={(e) => setUser(e.currentTarget.value)} />
          <TextInput label="Groups (comma-separated)" value={groups}
            placeholder="dev-team,qa" onChange={(e) => setGroups(e.currentTarget.value)} />
        </Group>
      ) : (
        <Group grow>
          <Autocomplete label="Namespace" value={saNamespace}
            data={discovery?.namespaces ?? []} limit={50} filter={showAllFilter}
            onChange={setSaNamespace} />
          <Autocomplete label="ServiceAccount" value={saName} placeholder="pick or type"
            data={[...new Set((discovery?.serviceAccounts ?? [])
              .filter((s) => !saNamespace || s.namespace === saNamespace)
              .map((s) => s.name))]}
            limit={50} filter={showAllFilter}
            onChange={setSaName} />
        </Group>
      )}
      <Group grow>
        <Select label="Verb" value={verb} searchable
          data={['get', 'list', 'watch', 'create', 'update', 'patch', 'delete',
            'deletecollection', 'impersonate', 'bind', 'escalate']}
          onChange={setVerb} />
        <Autocomplete label="Resource" value={resource}
          data={[...new Set((discovery?.groups ?? [])
            .flatMap((g) => g.resources.map((r) => r.name))
            .filter((n) => !n.includes('/')))].sort()}
          limit={50} filter={showAllFilter}
          onChange={setResource} />
        <Autocomplete label="API group (empty = core)" value={apiGroup}
          data={(discovery?.groups ?? []).map((g) => g.name).filter(Boolean).sort()}
          limit={50} filter={showAllFilter}
          onChange={setApiGroup} />
        <Autocomplete label="Namespace (empty = cluster-wide)" value={namespace}
          data={discovery?.namespaces ?? []} limit={50} filter={showAllFilter}
          onChange={setNamespace} />
      </Group>
      <Button onClick={run} loading={busy} w={200}>Check</Button>
      {error && <Alert color="red">{error}</Alert>}
      {result && (
        <Alert color={result.allowed ? 'green' : 'red'}
          title={
            <Badge size="lg" color={result.allowed ? 'green' : 'red'} variant="filled">
              {result.allowed ? '✓ ALLOWED' : '✕ DENIED'}
            </Badge>
          }>
          {result.reason || 'no reason returned by the API server'}
        </Alert>
      )}
    </Stack>
  );
}
