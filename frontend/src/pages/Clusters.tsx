import { useState } from 'react';
import { Alert, Badge, Button, Card, Code, FileButton, Group, Modal, Select, Stack,
  Stepper, Table, Text, TextInput, Textarea, Title } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { api, ApiError } from '../api/client';
import { ClusterMeta } from '../api/types';
import { useAuth } from '../AuthContext';
import { useCluster } from '../ClusterContext';
import { EnvBadge } from '../components/EnvBadge';
import { StepUpModal } from '../components/StepUpModal';

interface ValidateResult {
  contextsAvailable: string[];
  context: string;
  suggestedName: string;
  serverUrl: string;
  caSha256: string;
  credentialType: string;
  tlsVerified: boolean;
  execCommand?: string | null;
  execArgs?: string[];
  duplicateOf?: string | null;
}

function AddClusterWizard({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState(0);
  const [kubeconfig, setKubeconfig] = useState('');
  const [context, setContext] = useState<string | null>(null);
  const [validated, setValidated] = useState<ValidateResult | null>(null);
  const [name, setName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [environment, setEnvironment] = useState<ClusterMeta['environment']>('dev');
  const [description, setDescription] = useState('');
  const [publicApiUrl, setPublicApiUrl] = useState('');
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [dragOver, setDragOver] = useState(false);

  const loadFile = async (file: File | null) => {
    if (!file) return;
    try {
      setKubeconfig(await file.text());
    } catch {
      notifications.show({ color: 'red', message: `Cannot read ${file.name}` });
    }
  };

  const validate = async (chosen?: string | null) => {
    setBusy(true);
    try {
      const r = await api<ValidateResult>('/api/clusters/validate', {
        method: 'POST', body: { kubeconfig, context: chosen ?? context } });
      setValidated(r);
      setContext(r.context);
      if (!name) setName(r.suggestedName);
      setStep(1);
    } catch (e) {
      const err = e as ApiError;
      // Several contexts: the server asks us to pick one.
      if (err.status === 422 && String(err.detail).includes('several contexts')) {
        notifications.show({ color: 'blue', message: 'Pick a context below.' });
        setStep(1);
        setValidated(null);
      } else {
        notifications.show({ color: 'red', message: String(err.detail ?? err.message) });
      }
    } finally {
      setBusy(false);
    }
  };

  const save = async () => {
    setBusy(true);
    try {
      await api('/api/clusters', {
        method: 'POST',
        body: { kubeconfig, context, name, displayName, environment, description,
          publicApiUrl: publicApiUrl || null },
      });
      notifications.show({ color: 'green', message: `Cluster ${name} saved` });
      onDone();
    } catch (e) {
      const err = e as ApiError;
      if (err.stepUpRequired) {
        setStepUpOpen(true);
      } else {
        notifications.show({ color: 'red', message: String(err.detail ?? err.message) });
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack>
      <Stepper active={step} size="sm">
        <Stepper.Step label="Upload" description="paste kubeconfig">
          <Stack mt="md">
            <Alert color="blue" py={6}>
              Paste an admin kubeconfig (e.g. from ~/.kube/config on your machine),
              browse for the file, or drag and drop it below.
              It is validated as untrusted input and stored encrypted;
              it can never be viewed or downloaded again.
            </Alert>
            <Textarea minRows={10} autosize value={kubeconfig}
              styles={{ input: {
                fontFamily: 'var(--font-mono)',
                ...(dragOver && {
                  borderColor: 'var(--mantine-color-blue-6)',
                  borderStyle: 'dashed',
                }),
              } }}
              onChange={(e) => setKubeconfig(e.currentTarget.value)}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragOver(false);
                loadFile(e.dataTransfer.files?.[0] ?? null);
              }}
              placeholder="apiVersion: v1&#10;kind: Config&#10;...&#10;&#10;(or drag and drop a kubeconfig file here)" />
            <Group>
              <FileButton onChange={loadFile}>
                {(props) => <Button variant="default" {...props}>Browse file…</Button>}
              </FileButton>
              <Button onClick={() => validate()} loading={busy} disabled={!kubeconfig.trim()}>
                Validate
              </Button>
            </Group>
          </Stack>
        </Stepper.Step>
        <Stepper.Step label="Verify" description="context and identity">
          <Stack mt="md">
            {!validated && (
              <TextInput label="Context name (the file has several)"
                value={context ?? ''} onChange={(e) => setContext(e.currentTarget.value)}
                rightSection={<Button size="compact-xs" onClick={() => validate(context)}>Go</Button>} />
            )}
            {validated && (
              <>
                {validated.contextsAvailable.length > 1 && (
                  <Select label="Context" data={validated.contextsAvailable}
                    value={context} onChange={(v) => { setContext(v); validate(v); }} />
                )}
                <Table>
                  <Table.Tbody>
                    <Table.Tr><Table.Td>API server</Table.Td>
                      <Table.Td><Code>{validated.serverUrl}</Code></Table.Td></Table.Tr>
                    <Table.Tr><Table.Td>CA SHA-256</Table.Td>
                      <Table.Td><Code>{validated.caSha256.slice(0, 32)}…</Code></Table.Td></Table.Tr>
                    <Table.Tr><Table.Td>Credential</Table.Td>
                      <Table.Td>{validated.credentialType}</Table.Td></Table.Tr>
                  </Table.Tbody>
                </Table>
                {validated.execCommand && (
                  <Alert color="yellow" title="exec plugin">
                    This kubeconfig runs <Code>{validated.execCommand} {validated.execArgs?.join(' ')}</Code> on
                    the server, using the server's cloud identity.
                  </Alert>
                )}
                {!validated.tlsVerified && (
                  <Alert color="red" title="⚠ TLS not verified">
                    This cluster skips TLS verification and will carry a permanent warning badge.
                  </Alert>
                )}
                {validated.duplicateOf && (
                  <Alert color="yellow" py={6}>
                    Same server URL and CA fingerprint as cluster
                    “{validated.duplicateOf}”.
                  </Alert>
                )}
                <Button onClick={() => setStep(2)}>Continue</Button>
              </>
            )}
          </Stack>
        </Stepper.Step>
        <Stepper.Step label="Name & save" description="rename before saving">
          <Stack mt="md">
            <Group grow>
              <TextInput label="Name (DNS-1123, used in URLs)" value={name}
                onChange={(e) => setName(e.currentTarget.value.toLowerCase())} />
              <TextInput label="Display name" value={displayName}
                onChange={(e) => setDisplayName(e.currentTarget.value)} />
            </Group>
            <Group grow>
              <Select label="Environment" value={environment}
                data={['prod', 'staging', 'dev', 'other']}
                onChange={(v) => setEnvironment((v as ClusterMeta['environment']) ?? 'other')} />
              <TextInput label="Public API URL override (optional)"
                value={publicApiUrl} placeholder="https://k8s.example.com:6443"
                onChange={(e) => setPublicApiUrl(e.currentTarget.value)} />
            </Group>
            <TextInput label="Description" value={description}
              onChange={(e) => setDescription(e.currentTarget.value)} />
            <Button onClick={save} loading={busy} disabled={!name}>
              Save to encrypted store
            </Button>
          </Stack>
        </Stepper.Step>
      </Stepper>
      <StepUpModal opened={stepUpOpen} onClose={() => setStepUpOpen(false)}
        onSuccess={() => save()} />
    </Stack>
  );
}

interface CertRow {
  name: string; subject: string; issuer: string; notAfter: string; daysLeft: number;
}

function certColor(daysLeft: number): string {
  if (daysLeft < 30) return 'red';
  if (daysLeft < 90) return 'yellow';
  return 'green';
}

export default function ClustersPage() {
  const { clusters, active, setActive, reload } = useCluster();
  const { session } = useAuth();
  const [wizardOpen, setWizardOpen] = useState(false);
  const [certs, setCerts] = useState<Record<string, { rows: CertRow[]; errors: string[] }>>({});
  const [loadingCerts, setLoadingCerts] = useState<string | null>(null);

  const loadCerts = async (name: string) => {
    if (certs[name]) {
      setCerts(({ [name]: _, ...rest }) => rest); // toggle off
      return;
    }
    setLoadingCerts(name);
    try {
      const r = await api<{ certificates: CertRow[]; errors: string[] }>(
        `/api/clusters/${name}/certs`);
      setCerts((c) => ({ ...c, [name]: { rows: r.certificates, errors: r.errors } }));
    } catch (e) {
      const err = e as ApiError;
      notifications.show({ color: 'red', message: String(err.detail ?? err.message) });
    } finally {
      setLoadingCerts(null);
    }
  };
  const [deleting, setDeleting] = useState<ClusterMeta | null>(null);
  const [confirmName, setConfirmName] = useState('');
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [connecting, setConnecting] = useState<string | null>(null);
  const [connectError, setConnectError] =
    useState<{ cluster: string; message: string } | null>(null);

  const isAdmin = session?.role === 'admin';

  // Selecting a cluster first proves it is reachable; an unreachable cluster
  // is never set active.
  const selectCluster = async (c: ClusterMeta) => {
    if (active?.name === c.name) {
      setActive(null);
      return;
    }
    setConnecting(c.name);
    setConnectError(null);
    try {
      const r = await api<{ ok: boolean; version?: { gitVersion: string }; error?: string }>(
        `/api/clusters/${c.name}/test-connection`);
      if (r.ok) {
        setActive(c.name);
        notifications.show({ color: 'green',
          message: `Connected to ${c.displayName || c.name}`
            + (r.version?.gitVersion ? ` (${r.version.gitVersion})` : '') });
      } else {
        setConnectError({ cluster: c.displayName || c.name,
          message: r.error ?? 'connection failed' });
        notifications.show({ color: 'red',
          message: `Cannot connect to ${c.displayName || c.name}` });
      }
    } catch (e) {
      const err = e as ApiError;
      setConnectError({ cluster: c.displayName || c.name,
        message: String(err.detail ?? err.message) });
      notifications.show({ color: 'red',
        message: `Cannot connect to ${c.displayName || c.name}` });
    } finally {
      setConnecting(null);
    }
  };

  const doDelete = async () => {
    if (!deleting) return;
    try {
      await api(`/api/clusters/${deleting.name}/delete`, {
        method: 'POST', body: { confirmName } });
      notifications.show({ color: 'green', message: `Cluster ${deleting.name} deleted` });
      setDeleting(null);
      setConfirmName('');
      reload();
    } catch (e) {
      const err = e as ApiError;
      if (err.stepUpRequired) setStepUpOpen(true);
      else notifications.show({ color: 'red', message: String(err.detail ?? err.message) });
    }
  };

  return (
    <Stack mt="md">
      <Group justify="space-between">
        <Title order={3}>Clusters</Title>
        {isAdmin && (
          <Button onClick={() => setWizardOpen(true)}>+ Add cluster</Button>
        )}
      </Group>
      {connectError && (
        <Alert color="red" withCloseButton
          onClose={() => setConnectError(null)}
          title={`Cannot connect to ${connectError.cluster}`}
          styles={{
            root: {
              backgroundColor: 'var(--color-danger-subtle)',
              border: '1px solid var(--color-danger-subtle-border)',
            },
            title: { color: 'var(--color-danger)' },
          }}>
          {connectError.message} — the cluster was not selected.
        </Alert>
      )}
      {!clusters.length && (
        <Alert color="blue">
          No clusters registered. The app works offline as a pure generator;
          register a cluster to unlock discovery, dry-run, apply and can-i.
        </Alert>
      )}
      {clusters.map((c) => (
        <Card key={c.name} withBorder>
          <Group justify="space-between">
            <Group>
              <Text fw={600}>{c.displayName || c.name}</Text>
              <EnvBadge env={c.environment} />
              {c.managedByConfig && <Badge variant="light" color="gray">managed by config</Badge>}
              {!c.tlsVerified && <Badge color="red" variant="filled">⚠ TLS not verified</Badge>}
            </Group>
            <Group gap="xs">
              <Button size="xs" variant={active?.name === c.name ? 'filled' : 'light'}
                loading={connecting === c.name}
                disabled={!!connecting && connecting !== c.name}
                onClick={() => selectCluster(c)}>
                {active?.name === c.name ? 'Active'
                  : connecting === c.name ? 'Connecting…' : 'Select'}
              </Button>
              <Button size="xs" variant="default"
                loading={loadingCerts === c.name}
                onClick={() => loadCerts(c.name)}>
                {certs[c.name] ? 'Hide certificates' : '🔏 Certificates'}
              </Button>
              {isAdmin && !c.managedByConfig && (
                <Button size="xs" color="red" variant="outline"
                  onClick={() => setDeleting(c)}>
                  🗑 Delete cluster
                </Button>
              )}
            </Group>
          </Group>
          <Text size="xs" c="dimmed" mt={4}>
            <Code>{c.serverUrl}</Code> · CA {c.caSha256.slice(0, 16)}… ·
            credential: {c.credentialType} · store: {c.storeBackend}
          </Text>
          {certs[c.name] && (
            <>
              <Table mt="sm" withTableBorder>
                <Table.Thead><Table.Tr>
                  <Table.Th>Certificate</Table.Th>
                  <Table.Th>Subject</Table.Th>
                  <Table.Th>Expires</Table.Th>
                  <Table.Th>Residual time</Table.Th>
                </Table.Tr></Table.Thead>
                <Table.Tbody>
                  {certs[c.name].rows.map((r) => (
                    <Table.Tr key={r.name}>
                      <Table.Td>{r.name}</Table.Td>
                      <Table.Td><Code>{r.subject}</Code></Table.Td>
                      <Table.Td>{new Date(r.notAfter).toLocaleString()}</Table.Td>
                      <Table.Td>
                        <Badge variant="light" color={certColor(r.daysLeft)}>
                          {r.daysLeft}d
                        </Badge>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
              {certs[c.name].errors.map((e, i) => (
                <Text size="xs" c="dimmed" key={i}>⚠ {e}</Text>
              ))}
            </>
          )}
        </Card>
      ))}

      <Modal opened={wizardOpen} onClose={() => setWizardOpen(false)}
        title="Add cluster" size="xl">
        <AddClusterWizard onDone={() => { setWizardOpen(false); reload(); }} />
      </Modal>

      <Modal opened={!!deleting} onClose={() => setDeleting(null)}
        title={`Delete cluster ${deleting?.name}`}>
        <Stack>
          <Alert color="red">
            This destroys every stored credential version for this cluster.
            Type the cluster name to confirm.
          </Alert>
          <TextInput value={confirmName} placeholder={deleting?.name}
            onChange={(e) => setConfirmName(e.currentTarget.value)} />
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setDeleting(null)} data-autofocus>
              Cancel
            </Button>
            <Button color="red" disabled={confirmName !== deleting?.name} onClick={doDelete}>
              🗑 Delete cluster
            </Button>
          </Group>
        </Stack>
      </Modal>
      <StepUpModal opened={stepUpOpen} onClose={() => setStepUpOpen(false)}
        onSuccess={doDelete} />
    </Stack>
  );
}
