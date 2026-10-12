// All-in-one page: pick the scope (Role/ClusterRole + RoleBinding/
// ClusterRoleBinding), build a new role or bind an existing one, choose the
// subject (creating the ServiceAccount in the same bundle when needed), then
// download the YAML or apply it to the active cluster. After a successful
// apply the kubeconfig for the subject is generated automatically (SA token,
// or a user cert generated in the browser).
import { useMemo, useState } from 'react';
import { Alert, Autocomplete, Button, Code, Divider, Grid, Group,
  Loader, Modal, SegmentedControl, Select, Stack, Switch, Tabs, TagsInput,
  Text, TextInput, Textarea, Title } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { api, ApiError, apiBlob, downloadBlob } from '../api/client';
import { Bundle, PolicyRule, Subject, emptyBundle, emptyRule } from '../api/types';
import { useCluster } from '../ClusterContext';
import { FindingsList } from '../components/Findings';
import { RuleEditor } from '../components/RuleEditor';
import { StepUpModal } from '../components/StepUpModal';
import { YamlPreview } from '../components/YamlPreview';
import { liveCatalog, useAppConfig, useCatalog, useDiscovery, usePreview } from '../hooks';
import { ExpiryPicker, defaultExpiry, expiryError, expiryRequest } from '../components/ExpiryPicker';
import { showAllFilter } from '../components/pickers';
import { assembleUserKubeconfig, generateKeyAndCsr, webCryptoAvailable } from '../crypto/csr';

interface GuardrailDecision {
  allowed: boolean;
  hard_blocks: string[];
  override_required: string[];
}

interface ApplyResult {
  kind?: string; name?: string; namespace?: string; warning?: string;
}

type RoleKind = 'Role' | 'ClusterRole';
type BindingKind = 'RoleBinding' | 'ClusterRoleBinding';

const BUILT_IN_CLUSTER_ROLES = ['view', 'edit', 'admin', 'cluster-admin'];

export default function GrantAccessPage() {
  const { active } = useCluster();
  const offlineCatalog = useCatalog();
  const { discovery, loading: discovering, error: discoveryError } =
    useDiscovery(active?.name);

  // --- form state ---
  const [roleKind, setRoleKind] = useState<RoleKind>('Role');
  const [bindingKind, setBindingKind] = useState<BindingKind>('RoleBinding');
  const [roleSource, setRoleSource] = useState<'new' | 'existing'>('new');
  const [namespace, setNamespace] = useState('');
  // ClusterRole + RoleBinding grants across N namespaces (one
  // RoleBinding each); only that combo is multi-namespace.
  const [bindingNamespaces, setBindingNamespaces] = useState<string[]>([]);
  const [roleName, setRoleName] = useState('');
  const [existingRole, setExistingRole] = useState('');
  const [rules, setRules] = useState<PolicyRule[]>([emptyRule()]);
  const [subjectKind, setSubjectKind] = useState<Subject['kind']>('User');
  const [subjectName, setSubjectName] = useState('');
  const [createSa, setCreateSa] = useState(true);

  // --- apply state ---
  const [applyOpen, setApplyOpen] = useState(false);
  const [confirmName, setConfirmName] = useState('');
  const [overrideReason, setOverrideReason] = useState('');
  const [guardrails, setGuardrails] = useState<GuardrailDecision | null>(null);
  const [dryRunResults, setDryRunResults] = useState<ApplyResult[] | null>(null);
  const [applied, setApplied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [retry, setRetry] = useState<(() => void) | null>(null);

  // --- kubeconfig state ---
  const [autoKubeconfig, setAutoKubeconfig] = useState(true);
  const [expiry, setExpiry] = useState(defaultExpiry(8));
  const [kubeconfigDone, setKubeconfigDone] = useState('');
  const appConfig = useAppConfig();

  const catalog = liveCatalog(discovery) ?? discovery?.catalog ?? offlineCatalog;
  const namespaces = discovery?.namespaces ?? [];

  // --- kind constraints: a ClusterRoleBinding can only reference a
  // ClusterRole; a Role can only be referenced by a RoleBinding. ---
  const changeRoleKind = (v: RoleKind) => {
    setRoleKind(v);
    if (v === 'Role') setBindingKind('RoleBinding');
    setExistingRole('');
    resetApplyState();
  };
  const changeBindingKind = (v: BindingKind) => {
    setBindingKind(v);
    if (v === 'ClusterRoleBinding') {
      setRoleKind('ClusterRole');
      setExistingRole('');
    }
    resetApplyState();
  };

  // The namespace matters for: the Role itself, the RoleBinding, and a
  // ServiceAccount subject. Only ClusterRole + ClusterRoleBinding + User/Group
  // can skip it entirely.
  const needsNamespace = bindingKind === 'RoleBinding'
    || subjectKind === 'ServiceAccount' || roleKind === 'Role';
  // "2 · Where" is only about the Role/RoleBinding scope. A cluster-wide grant
  // to a ServiceAccount asks for the SA's home namespace in step 4 instead.
  const whereNeeded = bindingKind === 'RoleBinding' || roleKind === 'Role';
  const multiNs = roleKind === 'ClusterRole' && bindingKind === 'RoleBinding';
  const chosenBindingNs = bindingNamespaces.map((n) => n.trim()).filter(Boolean);

  const effectiveRoleName = roleSource === 'new' ? roleName : existingRole;
  const saExists = useMemo(
    () => (discovery?.serviceAccounts ?? []).some(
      (s) => s.name === subjectName && s.namespace === namespace),
    [discovery, subjectName, namespace]);

  // Existing-role picker fed from cluster discovery.
  const existingRoleOptions = useMemo(() => {
    if (roleKind === 'ClusterRole') {
      const live = (discovery?.clusterRoles ?? []).filter((r) => !r.startsWith('system:'));
      const unique = [...new Set(live)].filter((r) => !BUILT_IN_CLUSTER_ROLES.includes(r));
      return [
        ...BUILT_IN_CLUSTER_ROLES.map((r) => ({ value: r, label: `${r} (built-in)` })),
        ...unique.sort().map((r) => ({ value: r, label: r })),
      ];
    }
    const inNs = (discovery?.roles ?? [])
      .filter((r) => !namespace || r.namespace === namespace)
      .map((r) => r.name);
    return [...new Set(inNs)].sort().map((r) => ({ value: r, label: r }));
  }, [discovery, roleKind, namespace]);

  const existingRoleMissing = roleSource === 'existing' && roleKind === 'Role'
    && !!existingRole && !!namespace && !!discovery
    && !discovery.roles.some((r) => r.name === existingRole && r.namespace === namespace);

  const bindingName = effectiveRoleName ? `${effectiveRoleName}-binding` : '';
  const rulesReady = rules.some((r) => r.verbs.length && (r.resources.length || r.nonResourceURLs.length));
  const roleReady = roleSource === 'new' ? !!(roleName && rulesReady) : !!existingRole;
  // Multi-ns mode needs at least one binding namespace, plus the SA's own
  // namespace when the subject is a ServiceAccount.
  const nsReady = multiNs
    ? chosenBindingNs.length > 0 && (subjectKind !== 'ServiceAccount' || !!namespace)
    : (!needsNamespace || !!namespace);
  const formReady = roleReady && !!subjectName && nsReady;

  const bundle: Bundle = useMemo(() => {
    if (!formReady) return emptyBundle();
    const b = emptyBundle();
    if (roleSource === 'new') {
      b.roles = [{
        kind: roleKind,
        metadata: {
          name: roleName,
          namespace: roleKind === 'Role' ? namespace : null,
          labels: {}, annotations: {},
        },
        rules,
      }];
    }
    b.bindings = [{
      kind: bindingKind,
      name: bindingName,
      namespaces: bindingKind === 'RoleBinding'
        ? (multiNs ? chosenBindingNs : [namespace]) : [],
      labels: {}, annotations: {},
      roleRef: { kind: roleKind, name: effectiveRoleName },
      subjects: [{
        kind: subjectKind, name: subjectName,
        namespace: subjectKind === 'ServiceAccount' ? namespace : null,
      }],
    }];
    if (subjectKind === 'ServiceAccount' && createSa && !saExists) {
      b.serviceAccounts = [{
        name: subjectName, namespace, labels: {}, annotations: {},
        automountServiceAccountToken: false,
      }];
    }
    return b;
  }, [formReady, roleSource, roleKind, bindingKind, roleName, effectiveRoleName,
      namespace, chosenBindingNs.join(','), multiNs, JSON.stringify(rules),
      subjectKind, subjectName, createSa, saExists, bindingName]);

  const preview = usePreview(bundle);

  const resetApplyState = () => {
    setApplied(false);
    setDryRunResults(null);
    setKubeconfigDone('');
  };

  const handleError = (e: unknown, retryFn: () => void) => {
    const err = e as ApiError;
    if (err.stepUpRequired) {
      setRetry(() => retryFn);
      setStepUpOpen(true);
      return;
    }
    const d = err.detail as { hardBlocks?: string[]; overrideRequired?: string[];
      message?: string } | string;
    if (typeof d === 'object' && d?.hardBlocks) {
      notifications.show({ color: 'red', title: 'Hard-blocked',
        message: d.hardBlocks.join('; ') });
    } else if (typeof d === 'object' && d?.overrideRequired) {
      notifications.show({ color: 'yellow', title: 'Override required',
        message: `${d.message}: type a reason in the apply dialog` });
    } else {
      notifications.show({ color: 'red',
        message: typeof d === 'string' ? d : (d?.message ?? String(err.message)) });
    }
  };

  const downloadYaml = async () => {
    try {
      const blob = await apiBlob('/api/export/yaml', bundle);
      downloadBlob(blob, `${effectiveRoleName}-${namespace || 'cluster'}.yaml`);
    } catch (e) {
      handleError(e, downloadYaml);
    }
  };

  const openApply = async () => {
    resetApplyState();
    setConfirmName('');
    setOverrideReason('');
    try {
      const d = await api<GuardrailDecision>('/api/guardrails',
        { method: 'POST', body: bundle });
      setGuardrails(d);
      setApplyOpen(true);
    } catch (e) {
      handleError(e, openApply);
    }
  };

  const maxTtl = (subjectKind === 'ServiceAccount'
    ? appConfig?.maxTokenTtlSeconds
    : appConfig?.maxCertTtlSeconds) ?? 0;
  const kubeconfigPossible = subjectKind === 'ServiceAccount' || subjectKind === 'User';

  const downloadSaKubeconfig = async () => {
    if (!active) return;
    setBusy(true);
    try {
      const r = await api<{ kubeconfig: string; filename: string; expiresAt: string }>(
        `/api/clusters/${active.name}/kubeconfig/serviceaccount`, {
          method: 'POST',
          body: { namespace, serviceAccount: subjectName, ...expiryRequest(expiry) },
        });
      downloadBlob(new Blob([r.kubeconfig], { type: 'application/yaml' }), r.filename);
      setKubeconfigDone(`${r.filename} (expires ${r.expiresAt})`);
      notifications.show({ color: 'green', message: `Kubeconfig downloaded: ${r.filename}` });
    } catch (e) {
      handleError(e, downloadSaKubeconfig);
    } finally {
      setBusy(false);
    }
  };

  const downloadUserKubeconfig = async () => {
    if (!active) return;
    setBusy(true);
    try {
      if (!webCryptoAvailable()) {
        throw new Error('WebCrypto unavailable — serve over https:// or http://127.0.0.1');
      }
      const { csrPem, privateKeyPem } = await generateKeyAndCsr(subjectName, []);
      const r = await api<{ certificatePem: string; expiresAt: string; filename: string;
        clusterDetails: { clusterName: string; serverUrl: string; caDataB64: string } }>(
        `/api/clusters/${active.name}/kubeconfig/user-csr`, {
          method: 'POST',
          body: { commonName: subjectName, groups: [], csrPem,
            ...expiryRequest(expiry), defaultNamespace: namespace || 'default' },
        });
      const kubeconfig = assembleUserKubeconfig({
        ...r.clusterDetails, userName: subjectName, certPem: r.certificatePem,
        keyPem: privateKeyPem, defaultNamespace: namespace || 'default',
        expiresAt: r.expiresAt,
      });
      downloadBlob(new Blob([kubeconfig], { type: 'application/yaml' }), r.filename);
      setKubeconfigDone(`${r.filename} (expires ${r.expiresAt})`);
      notifications.show({ color: 'green', message: `Kubeconfig downloaded: ${r.filename}` });
    } catch (e) {
      handleError(e, downloadUserKubeconfig);
    } finally {
      setBusy(false);
    }
  };

  const generateKubeconfig = () => (subjectKind === 'ServiceAccount'
    ? downloadSaKubeconfig() : downloadUserKubeconfig());

  const runApply = async (dryRun: boolean) => {
    if (!active) return;
    setBusy(true);
    try {
      const r = await api<{ dryRun: boolean; results: ApplyResult[] }>(
        `/api/clusters/${active.name}/apply`, {
          method: 'POST',
          body: {
            bundle, dryRun,
            confirmClusterName: confirmName || null,
            overrideReason: overrideReason || null,
          },
        });
      if (dryRun) {
        setDryRunResults(r.results);
        notifications.show({ color: 'green', message: 'Dry-run passed on the server' });
      } else {
        setApplied(true);
        setApplyOpen(false);
        notifications.show({ color: 'green',
          message: `Applied ${r.results.length} object(s) to ${active.name}` });
        // Auto-generate the kubeconfig right after a successful apply.
        if (autoKubeconfig && kubeconfigPossible && !expiryError(expiry, maxTtl, discovery?.caNotAfter)) {
          setBusy(false);
          await generateKubeconfig();
          return;
        }
      }
    } catch (e) {
      handleError(e, () => runApply(dryRun));
    } finally {
      setBusy(false);
    }
  };

  const isProd = active?.environment === 'prod';
  const needsReason = !!guardrails && guardrails.override_required.length > 0;
  const hardBlocked = !!guardrails && guardrails.hard_blocks.length > 0;
  const applyDisabled = busy || hardBlocked
    || (isProd && confirmName !== active?.name)
    || (needsReason && !overrideReason.trim());

  return (
    <Stack mt="md">
      <Group justify="space-between">
        <Title order={3}>Grant access</Title>
        {active ? (
          <Group gap="xs">
            {discovering && <Loader size="xs" />}
            <Text size="sm" c="dimmed">
              cluster: {active.displayName || active.name}
              {discovery && ` · K8s ${discovery.version.minor} · ${namespaces.length} namespaces`}
            </Text>
          </Group>
        ) : (
          <Text size="sm" c="dimmed">no cluster selected — YAML download only</Text>
        )}
      </Group>
      {discoveryError && (
        <Alert color="red" py={6}>Discovery failed: {discoveryError}</Alert>
      )}

      <Grid>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Stack gap="sm">
            <Text fw={600}>1 · Scope</Text>
            <Group grow>
              <Select label="Role kind" value={roleKind}
                data={['Role', 'ClusterRole']}
                onChange={(v) => changeRoleKind((v as RoleKind) ?? 'Role')} />
              <Select label="Binding kind" value={bindingKind}
                data={[
                  { value: 'RoleBinding', label: 'RoleBinding' },
                  { value: 'ClusterRoleBinding', label: 'ClusterRoleBinding',
                    disabled: roleKind === 'Role' },
                ]}
                onChange={(v) => changeBindingKind((v as BindingKind) ?? 'RoleBinding')} />
            </Group>
            <Text size="xs" c="dimmed">
              {roleKind === 'Role'
                ? 'Role + RoleBinding: access inside one namespace.'
                : bindingKind === 'RoleBinding'
                  ? 'ClusterRole + RoleBinding: a reusable ClusterRole, granted only inside the chosen namespaces (one RoleBinding each).'
                  : 'ClusterRole + ClusterRoleBinding: cluster-wide access — use with care.'}
            </Text>
            {bindingKind === 'ClusterRoleBinding' && (
              <Alert color="yellow" py={6}>
                Does this really need cluster-wide scope? A RoleBinding per
                namespace is usually narrower.
              </Alert>
            )}

            {whereNeeded && (
              <>
                <Text fw={600}>2 · Where</Text>
                {multiNs ? (
                  <TagsInput label="Namespaces (several = one RoleBinding each)"
                    value={bindingNamespaces}
                    onChange={(v) => {
                      setBindingNamespaces(v.map((n) => n.toLowerCase()));
                      resetApplyState();
                    }}
                    data={namespaces} placeholder="add one or more namespaces" />
                ) : (
                  <Autocomplete label="Namespace" data={namespaces} value={namespace}
                    placeholder={namespaces.length ? 'pick or type a namespace' : 'type a namespace'}
                    onChange={(v) => { setNamespace(v.toLowerCase()); resetApplyState(); }}
                    limit={50} filter={showAllFilter} />
                )}
              </>
            )}

            <Text fw={600}>3 · What (the {roleKind})</Text>
            <SegmentedControl value={roleSource} fullWidth
              data={[
                { value: 'new', label: `Build a new ${roleKind}` },
                { value: 'existing', label: `Bind an existing ${roleKind}` },
              ]}
              onChange={(v) => { setRoleSource(v as 'new' | 'existing'); resetApplyState(); }} />
            {roleSource === 'new' ? (
              <>
                <TextInput label={`${roleKind} name`} value={roleName} placeholder="app-deployer"
                  onChange={(e) => { setRoleName(e.currentTarget.value.toLowerCase()); resetApplyState(); }} />
                <RuleEditor rules={rules} onChange={(r) => { setRules(r); resetApplyState(); }}
                  catalog={catalog} clusterScope={roleKind === 'ClusterRole'} />
              </>
            ) : (
              <>
                <Select label={`${roleKind} name`} searchable value={existingRole || null}
                  data={existingRoleOptions}
                  onChange={(v) => { setExistingRole(v ?? ''); resetApplyState(); }}
                  onSearchChange={(v) => { if (v) setExistingRole(v); }}
                  placeholder={active
                    ? `pick a ${roleKind} from the cluster or type a name`
                    : 'type a name (no cluster selected)'}
                  nothingFoundMessage="nothing found — type a name"
                  limit={30} />
                {existingRoleMissing && (
                  <Alert color="yellow" py={6}>
                    Role <b>{existingRole}</b> does not exist in namespace{' '}
                    <b>{namespace}</b> on the cluster — the binding would
                    reference a missing Role until you create it.
                  </Alert>
                )}
              </>
            )}

            <Text fw={600}>4 · Who (the {bindingKind})</Text>
            <Group grow>
              <Select label="Subject kind" value={subjectKind}
                data={['User', 'Group', 'ServiceAccount']}
                onChange={(v) => { setSubjectKind((v as Subject['kind']) ?? 'User'); resetApplyState(); }} />
              {subjectKind === 'ServiceAccount' && (!whereNeeded || multiNs) && (
                <Autocomplete label="SA namespace" value={namespace}
                  placeholder={namespaces.length ? 'pick or type' : 'type a namespace'}
                  data={namespaces} limit={50} filter={showAllFilter}
                  onChange={(v) => { setNamespace(v.toLowerCase()); resetApplyState(); }} />
              )}
              {subjectKind === 'ServiceAccount' ? (
                <Autocomplete label="Subject name" value={subjectName}
                  placeholder="pick an existing SA or type a new one"
                  data={[...new Set((discovery?.serviceAccounts ?? [])
                    .filter((sa) => !namespace || sa.namespace === namespace)
                    .map((sa) => sa.name))]}
                  limit={50} filter={showAllFilter}
                  onChange={(v) => { setSubjectName(v); resetApplyState(); }} />
              ) : (
                <TextInput label="Subject name" value={subjectName}
                  placeholder={subjectKind === 'Group' ? 'dev-team' : 'jane.doe'}
                  onChange={(e) => { setSubjectName(e.currentTarget.value); resetApplyState(); }} />
              )}
            </Group>
            {subjectKind === 'ServiceAccount' && (!whereNeeded || multiNs) && (
              <Text size="xs" c="dimmed">
                The SA namespace is only where the ServiceAccount lives — the
                {multiNs ? ' RoleBindings grant access in the namespaces chosen above' : ' ClusterRoleBinding still grants cluster-wide access'}.
              </Text>
            )}
            {subjectKind === 'ServiceAccount' && (
              saExists ? (
                <Alert color="blue" py={6}>
                  ServiceAccount <Code>{namespace}/{subjectName}</Code> already
                  exists on the cluster — it will be bound as-is.
                </Alert>
              ) : (
                <Switch label={`Create ServiceAccount ${namespace || '?'}/${subjectName || '?'} in the same bundle`}
                  checked={createSa}
                  onChange={(e) => { setCreateSa(e.currentTarget.checked); resetApplyState(); }} />
              )
            )}
            {subjectKind !== 'ServiceAccount' && (
              <Text size="xs" c="dimmed">
                Binding name: <Code>{bindingName || '…'}</Code>. Prefer Groups
                over individual Users where you can.
              </Text>
            )}

            <Text fw={600}>5 · Kubeconfig</Text>
            {kubeconfigPossible ? (
              <>
                <Group align="flex-end" gap="xs">
                  <Switch label="Generate kubeconfig automatically after apply"
                    checked={autoKubeconfig}
                    onChange={(e) => setAutoKubeconfig(e.currentTarget.checked)} />
                  <ExpiryPicker label="Expiry" value={expiry}
                    onChange={setExpiry} maxSeconds={maxTtl}
                    caNotAfter={discovery?.caNotAfter}
                    serverCertNotAfter={discovery?.apiServerCertNotAfter} />
                </Group>
                {subjectKind === 'User' && (
                  <Text size="xs" c="dimmed">
                    The private key is generated in your browser and never sent
                    to the server.
                  </Text>
                )}
              </>
            ) : (
              <Text size="sm" c="dimmed">
                Group subjects get access through their identity provider —
                there is no kubeconfig to issue for a group.
              </Text>
            )}
          </Stack>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Tabs defaultValue="yaml">
            <Tabs.List>
              <Tabs.Tab value="yaml">YAML</Tabs.Tab>
              <Tabs.Tab value="lint">
                Linter {preview.findings.length ? `(${preview.findings.length})` : ''}
              </Tabs.Tab>
            </Tabs.List>
            <Tabs.Panel value="yaml" pt="xs">
              {preview.error && <Alert color="red" mb="xs">{preview.error}</Alert>}
              <YamlPreview yaml={preview.yaml || '# fill in the scope, role, rules and subject'}
                height={420} />
            </Tabs.Panel>
            <Tabs.Panel value="lint" pt="xs">
              <FindingsList findings={preview.findings} score={preview.score} />
            </Tabs.Panel>
          </Tabs>

          <Divider my="sm" />
          <Group>
            <Button variant="light" disabled={!formReady || !preview.yaml}
              onClick={downloadYaml}>Download YAML</Button>
            <Button disabled={!formReady || !preview.yaml || !active}
              onClick={openApply}>
              Apply to {active ? (active.displayName || active.name) : 'cluster'}…
            </Button>
          </Group>

          {applied && (
            <Alert color="green" mt="sm" title="✓ Applied">
              <Stack gap="xs">
                <Text size="sm">
                  The {roleSource === 'new' ? `${roleKind}, ` : ''}{bindingKind}
                  {bundle.serviceAccounts.length ? ' and ServiceAccount' : ''} are
                  live on <b>{active?.displayName || active?.name}</b>.
                </Text>
                {kubeconfigPossible && (
                  <Group align="flex-end" gap="xs">
                    <ExpiryPicker label="Kubeconfig expiry" value={expiry}
                      onChange={setExpiry} maxSeconds={maxTtl}
                      caNotAfter={discovery?.caNotAfter}
                    serverCertNotAfter={discovery?.apiServerCertNotAfter} />
                    <Button loading={busy}
                      disabled={!!expiryError(expiry, maxTtl, discovery?.caNotAfter)}
                      onClick={generateKubeconfig}>
                      {kubeconfigDone ? 'Download again' : `Download kubeconfig for ${subjectName}`}
                    </Button>
                  </Group>
                )}
                {kubeconfigDone && (
                  <Text size="sm">Downloaded once, not stored: <Code>{kubeconfigDone}</Code></Text>
                )}
              </Stack>
            </Alert>
          )}
        </Grid.Col>
      </Grid>

      <Modal opened={applyOpen} onClose={() => setApplyOpen(false)} size="lg"
        title={`Apply to ${active?.displayName || active?.name}`}>
        <Stack>
          {isProd && (
            <Alert color="red" title="PROD cluster" py={6}>
              This is a production cluster. Type its name to confirm.
            </Alert>
          )}
          {hardBlocked && (
            <Alert color="red" title="⛔ Hard-blocked (no override)">
              {guardrails!.hard_blocks.map((h, i) => <Text size="sm" key={i}>{h}</Text>)}
            </Alert>
          )}
          {needsReason && !hardBlocked && (
            <Alert color="yellow" title="⚠ Guardrail override required (admin)">
              {guardrails!.override_required.map((o, i) => <Text size="sm" key={i}>{o}</Text>)}
              <Textarea mt="xs" label="Reason (written to the audit log)"
                value={overrideReason}
                onChange={(e) => setOverrideReason(e.currentTarget.value)} />
            </Alert>
          )}
          {isProd && (
            <TextInput label={`Type "${active?.name}" to confirm`} value={confirmName}
              onChange={(e) => setConfirmName(e.currentTarget.value)} />
          )}
          {dryRunResults && (
            <Alert color="green" py={6}>
              Dry-run OK: {dryRunResults.filter((r) => r.kind)
                .map((r) => `${r.kind}/${r.name}`).join(', ')}
            </Alert>
          )}
          {autoKubeconfig && kubeconfigPossible && (
            <Text size="xs" c="dimmed">
              After apply, the kubeconfig for <Code>{subjectName}</Code> will be
              generated and downloaded automatically.
            </Text>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setApplyOpen(false)} data-autofocus>
              Cancel
            </Button>
            <Button variant="light" loading={busy} disabled={hardBlocked}
              onClick={() => runApply(true)}>Dry-run first</Button>
            <Button color={isProd ? 'red' : undefined} loading={busy}
              disabled={applyDisabled} onClick={() => runApply(false)}>
              {isProd ? '⚠ Apply to PROD' : 'Apply'}
            </Button>
          </Group>
        </Stack>
      </Modal>

      <StepUpModal opened={stepUpOpen} onClose={() => setStepUpOpen(false)}
        onSuccess={() => retry?.()} />
    </Stack>
  );
}
