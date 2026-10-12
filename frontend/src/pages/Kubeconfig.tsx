import { useState } from 'react';
import { Alert, Autocomplete, Button, Code, Grid, Group, SegmentedControl,
  Stack, TagsInput, Text, TextInput, Title } from '@mantine/core';
import { YamlPreview } from '../components/YamlPreview';
import { notifications } from '@mantine/notifications';
import { api, ApiError, downloadBlob } from '../api/client';
import { useCluster } from '../ClusterContext';
import { assembleUserKubeconfig, generateKeyAndCsr, webCryptoAvailable } from '../crypto/csr';
import { StepUpModal } from '../components/StepUpModal';
import { useAppConfig, useDiscovery } from '../hooks';
import { showAllFilter } from '../components/pickers';
import { Expiry, ExpiryPicker, defaultExpiry, expiryError, expiryRequest } from '../components/ExpiryPicker';

// The full manual recipe the "Generate" button automates (the button does the
// key + CSR in the browser; here every step is explicit kubectl/openssl).
function userCertGuide(userName: string, groups: string[],
  expiry: Expiry, clusterName: string, serverUrl: string): string {
  const user = userName || '<username>';
  const subj = `/CN=${user}${groups.map((g) => `/O=${g}`).join('')}`;
  const seconds = expiry.mode === 'hours'
    ? String(Math.round(expiry.hours * 3600))
    : expiry.mode === 'date' && expiry.until
      ? String(Math.max(600, Math.round((new Date(expiry.until).getTime() - Date.now()) / 1000)))
      : '<ttl-seconds>';
  return `# ── Manual steps to issue a kubeconfig for user ${user} ──
# (the Generate button automates all of this; the key stays in your browser)

# 1 · Generate a private key
openssl genrsa -out ${user}.key 2048

# 2 · Create a CSR — CN becomes the username, each O a group
openssl req -new -key ${user}.key -out ${user}.csr \\
  -subj "${subj}"

# 3 · Submit it to Kubernetes as a CertificateSigningRequest
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ${user}-csr
spec:
  request: $(base64 < ${user}.csr | tr -d '\\n')
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: ${seconds}
  usages: ["client auth"]
EOF

# 4 · Approve it (needs the "approve" verb on signers)
kubectl certificate approve ${user}-csr

# 5 · Fetch the signed certificate (issued by the cluster CA)
kubectl get csr ${user}-csr \\
  -o jsonpath='{.status.certificate}' | base64 -d > ${user}.crt

# 6 · Get the cluster CA certificate
kubectl config view --raw --minify \\
  -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' \\
  | base64 -d > ca.crt

# 7 · Assemble the kubeconfig
kubectl config set-cluster ${clusterName} --server=${serverUrl} \\
  --certificate-authority=ca.crt --embed-certs \\
  --kubeconfig=${user}.kubeconfig
kubectl config set-credentials ${user} --client-certificate=${user}.crt \\
  --client-key=${user}.key --embed-certs --kubeconfig=${user}.kubeconfig
kubectl config set-context ${user}@${clusterName} --cluster=${clusterName} \\
  --user=${user} --kubeconfig=${user}.kubeconfig
kubectl config use-context ${user}@${clusterName} --kubeconfig=${user}.kubeconfig

# 8 · Clean up the CSR object and test
kubectl delete csr ${user}-csr
KUBECONFIG=${user}.kubeconfig kubectl auth whoami   # Username: ${user}
rm ${user}.csr   # key+crt are embedded in the kubeconfig now

# 9 · The user has NO permissions yet — bind a role (Grant Access page), or:
kubectl create rolebinding ${user}-edit --clusterrole=edit \\
  --user=${user} -n <namespace>

# Client certs cannot be revoked — to cut access, remove the bindings.`;
}

export default function KubeconfigPage() {
  const { active } = useCluster();
  const { discovery } = useDiscovery(active?.name);
  const [mode, setMode] = useState<'sa' | 'user'>('user');
  const appConfig = useAppConfig();
  // SA token mode
  const [saNamespace, setSaNamespace] = useState('default');
  const [saName, setSaName] = useState('');
  const [saExpiry, setSaExpiry] = useState(defaultExpiry(8));
  // user cert mode
  const [userName, setUserName] = useState('');
  const [userGroups, setUserGroups] = useState<string[]>([]);
  const [certExpiry, setCertExpiry] = useState(defaultExpiry(24));

  const [busy, setBusy] = useState(false);
  const [downloaded, setDownloaded] = useState<string | null>(null);
  const [warning, setWarning] = useState('');
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [retry, setRetry] = useState<(() => void) | null>(null);

  if (!active) {
    return (
      <Alert color="blue" mt="md">
        Select a registered cluster first. Offline, the builder can still export
        the CSR manifest for manual signing.
      </Alert>
    );
  }

  const handleError = (e: unknown, retryFn: () => void) => {
    const err = e as ApiError;
    if (err.stepUpRequired) {
      setRetry(() => retryFn);
      setStepUpOpen(true);
    } else {
      notifications.show({ color: 'red', message: String(err.detail ?? err.message) });
    }
  };

  const generateSa = async () => {
    setBusy(true);
    setDownloaded(null);
    try {
      const r = await api<{ kubeconfig: string; filename: string;
        expiresAt: string; warning: string }>(
        `/api/clusters/${active.name}/kubeconfig/serviceaccount`, {
          method: 'POST',
          body: { namespace: saNamespace, serviceAccount: saName,
            ...expiryRequest(saExpiry) },
        });
      // Shown and downloaded once, never stored.
      downloadBlob(new Blob([r.kubeconfig], { type: 'application/yaml' }), r.filename);
      setDownloaded(`${r.filename} (expires ${r.expiresAt})`);
      setWarning(r.warning);
    } catch (e) {
      handleError(e, generateSa);
    } finally {
      setBusy(false);
    }
  };

  const generateUser = async () => {
    setBusy(true);
    setDownloaded(null);
    try {
      if (!webCryptoAvailable()) {
        throw new Error(
          'WebCrypto is unavailable: this deployment is not a secure context. '
          + 'Serve over https:// or http://127.0.0.1.');
      }
      const { csrPem, privateKeyPem } = await generateKeyAndCsr(userName, userGroups);
      const r = await api<{ certificatePem: string; expiresAt: string;
        filename: string; warning: string;
        clusterDetails: { clusterName: string; serverUrl: string;
          caDataB64: string; defaultNamespace?: string | null } }>(
        `/api/clusters/${active.name}/kubeconfig/user-csr`, {
          method: 'POST',
          body: { commonName: userName, groups: userGroups, csrPem,
            ...expiryRequest(certExpiry) },
        });
      const kubeconfig = assembleUserKubeconfig({
        ...r.clusterDetails, userName, certPem: r.certificatePem,
        keyPem: privateKeyPem, expiresAt: r.expiresAt,
      });
      downloadBlob(new Blob([kubeconfig], { type: 'application/yaml' }), r.filename);
      setDownloaded(`${r.filename} (expires ${r.expiresAt})`);
      setWarning(r.warning);
    } catch (e) {
      handleError(e, generateUser);
    } finally {
      setBusy(false);
    }
  };

  const systemBlocked = userName.startsWith('system:')
    || userGroups.some((g) => g.startsWith('system:'));

  // Right-hand panel: what this form does, as plain kubectl, plus how to use
  // the downloaded file — mirrors the form state live.
  const duration = (e: typeof saExpiry) => (e.mode === 'hours' ? `${e.hours}h`
    : e.mode === 'never' ? '<server max>' : '<until your chosen date>');
  const commands = mode === 'sa'
    ? `# What “Generate” does on ${active.name} (server-side, TokenRequest API):
kubectl create token ${saName || '<serviceaccount>'} \\
  --namespace ${saNamespace || '<namespace>'} \\
  --duration ${duration(saExpiry)}
# …then wraps the token into a ready-to-use kubeconfig.

# Use the downloaded file:
export KUBECONFIG=~/Downloads/<downloaded-file>.yaml
kubectl auth whoami
kubectl auth can-i --list -n ${saNamespace || '<namespace>'}

# The SA only has the access its RoleBindings grant — add some on the
# Grant Access page, or:
kubectl create rolebinding ${saName || '<sa>'}-edit --clusterrole=edit \\
  --serviceaccount=${saNamespace || '<ns>'}:${saName || '<sa>'} -n ${saNamespace || '<ns>'}

# Tokens cannot be revoked — to cut access early, delete the SA or its
# bindings. When it expires, just generate a fresh kubeconfig here.`
    : userCertGuide(userName, userGroups, certExpiry, active.name, active.serverUrl);

  return (
    <Stack mt="md">
      <Title order={3}>Kubeconfig generator — {active.displayName || active.name}</Title>
      <Grid>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Stack>
      <SegmentedControl value={mode} data={[
        { value: 'user', label: 'User certificate (CSR)' },
        { value: 'sa', label: 'ServiceAccount token' },
      ]} onChange={(v) => setMode(v as 'sa' | 'user')} />

      {mode === 'sa' ? (
        <Stack>
          <Group grow>
            <Autocomplete label="Namespace" value={saNamespace}
              data={discovery?.namespaces ?? []} limit={50} filter={showAllFilter}
              onChange={setSaNamespace} />
            <Autocomplete label="ServiceAccount" value={saName}
              placeholder="pick or type"
              data={[...new Set((discovery?.serviceAccounts ?? [])
                .filter((s) => !saNamespace || s.namespace === saNamespace)
                .map((s) => s.name))]}
              limit={50} filter={showAllFilter}
              onChange={setSaName} />
          </Group>
          <ExpiryPicker value={saExpiry} onChange={setSaExpiry}
            maxSeconds={appConfig?.maxTokenTtlSeconds ?? 0}
            caNotAfter={discovery?.caNotAfter}
            serverCertNotAfter={discovery?.apiServerCertNotAfter} />
          <Alert color="yellow" py={6}>
            A TokenRequest token cannot be revoked before it expires. Cutting
            access early means deleting the ServiceAccount or removing its
            bindings — keep the TTL short.
          </Alert>
          <Button onClick={generateSa} loading={busy}
            disabled={!saName || !!expiryError(saExpiry, appConfig?.maxTokenTtlSeconds ?? 0, discovery?.caNotAfter)}>
            Generate and download once
          </Button>
        </Stack>
      ) : (
        <Stack>
          <Group grow>
            <TextInput label="Username (CN)" value={userName} placeholder="alice"
              error={userName.startsWith('system:')
                ? 'system:* is hard-blocked' : undefined}
              onChange={(e) => setUserName(e.currentTarget.value)} />
          </Group>
          <ExpiryPicker value={certExpiry} onChange={setCertExpiry}
            maxSeconds={appConfig?.maxCertTtlSeconds ?? 0}
            caNotAfter={discovery?.caNotAfter}
            serverCertNotAfter={discovery?.apiServerCertNotAfter} />
          <TagsInput label="Groups (O). Prefer groups for bindings." value={userGroups}
            onChange={setUserGroups} placeholder="dev-team"
            error={userGroups.some((g) => g.startsWith('system:'))
              ? 'system:* groups are hard-blocked' : undefined} />
          <Alert color="blue" py={6}>
            The private key is generated <b>in your browser</b> and never sent to
            the server; only the CSR is submitted. Client certificates
            cannot be revoked — to cut access, remove the bindings.
          </Alert>
          <Button onClick={generateUser} loading={busy}
            disabled={!userName || systemBlocked
              || !!expiryError(certExpiry, appConfig?.maxCertTtlSeconds ?? 0, discovery?.caNotAfter)}>
            Generate key in browser, sign CSR, download once
          </Button>
        </Stack>
      )}

      {downloaded && (
        <Alert color="green" title="Downloaded once — not stored anywhere">
          <Code>{downloaded}</Code>
          <Text size="sm" mt={4}>{warning}</Text>
        </Alert>
      )}
          </Stack>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Text fw={600} size="sm" mb={4}>What this does / how to use it</Text>
          <YamlPreview yaml={commands} height={480} />
        </Grid.Col>
      </Grid>
      <StepUpModal opened={stepUpOpen} onClose={() => setStepUpOpen(false)}
        onSuccess={() => retry?.()} />
    </Stack>
  );
}
