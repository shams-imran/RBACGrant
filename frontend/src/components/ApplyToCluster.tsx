// Reusable "Apply to cluster" button + modal for the builder pages. Runs the
// guardrail check up front, then offers a server dry-run and the real apply,
// with the prod typed-name confirmation, guardrail override reason
// and step-up retry the backend demands.
import { useState } from 'react';
import { Alert, Button, Group, Modal, Stack, Text, Textarea, TextInput } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { api, ApiError } from '../api/client';
import { Bundle } from '../api/types';
import { useCluster } from '../ClusterContext';
import { StepUpModal } from './StepUpModal';

interface GuardrailDecision {
  allowed: boolean;
  hard_blocks: string[];
  override_required: string[];
}

interface ApplyResult {
  kind?: string; name?: string; namespace?: string; warning?: string;
}

export function ApplyToCluster({ bundle, disabled, onApplied }: {
  bundle: Bundle;
  disabled?: boolean;
  onApplied?: (results: ApplyResult[]) => void;
}) {
  const { active } = useCluster();
  const [opened, setOpened] = useState(false);
  const [confirmName, setConfirmName] = useState('');
  const [overrideReason, setOverrideReason] = useState('');
  const [guardrails, setGuardrails] = useState<GuardrailDecision | null>(null);
  const [dryRunResults, setDryRunResults] = useState<ApplyResult[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [retry, setRetry] = useState<(() => void) | null>(null);

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

  const open = async () => {
    setConfirmName('');
    setOverrideReason('');
    setDryRunResults(null);
    try {
      const d = await api<GuardrailDecision>('/api/guardrails',
        { method: 'POST', body: bundle });
      setGuardrails(d);
      setOpened(true);
    } catch (e) {
      handleError(e, open);
    }
  };

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
        setOpened(false);
        notifications.show({ color: 'green',
          message: `Applied ${r.results.length} object(s) to ${active.name}` });
        onApplied?.(r.results);
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
    <>
      <Button size="xs" disabled={disabled || !active} onClick={open}
        title={active ? undefined : 'select a cluster first'}>
        Apply to {active ? (active.displayName || active.name) : 'cluster'}…
      </Button>

      <Modal opened={opened} onClose={() => setOpened(false)} size="lg"
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
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setOpened(false)} data-autofocus>
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
    </>
  );
}
