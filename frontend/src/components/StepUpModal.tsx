import { useState } from 'react';
import { Button, Modal, PasswordInput, Stack, Text } from '@mantine/core';
import { useAuth } from '../AuthContext';

// Re-enter the password before dangerous actions.
export function StepUpModal({ opened, onClose, onSuccess }: {
  opened: boolean; onClose: () => void; onSuccess: () => void;
}) {
  const { stepUp } = useAuth();
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setError('');
    try {
      await stepUp(password);
      setPassword('');
      onSuccess();
      onClose();
    } catch {
      setError('invalid username or password');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal opened={opened} onClose={onClose} title="Confirm your identity" centered>
      <Stack>
        <Text size="sm">
          This action is security-sensitive. Re-enter your password to continue.
        </Text>
        <PasswordInput label="Password" value={password} error={error || undefined}
          onChange={(e) => setPassword(e.currentTarget.value)} autoFocus
          onKeyDown={(e) => e.key === 'Enter' && submit()} />
        <Button onClick={submit} loading={busy}>Confirm</Button>
      </Stack>
    </Modal>
  );
}
