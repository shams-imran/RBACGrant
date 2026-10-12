import { useState } from 'react';
import { Button, Center, Paper, PasswordInput, Stack, Text, TextInput, Title } from '@mantine/core';
import { useAuth } from '../AuthContext';

// The login page uses the same tokens — a centered card on surface.
export default function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setError('');
    try {
      await login(username, password);
    } catch {
      setError('invalid username or password');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Center h="100vh" style={{ background: 'var(--color-bg)' }}>
      <Paper w={380} p="xl" radius="md" withBorder
        style={{ background: 'var(--color-surface)' }}>
        <Stack>
          <Title order={2} ta="center" c="reddot">RBACGrant</Title>
          <Text size="sm" c="dimmed" ta="center">
            Sign in to manage RBAC across your registered clusters
          </Text>
          <TextInput label="Username" value={username} autoComplete="username"
            onChange={(e) => setUsername(e.currentTarget.value)} />
          <PasswordInput label="Password" value={password} autoComplete="current-password"
            error={error || undefined}
            onChange={(e) => setPassword(e.currentTarget.value)}
            onKeyDown={(e) => e.key === 'Enter' && submit()} />
          <Button onClick={submit} loading={busy} fullWidth>Sign in</Button>
        </Stack>
      </Paper>
    </Center>
  );
}
