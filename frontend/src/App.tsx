import { AppShell, Badge, Burger, Divider, Group, NavLink, ScrollArea, Text, Title,
  ActionIcon, useMantineColorScheme, Loader, Center, Button } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './AuthContext';
import LoginPage from './pages/Login';
import GrantAccessPage from './pages/GrantAccess';
import RoleBuilderPage from './pages/RoleBuilder';
import BindingBuilderPage from './pages/BindingBuilder';
import TemplatesPage from './pages/Templates';
import ClustersPage from './pages/Clusters';
import RbacObjectsPage from './pages/RbacObjects';
import KubeconfigPage from './pages/Kubeconfig';
import CanIPage from './pages/CanI';
import ConfigToolsPage from './pages/ConfigTools';
import { ClusterProvider, useCluster } from './ClusterContext';
import { EnvBadge } from './components/EnvBadge';

function ThemeToggle() {
  const { colorScheme, toggleColorScheme } = useMantineColorScheme();
  return (
    <ActionIcon variant="subtle" size="lg" onClick={toggleColorScheme}
      aria-label="Toggle color scheme">
      {colorScheme === 'dark' ? '☀' : '☾'}
    </ActionIcon>
  );
}

function ClusterBanner() {
  const { active } = useCluster();
  if (!active) return null;
  const envColors: Record<string, string> = {
    prod: 'var(--color-danger)', staging: 'var(--color-warning)',
    dev: 'var(--color-success)', other: 'var(--color-border)',
  };
  return (
    <Group className="cluster-banner" px="md" py={6} gap="sm"
      style={{ ['--env-color' as string]: envColors[active.environment] }}>
      <Text size="sm" fw={600}>{active.displayName || active.name}</Text>
      <EnvBadge env={active.environment} />
      {active.identity && <Text size="xs" c="dimmed">{active.identity}</Text>}
      {!active.tlsVerified && (
        <Badge color="red" variant="filled" size="sm">⚠ TLS not verified</Badge>
      )}
    </Group>
  );
}

function Shell() {
  const [opened, { toggle }] = useDisclosure();
  const { session, loading, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  if (loading) {
    return <Center h="100vh"><Loader color="reddot" /></Center>;
  }
  if (!session) {
    return <LoginPage />;
  }

  const navGroups = [
    [
      { to: '/objects', label: 'RBAC Objects List' },
    ],
    [
      { to: '/roles', label: 'Role Builder' },
      { to: '/bindings', label: 'Binding Builder' },
      { to: '/kubeconfig', label: 'KubeConfig' },
    ],
    [
      { to: '/grant', label: 'Grant Access' },
      { to: '/templates', label: 'Templates' },
    ],
    [
      { to: '/config-tools', label: 'Merge / Split Configs' },
    ],
    [
      { to: '/can-i', label: 'Can-I Check' },
      { to: '/clusters', label: 'Clusters' },
    ],
  ];

  return (
    <AppShell header={{ height: 56 }} navbar={{
      width: 220, breakpoint: 'sm', collapsed: { mobile: !opened } }} padding="md">
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Group>
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <Title order={4} c="reddot">RBACGrant</Title>
          </Group>
          <Group gap="xs">
            <Text size="sm" c="dimmed">{session.username} ({session.role})</Text>
            <ThemeToggle />
            {session.authMode !== 'none' && (
              <Button variant="subtle" size="xs" onClick={() => logout()}>Log out</Button>
            )}
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar p="xs">
        <ScrollArea>
          {navGroups.map((group, i) => (
            <div key={i}>
              {i > 0 && <Divider my="xs" />}
              {group.map((item) => (
                <NavLink key={item.to} label={item.label}
                  active={location.pathname.startsWith(item.to)}
                  onClick={() => navigate(item.to)} />
              ))}
            </div>
          ))}
        </ScrollArea>
      </AppShell.Navbar>
      <AppShell.Main>
        <ClusterBanner />
        <Routes>
          <Route path="/" element={<Navigate to="/grant" replace />} />
          <Route path="/grant" element={<GrantAccessPage />} />
          <Route path="/roles" element={<RoleBuilderPage />} />
          <Route path="/bindings" element={<BindingBuilderPage />} />
          <Route path="/templates" element={<TemplatesPage />} />
          <Route path="/kubeconfig" element={<KubeconfigPage />} />
          <Route path="/config-tools" element={<ConfigToolsPage />} />
          <Route path="/objects" element={<RbacObjectsPage />} />
          <Route path="/can-i" element={<CanIPage />} />
          <Route path="/clusters" element={<ClustersPage />} />
          <Route path="*" element={<Navigate to="/grant" replace />} />
        </Routes>
      </AppShell.Main>
    </AppShell>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <ClusterProvider>
        <Shell />
      </ClusterProvider>
    </AuthProvider>
  );
}
