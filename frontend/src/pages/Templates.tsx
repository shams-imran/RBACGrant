import { useEffect, useState } from 'react';
import { Alert, Autocomplete, Badge, Button, Card, Group, SimpleGrid, Stack,
  Text, TextInput, Title, Modal } from '@mantine/core';
import { api } from '../api/client';
import { Bundle, Finding } from '../api/types';
import { useCluster } from '../ClusterContext';
import { ExportBar } from '../components/ExportBar';
import { FindingsList } from '../components/Findings';
import { YamlPreview } from '../components/YamlPreview';
import { useDiscovery } from '../hooks';
import { showAllFilter } from '../components/pickers';

interface TemplateInfo { id: string; title: string; description: string }
interface TemplateFull extends TemplateInfo { variables: string[]; bundle: Bundle }

function substitute(bundle: Bundle, vars: Record<string, string>): Bundle {
  let text = JSON.stringify(bundle);
  for (const [k, v] of Object.entries(vars)) {
    if (v) text = text.split(`\${${k}}`).join(v);
  }
  return JSON.parse(text) as Bundle;
}

export default function TemplatesPage() {
  const { active } = useCluster();
  const { discovery } = useDiscovery(active?.name);
  const [templates, setTemplates] = useState<TemplateInfo[]>([]);
  const [open, setOpen] = useState<TemplateFull | null>(null);
  const [vars, setVars] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<{ yaml: string; findings: Finding[]; score: number } | null>(null);

  useEffect(() => {
    api<{ templates: TemplateInfo[] }>('/api/templates')
      .then((r) => setTemplates(r.templates))
      .catch(() => setTemplates([]));
  }, []);

  const openTemplate = async (id: string) => {
    const t = await api<TemplateFull>(`/api/templates/${id}`);
    setOpen(t);
    setVars(Object.fromEntries((t.variables ?? []).map((v) => [v, ''])));
    setPreview(null);
  };

  const resolved = open ? substitute(open.bundle, vars) : null;
  const unresolved = resolved ? JSON.stringify(resolved).includes('${') : false;

  const doPreview = async () => {
    if (!resolved) return;
    const r = await api<{ yaml: string; findings: Finding[]; score: number }>(
      '/api/preview', { method: 'POST', body: resolved });
    setPreview(r);
  };

  return (
    <Stack mt="md">
      <Title order={3}>Starter templates</Title>
      <SimpleGrid cols={{ base: 1, md: 2, xl: 3 }}>
        {templates.map((t) => (
          <Card key={t.id} withBorder>
            <Group justify="space-between" mb="xs">
              <Text fw={600}>{t.title}</Text>
              {t.id.startsWith('operator') && (
                <Badge color={t.id === 'operator-full' ? 'red' : 'green'} variant="light">
                  {t.id === 'operator-full' ? '⚠ cluster-admin equivalent' : 'recommended'}
                </Badge>
              )}
            </Group>
            <Text size="sm" c="dimmed" mb="md">{t.description}</Text>
            <Button variant="light" size="xs" onClick={() => openTemplate(t.id)}>
              Use template
            </Button>
          </Card>
        ))}
      </SimpleGrid>

      <Modal opened={!!open} onClose={() => setOpen(null)} size="xl"
        title={open?.title ?? ''}>
        {open && (
          <Stack>
            {Object.keys(vars).length > 0 && (
              <Group grow>
                {Object.keys(vars).map((k) => (
                  // Namespace-like variables get the live namespace dropdown
                  // from the active cluster; free text still works.
                  k.toLowerCase().includes('namespace') ? (
                    <Autocomplete key={k} label={`\${${k}}`} value={vars[k]}
                      data={discovery?.namespaces ?? []} limit={50}
                      filter={showAllFilter}
                      placeholder={discovery ? 'pick or type a namespace' : 'type a namespace'}
                      onChange={(v) => setVars({ ...vars, [k]: v })} />
                  ) : (
                    <TextInput key={k} label={`\${${k}}`} value={vars[k]}
                      onChange={(e) => setVars({ ...vars, [k]: e.currentTarget.value })} />
                  )
                ))}
              </Group>
            )}
            {unresolved && (
              <Alert color="yellow" py={6}>Fill in every variable before exporting.</Alert>
            )}
            <Button onClick={doPreview} disabled={unresolved}>Preview</Button>
            {preview && (
              <>
                <YamlPreview yaml={preview.yaml} height={320} />
                <FindingsList findings={preview.findings} score={preview.score} />
                {resolved && <ExportBar bundle={resolved} />}
              </>
            )}
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
