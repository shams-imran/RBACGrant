// Merge several kubeconfigs into one / split a merged kubeconfig into
// per-context files. Everything runs in the browser: these files carry
// credentials and are never uploaded to the server.
import { useMemo, useState } from 'react';
import { ActionIcon, Alert, Badge, Button, Checkbox, Code, FileButton, Group,
  Paper, SegmentedControl, Select, Stack, Table, Tabs, Text, TextInput,
  Textarea, Title } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { downloadBlob } from '../api/client';
import { YamlPreview } from '../components/YamlPreview';
import { Conflict, Kubeconfig, MergeInput, Resolution, mergeKubeconfigs,
  parseKubeconfig, safeFilename, splitKubeconfig, toYaml } from '../lib/kubeconfig';

interface LoadedFile { label: string; text: string; error: string | null }

const downloadYamlFile = (name: string, yaml: string) =>
  downloadBlob(new Blob([yaml], { type: 'application/yaml' }), name);

function MergeTab() {
  const [files, setFiles] = useState<LoadedFile[]>([]);
  const [resolutions, setResolutions] = useState<Record<string, Resolution>>({});
  const [currentCtx, setCurrentCtx] = useState<string | null>(null);
  const [excluded, setExcluded] = useState<Set<string>>(new Set()); // unchecked contexts
  const [dragOver, setDragOver] = useState(false);
  const [pasteText, setPasteText] = useState('');
  const [pasteError, setPasteError] = useState('');

  const addPasted = () => {
    try {
      parseKubeconfig(pasteText);
      const n = files.filter((f) => f.label.startsWith('pasted-')).length + 1;
      setFiles((cur) => [...cur, { label: `pasted-${n}`, text: pasteText, error: null }]);
      setPasteText('');
      setPasteError('');
      setResolutions({});
      setExcluded(new Set());
      setCurrentCtx(null);
    } catch (e) {
      setPasteError(String((e as Error).message));
    }
  };

  const addFiles = async (picked: File[]) => {
    const loaded: LoadedFile[] = [];
    for (const f of picked) {
      try {
        const text = await f.text();
        parseKubeconfig(text);
        loaded.push({ label: f.name, text, error: null });
      } catch (e) {
        loaded.push({ label: f.name, text: '', error: String((e as Error).message) });
      }
    }
    setFiles((cur) => [...cur, ...loaded]);
    setResolutions({});
    setExcluded(new Set());
    setCurrentCtx(null);
  };

  const inputs: MergeInput[] = useMemo(() => files
    .filter((f) => !f.error)
    .map((f) => ({ label: f.label, config: parseKubeconfig(f.text) })), [files]);

  const result = useMemo(
    () => (inputs.length ? mergeKubeconfigs(inputs, resolutions) : null),
    [inputs, resolutions]);

  const resolve = (c: Conflict, r: Resolution) =>
    setResolutions((cur) => ({ ...cur, [c.id]: r }));

  // Only the CHECKED contexts end up in the merged file; clusters and users
  // nothing references any more are pruned along with them.
  const allContexts = result?.merged.contexts ?? [];
  const included = allContexts.filter((c) => !excluded.has(c.name));
  const finalMerged: Kubeconfig | null = useMemo(() => {
    if (!result || result.conflicts.length) return null;
    const refClusters = new Set(included.map(
      (c) => (c.context as Record<string, string> | undefined)?.cluster));
    const refUsers = new Set(included.map(
      (c) => (c.context as Record<string, string> | undefined)?.user));
    const out: Kubeconfig = {
      ...result.merged,
      contexts: included,
      clusters: (result.merged.clusters ?? []).filter((c) => refClusters.has(c.name)),
      users: (result.merged.users ?? []).filter((u) => refUsers.has(u.name)),
    };
    const names = included.map((c) => c.name);
    const cc = currentCtx && names.includes(currentCtx) ? currentCtx
      : result.merged['current-context'] && names.includes(result.merged['current-context'])
        ? result.merged['current-context'] : names[0];
    if (cc) out['current-context'] = cc; else delete out['current-context'];
    return out;
  }, [result, excluded, currentCtx]);

  const toggleCtx = (name: string) => setExcluded((cur) => {
    const next = new Set(cur);
    if (next.has(name)) next.delete(name); else next.add(name);
    return next;
  });

  const download = () => {
    if (!finalMerged) return;
    downloadYamlFile('kubeconfig-merged.yaml', toYaml(finalMerged));
    notifications.show({ color: 'green', message: 'Merged kubeconfig downloaded' });
  };

  return (
    <Stack gap="sm">
      <Paper withBorder p="md" ta="center"
        style={{
          borderStyle: 'dashed',
          ...(dragOver && { borderColor: 'var(--mantine-color-blue-6)',
            backgroundColor: 'var(--mantine-color-blue-light)' }),
        }}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          addFiles(Array.from(e.dataTransfer.files ?? []));
        }}>
        <Text size="sm" c="dimmed">Drag and drop kubeconfig files here</Text>
        <Group justify="center" mt="xs">
          <FileButton onChange={addFiles} multiple>
            {(props) => <Button variant="light" size="xs" {...props}>…or browse files</Button>}
          </FileButton>
          {files.length > 0 && (
            <Button variant="subtle" color="red" size="xs"
              onClick={() => { setFiles([]); setResolutions({}); setCurrentCtx(null); setExcluded(new Set()); }}>
              Clear all
            </Button>
          )}
        </Group>
      </Paper>

      <Textarea minRows={3} autosize maxRows={8} value={pasteText}
        styles={{ input: { fontFamily: 'var(--font-mono)' } }}
        placeholder="…or paste a kubeconfig here and press “Add pasted config”"
        error={pasteError || undefined}
        onChange={(e) => { setPasteText(e.currentTarget.value); setPasteError(''); }} />
      {pasteText.trim() && (
        <Group>
          <Button size="xs" variant="light" onClick={addPasted}>
            + Add pasted config
          </Button>
        </Group>
      )}

      {files.map((f, i) => (
        <Paper key={i} withBorder p="xs">
          <Group justify="space-between">
            <Group gap="xs">
              <Text size="sm" fw={600}>{f.label}</Text>
              {f.error
                ? <Badge color="red" variant="light">unreadable</Badge>
                : <Text size="xs" c="dimmed">
                    {parseKubeconfig(f.text).contexts?.length ?? 0} contexts
                  </Text>}
            </Group>
            <ActionIcon variant="subtle" color="red" aria-label="Remove file"
              onClick={() => { setFiles(files.filter((_, k) => k !== i)); setResolutions({}); }}>
              ✕
            </ActionIcon>
          </Group>
          {f.error && <Text size="xs" c="red">{f.error}</Text>}
        </Paper>
      ))}

      {result && result.conflicts.length > 0 && (
        <Alert color="yellow" title={`⚠ ${result.conflicts.length} naming conflict${result.conflicts.length > 1 ? 's' : ''} to resolve`}>
          <Stack gap="xs" mt="xs">
            {result.conflicts.map((c) => {
              const res = resolutions[c.id];
              return (
                <Paper key={c.id} withBorder p="xs">
                  <Text size="sm">
                    {c.kind} <Code>{c.name}</Code> in <b>{c.file}</b> has the same
                    name as an earlier entry but different content.
                  </Text>
                  <Group mt={6} gap="xs" align="flex-end">
                    <SegmentedControl size="xs"
                      value={res ? res.action : ''}
                      data={[
                        { value: 'keep-existing', label: 'Keep the earlier one' },
                        { value: 'rename', label: 'Rename this one' },
                      ]}
                      onChange={(v) => resolve(c, v === 'rename'
                        ? { action: 'rename', newName: `${c.name}-${c.fileIndex + 1}` }
                        : { action: 'keep-existing' })} />
                    {res?.action === 'rename' && (
                      <TextInput size="xs" label="New name" value={res.newName}
                        onChange={(e) => resolve(c, { action: 'rename',
                          newName: e.currentTarget.value })} />
                    )}
                  </Group>
                </Paper>
              );
            })}
          </Stack>
        </Alert>
      )}

      {result && result.notes.length > 0 && (
        <Stack gap={2}>
          {result.notes.map((n, i) => <Text key={i} size="xs" c="dimmed">· {n}</Text>)}
        </Stack>
      )}

      {result && result.conflicts.length === 0 && finalMerged && (
        <>
          <Text fw={600} size="sm">Contexts to include (checked = merged)</Text>
          <Table withTableBorder highlightOnHover>
            <Table.Thead><Table.Tr>
              <Table.Th w={40}>
                <Checkbox aria-label="Select all"
                  checked={excluded.size === 0}
                  indeterminate={excluded.size > 0 && excluded.size < allContexts.length}
                  onChange={() => setExcluded(excluded.size === 0
                    ? new Set(allContexts.map((c) => c.name)) : new Set())} />
              </Table.Th>
              <Table.Th>Context</Table.Th><Table.Th>Cluster</Table.Th>
              <Table.Th>User</Table.Th><Table.Th>Namespace</Table.Th>
            </Table.Tr></Table.Thead>
            <Table.Tbody>
              {allContexts.map((c) => {
                const ctx = (c.context ?? {}) as Record<string, string>;
                return (
                  <Table.Tr key={c.name}>
                    <Table.Td>
                      <Checkbox checked={!excluded.has(c.name)}
                        aria-label={`Include ${c.name}`}
                        onChange={() => toggleCtx(c.name)} />
                    </Table.Td>
                    <Table.Td>{c.name}</Table.Td>
                    <Table.Td>{ctx.cluster}</Table.Td>
                    <Table.Td>{ctx.user}</Table.Td>
                    <Table.Td>{ctx.namespace ?? '—'}</Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
          <Group align="flex-end">
            <Select label="current-context of the merged file" w={280}
              data={included.map((c) => c.name)}
              value={finalMerged['current-context'] ?? null}
              onChange={setCurrentCtx} />
            <Button onClick={download} disabled={included.length === 0}>
              Download merged kubeconfig ({included.length} of {allContexts.length} contexts)
            </Button>
          </Group>
          <YamlPreview yaml={included.length ? toYaml(finalMerged)
            : '# check at least one context to merge'} height={320} />
        </>
      )}
    </Stack>
  );
}

function SplitTab() {
  const [text, setText] = useState('');
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [dragOver, setDragOver] = useState(false);

  const entries = useMemo(() => {
    setError('');
    if (!text.trim()) return [];
    try {
      return splitKubeconfig(parseKubeconfig(text));
    } catch (e) {
      setError(String((e as Error).message));
      return [];
    }
  }, [text]);

  const loadFile = async (f: File | null) => {
    if (!f) return;
    setText(await f.text());
    setSelected(new Set());
  };

  const toggle = (name: string) => setSelected((cur) => {
    const next = new Set(cur);
    if (next.has(name)) next.delete(name); else next.add(name);
    return next;
  });
  const allSelected = entries.length > 0 && selected.size === entries.length;

  const downloadZip = async () => {
    const chosen = entries.filter((e) => selected.has(e.context));
    if (!chosen.length) return;
    const JSZip = (await import('jszip')).default;
    const zip = new JSZip();
    for (const e of chosen) {
      zip.file(`kubeconfig-${safeFilename(e.context)}.yaml`, e.yaml);
    }
    downloadBlob(await zip.generateAsync({ type: 'blob' }), 'kubeconfigs.zip');
    notifications.show({ color: 'green',
      message: `${chosen.length} kubeconfig(s) downloaded as kubeconfigs.zip` });
  };

  return (
    <Stack gap="sm">
      <Paper withBorder p="md" ta="center"
        style={{
          borderStyle: 'dashed',
          ...(dragOver && { borderColor: 'var(--mantine-color-blue-6)',
            backgroundColor: 'var(--mantine-color-blue-light)' }),
        }}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          loadFile(e.dataTransfer.files?.[0] ?? null);
        }}>
        <Text size="sm" c="dimmed">Drag and drop a kubeconfig file here</Text>
        <Group justify="center" mt="xs">
          <FileButton onChange={loadFile}>
            {(props) => <Button variant="light" size="xs" {...props}>…or browse a file</Button>}
          </FileButton>
          {text.trim() && (
            <Button variant="subtle" color="red" size="xs"
              onClick={() => { setText(''); setSelected(new Set()); }}>
              Clear
            </Button>
          )}
        </Group>
      </Paper>

      <Textarea minRows={3} autosize maxRows={entries.length ? 6 : 10}
        styles={{ input: { fontFamily: 'var(--font-mono)' } }}
        value={text} placeholder="…or paste a kubeconfig here"
        onChange={(e) => { setText(e.currentTarget.value); setSelected(new Set()); }} />
      {error && <Alert color="red" py={6}>{error}</Alert>}

      {entries.length > 0 && (
        <>
          <Table withTableBorder highlightOnHover>
            <Table.Thead><Table.Tr>
              <Table.Th w={40}>
                <Checkbox checked={allSelected} aria-label="Select all"
                  indeterminate={selected.size > 0 && !allSelected}
                  onChange={() => setSelected(allSelected
                    ? new Set() : new Set(entries.map((e) => e.context)))} />
              </Table.Th>
              <Table.Th>Context</Table.Th><Table.Th>Cluster</Table.Th>
              <Table.Th>User</Table.Th><Table.Th>Namespace</Table.Th>
              <Table.Th w={110} />
            </Table.Tr></Table.Thead>
            <Table.Tbody>
              {entries.map((e) => (
                <Table.Tr key={e.context}>
                  <Table.Td>
                    <Checkbox checked={selected.has(e.context)}
                      aria-label={`Select ${e.context}`}
                      onChange={() => toggle(e.context)} />
                  </Table.Td>
                  <Table.Td>{e.context}</Table.Td>
                  <Table.Td>{e.cluster}</Table.Td>
                  <Table.Td>{e.user}</Table.Td>
                  <Table.Td>{e.namespace ?? '—'}</Table.Td>
                  <Table.Td>
                    {e.missing.length ? (
                      <Badge color="red" variant="light"
                        title={`missing: ${e.missing.join(', ')}`}>incomplete</Badge>
                    ) : (
                      <Button size="compact-xs" variant="light"
                        onClick={() => downloadYamlFile(
                          `kubeconfig-${safeFilename(e.context)}.yaml`, e.yaml)}>
                        Download
                      </Button>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
          {entries.some((e) => e.missing.length > 0) && (
            <Text size="xs" c="dimmed">
              “incomplete” contexts reference a cluster or user that is missing
              from the source file; they are excluded from downloads.
            </Text>
          )}
          <Group>
            <Button disabled={selected.size === 0} onClick={downloadZip}>
              Download selected ({selected.size}) as ZIP
            </Button>
          </Group>
        </>
      )}
    </Stack>
  );
}

export default function ConfigToolsPage() {
  return (
    <Stack mt="md">
      <Title order={3}>Merge / split kubeconfigs</Title>
      <Alert color="blue" py={6}>
        Everything on this page runs in your browser — the kubeconfigs you open
        here are never uploaded to the server or stored anywhere.
      </Alert>
      <Tabs defaultValue="merge">
        <Tabs.List>
          <Tabs.Tab value="merge">Merge</Tabs.Tab>
          <Tabs.Tab value="split">Split</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="merge" pt="sm"><MergeTab /></Tabs.Panel>
        <Tabs.Panel value="split" pt="sm"><SplitTab /></Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
