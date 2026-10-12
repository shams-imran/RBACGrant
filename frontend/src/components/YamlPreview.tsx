import { useComputedColorScheme, Paper, Group, Button, CopyButton } from '@mantine/core';
import Editor from '@monaco-editor/react';

// Live read-only Monaco YAML preview. Monaco is bundled (no CDN).
export function YamlPreview({ yaml, height = 480 }: { yaml: string; height?: number }) {
  const scheme = useComputedColorScheme('light');
  return (
    <Paper withBorder>
      <Group justify="flex-end" p={4}>
        <CopyButton value={yaml}>
          {({ copied, copy }) => (
            <Button size="compact-xs" variant="subtle" onClick={copy}>
              {copied ? '✓ Copied' : 'Copy YAML'}
            </Button>
          )}
        </CopyButton>
      </Group>
      <Editor
        height={height}
        language="yaml"
        value={yaml}
        theme={scheme === 'dark' ? 'vs-dark' : 'vs'}
        options={{
          readOnly: true,
          minimap: { enabled: false },
          fontFamily: "'Geist Mono', ui-monospace, monospace",
          fontSize: 13,
          scrollBeyondLastLine: false,
          wordWrap: 'on',
        }}
      />
    </Paper>
  );
}
