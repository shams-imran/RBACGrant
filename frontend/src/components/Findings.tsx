import { Alert, Badge, Group, Stack, Text } from '@mantine/core';
import { Finding } from '../api/types';

// Severity badges always carry an icon AND a text label, and use the
// danger colour, never the brand primary. Colour is never the only signal.
const SEVERITY: Record<Finding['severity'], { color: string; label: string; icon: string }> = {
  critical: { color: 'red', label: 'Critical', icon: '⛔' },
  high: { color: 'red', label: 'High', icon: '⚠' },
  medium: { color: 'yellow', label: 'Medium', icon: '⚠' },
  low: { color: 'blue', label: 'Low', icon: 'ℹ' },
  info: { color: 'gray', label: 'Info', icon: 'ℹ' },
};

export function SeverityBadge({ severity }: { severity: Finding['severity'] }) {
  const s = SEVERITY[severity];
  return (
    <Badge color={s.color} variant={severity === 'critical' ? 'filled' : 'light'}
      radius="sm">{s.icon} {s.label}</Badge>
  );
}

export function FindingsList({ findings, score }: { findings: Finding[]; score?: number }) {
  if (!findings.length) {
    return (
      <Alert color="green" title="✓ No linter findings">
        This bundle looks least-privilege clean.
        {score !== undefined && ` Score: ${score}/100.`}
      </Alert>
    );
  }
  return (
    <Stack gap="xs">
      {score !== undefined && (
        <Group gap="xs">
          <Text size="sm" fw={600}>Least-privilege score:</Text>
          <Badge color={score >= 80 ? 'green' : score >= 50 ? 'yellow' : 'red'}
            variant="filled">{score}/100</Badge>
        </Group>
      )}
      {findings.map((f, i) => (
        <Alert key={i} color={SEVERITY[f.severity].color} py={6}
          title={
            <Group gap="xs">
              <SeverityBadge severity={f.severity} />
              <Text size="sm" span>{f.object_kind} {f.object_name}</Text>
            </Group>
          }>
          <Text size="sm">{f.message}</Text>
          {f.suggestion && <Text size="xs" c="dimmed">Suggestion: {f.suggestion}</Text>}
        </Alert>
      ))}
    </Stack>
  );
}
