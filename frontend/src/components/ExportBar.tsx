import { Button, Group } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { apiBlob, downloadBlob } from '../api/client';
import { Bundle } from '../api/types';

// Export formats + download buttons.
export function ExportBar({ bundle, disabled }: { bundle: Bundle; disabled?: boolean }) {
  const grab = async (fmt: string, filename: string) => {
    try {
      const blob = await apiBlob(`/api/export/${fmt}`, bundle);
      downloadBlob(blob, filename);
    } catch (e) {
      notifications.show({ color: 'red', message: `Export failed: ${e}` });
    }
  };
  return (
    <Group gap="xs">
      <Button size="xs" variant="light" disabled={disabled}
        onClick={() => grab('yaml', 'rbac-bundle.yaml')}>Download YAML</Button>
      <Button size="xs" variant="light" disabled={disabled}
        onClick={() => grab('zip', 'rbac-bundle.zip')}>Zip (per object)</Button>
      <Button size="xs" variant="light" disabled={disabled}
        onClick={() => grab('kubectl', 'rbac-commands.sh')}>kubectl commands</Button>
      <Button size="xs" variant="light" disabled={disabled}
        onClick={() => grab('kustomize', 'kustomization.yaml')}>Kustomize</Button>
    </Group>
  );
}
