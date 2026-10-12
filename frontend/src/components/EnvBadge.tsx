import { Badge } from '@mantine/core';

// Environment badges. prod is filled danger with the text "PROD".
export function EnvBadge({ env }: { env: 'prod' | 'staging' | 'dev' | 'other' }) {
  if (env === 'prod') {
    return <Badge color="red" variant="filled" radius="sm">PROD</Badge>;
  }
  if (env === 'staging') {
    return <Badge color="yellow" variant="light" radius="sm">staging</Badge>;
  }
  if (env === 'dev') {
    return <Badge color="green" variant="light" radius="sm">dev</Badge>;
  }
  return <Badge color="gray" variant="light" radius="sm">other</Badge>;
}
