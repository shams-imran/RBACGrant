// Credential expiry selector: fixed hours, an absolute date/time, or
// "never" — which honestly means the server's configured maximum TTL,
// since TokenRequest tokens and signed certs always carry an expiry
//. The real cap comes from /api/config.
import { Group, NumberInput, Select, Stack, Text } from '@mantine/core';
import { DateTimePicker, DateTimePickerProps } from '@mantine/dates';

export interface Expiry {
  mode: 'hours' | 'date' | 'never';
  hours: number;
  until: string; // datetime-local value, local time
}

export const defaultExpiry = (hours: number): Expiry =>
  ({ mode: 'hours', hours, until: '' });

export function humanizeSeconds(s: number): string {
  if (s % 86400 === 0) return `${s / 86400}d`;
  if (s % 3600 === 0) return `${s / 3600}h`;
  return `${Math.round(s / 60)}m`;
}

function dateTtlSeconds(until: string): number {
  return Math.round((new Date(until).getTime() - Date.now()) / 1000);
}

// Keep `until` in datetime-local format ("YYYY-MM-DDTHH:mm", local time) so
// dateTtlSeconds and any stored values stay backward-compatible.
function toLocalInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
    + `T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// null = valid. maxSeconds <= 0 means "cap unknown, let the server decide".
// caNotAfter (optional) is the cluster CA expiry — nothing can outlive it.
export function expiryError(e: Expiry, maxSeconds: number,
  caNotAfter?: string | null): string | null {
  if (e.mode === 'hours') {
    if (!e.hours || e.hours < 1) return 'TTL must be at least 1 hour';
    if (maxSeconds > 0 && e.hours * 3600 > maxSeconds) {
      return `above the server cap of ${humanizeSeconds(maxSeconds)}`;
    }
  }
  if (e.mode === 'date') {
    if (!e.until) return 'pick an expiry date and time';
    const ttl = dateTtlSeconds(e.until);
    if (!Number.isFinite(ttl) || ttl < 600) {
      return 'expiry must be at least 10 minutes in the future';
    }
    if (maxSeconds > 0 && ttl > maxSeconds) {
      return `above the server cap of ${humanizeSeconds(maxSeconds)}`;
    }
    if (caNotAfter && new Date(e.until).getTime() > new Date(caNotAfter).getTime()) {
      return `after the cluster CA expires (${new Date(caNotAfter).toLocaleDateString()})`;
    }
  }
  return null;
}

// Body fields for the kubeconfig endpoints.
export function expiryRequest(e: Expiry): { ttlSeconds?: number; neverExpire?: boolean } {
  if (e.mode === 'never') return { neverExpire: true };
  if (e.mode === 'date') return { ttlSeconds: dateTtlSeconds(e.until) };
  return { ttlSeconds: Math.round(e.hours * 3600) };
}

export function ExpiryPicker({ value, onChange, maxSeconds, caNotAfter,
  serverCertNotAfter, label = 'Expiry' }: {
  value: Expiry;
  onChange: (e: Expiry) => void;
  maxSeconds: number;
  caNotAfter?: string | null;
  serverCertNotAfter?: string | null; // informational only — rotated server-side
  label?: string;
}) {
  const error = expiryError(value, maxSeconds, caNotAfter);
  // An empty date is signalled by the placeholder alone; the error text (and
  // red border) only appears once a picked date actually violates a limit.
  const shownError = value.mode === 'date' && !value.until ? null : error;
  const cap = maxSeconds > 0 ? humanizeSeconds(maxSeconds) : null;
  // The calendar greys out dates past the server cap and the CA expiry.
  const capDate = maxSeconds > 0 ? new Date(Date.now() + maxSeconds * 1000) : null;
  const caDate = caNotAfter ? new Date(caNotAfter) : null;
  const maxDate = capDate && caDate ? (capDate < caDate ? capDate : caDate)
    : capDate ?? caDate ?? undefined;
  return (
    <Group gap="xs" align="flex-end">
      <Select label={label} w={150} allowDeselect={false} value={value.mode}
        data={[
          { value: 'hours', label: 'Hours (TTL)' },
          { value: 'date', label: 'Until date' },
          { value: 'never', label: 'Never expire' },
        ]}
        onChange={(m) => onChange({ ...value, mode: (m as Expiry['mode']) ?? 'hours' })} />
      {value.mode === 'hours' && (
        <NumberInput label="TTL (hours)" value={value.hours} w={130}
          min={1} max={maxSeconds > 0 ? Math.floor(maxSeconds / 3600) : undefined}
          error={error} onChange={(v) => onChange({ ...value, hours: Number(v) || 0 })} />
      )}
      {value.mode === 'date' && (
        <DateTimePicker label="Expires at" w={220} clearable
          value={value.until ? new Date(value.until) : null}
          minDate={new Date()} maxDate={maxDate}
          valueFormat="YYYY-MM-DD hh:mm A"
          placeholder="pick a date and time"
          error={shownError}
          // The popup's time field only re-reads the value when the popup
          // closes, so control it directly or the 11:59 PM default looks
          // unset. Mantine's types omit `value` here, but the spread honors it.
          timeInputProps={{ value: value.until ? value.until.slice(11, 16) : '' } as
            DateTimePickerProps['timeInputProps']}
          onChange={(d) => {
            if (!d) return onChange({ ...value, until: '' });
            const picked = new Date(d);
            // First pick of a date defaults the time to 11:59 PM.
            if (!value.until && picked.getHours() === 0 && picked.getMinutes() === 0) {
              picked.setHours(23, 59, 0, 0);
            }
            onChange({ ...value, until: toLocalInput(picked) });
          }} />
      )}
      {value.mode === 'date' && (caDate || serverCertNotAfter) && (
        <Stack gap={0} pb={6}>
          {caDate && (
            <Text size="xs" c="dimmed">
              cluster CA valid until {caDate.toLocaleDateString()}
            </Text>
          )}
          {serverCertNotAfter && (
            <Text size="xs" c="dimmed">
              API server (serving cert) valid until{' '}
              {new Date(serverCertNotAfter).toLocaleDateString()}
            </Text>
          )}
        </Stack>
      )}
      {value.mode === 'never' && (
        <Text size="xs" c="dimmed" maw={230} pb={6}>
          K8s credentials always carry an expiry — this issues the maximum the
          server allows{cap ? ` (${cap}, RBAC_UI_MAX_*_TTL)` : ''}.
        </Text>
      )}
    </Group>
  );
}
