// API client: same-origin fetch, session cookie + CSRF synchronizer token
//. 401 responses bounce the user to the login page.

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

export class ApiError extends Error {
  status: number;
  detail: unknown;
  stepUpRequired: boolean;
  constructor(status: number, detail: unknown, stepUpRequired = false) {
    super(typeof detail === 'string' ? detail : JSON.stringify(detail));
    this.status = status;
    this.detail = detail;
    this.stepUpRequired = stepUpRequired;
  }
}

export async function api<T = unknown>(
  path: string,
  options: { method?: string; body?: unknown; raw?: boolean } = {},
): Promise<T> {
  const method = options.method ?? 'GET';
  const headers: Record<string, string> = {};
  let body: BodyInit | undefined;
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(options.body);
  }
  if (method !== 'GET' && csrfToken) headers['x-csrf-token'] = csrfToken;

  const resp = await fetch(path, { method, headers, body, credentials: 'same-origin' });
  if (resp.status === 401 && !path.endsWith('/login')) {
    window.dispatchEvent(new CustomEvent('rbac-ui:unauthenticated'));
  }
  if (!resp.ok) {
    let detail: unknown = resp.statusText;
    try {
      detail = (await resp.json()).detail ?? detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(resp.status, detail,
      resp.headers.get('X-Step-Up-Required') === 'true');
  }
  if (options.raw) return (await resp.text()) as unknown as T;
  // A 200 with HTML means the request fell through to the SPA fallback
  // (usually an outdated server) — fail with a readable message instead of
  // "Unexpected token '<' ... is not valid JSON".
  if (!(resp.headers.get('content-type') ?? '').includes('application/json')) {
    throw new ApiError(resp.status,
      `the server returned a non-JSON response for ${path} — `
      + 'it is probably running an older build; restart it (make run)');
  }
  return (await resp.json()) as T;
}

export async function apiText<T = unknown>(path: string, text: string,
  contentType = 'application/yaml'): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': contentType };
  if (csrfToken) headers['x-csrf-token'] = csrfToken;
  const resp = await fetch(path, {
    method: 'POST', headers, body: text, credentials: 'same-origin',
  });
  if (!resp.ok) {
    let detail: unknown = resp.statusText;
    try {
      detail = (await resp.json()).detail ?? detail;
    } catch { /* non-JSON */ }
    throw new ApiError(resp.status, detail);
  }
  return (await resp.json()) as T;
}

export async function apiBlob(path: string, body: unknown): Promise<Blob> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (csrfToken) headers['x-csrf-token'] = csrfToken;
  const resp = await fetch(path, {
    method: 'POST', headers, body: JSON.stringify(body), credentials: 'same-origin',
  });
  if (!resp.ok) throw new ApiError(resp.status, resp.statusText);
  return resp.blob();
}

export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
