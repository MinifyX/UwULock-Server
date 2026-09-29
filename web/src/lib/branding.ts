/**
 * What the server says about itself, once per page: its features and its branding (the name, the
 * logos). The page's title, favicon and colours come with the HTML already; this is for what
 * scripts draw — the title bar, the login and Send pages.
 */

import { useSyncExternalStore } from 'react';
import { serverInfo, type Branding, type ServerInfo } from './account';

let info: ServerInfo | null = null;
let loading: Promise<void> | null = null;
const listeners = new Set<() => void>();

function notify() {
  for (const listener of listeners) listener();
}

/** Ask the server (again, with `force`: after an admin changed something). */
export function loadServerInfo(force = false): Promise<void> {
  if (loading && !force) return loading;
  loading = serverInfo().then(
    (answer) => {
      info = answer;
      notify();
    },
    () => undefined,
  );
  return loading;
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  if (!info && !loading) void loadServerInfo();
  return () => void listeners.delete(listener);
}

/** The server's answer to `/uwu/v1/info`, once it came. */
export function useServerInfo(): ServerInfo | null {
  return useSyncExternalStore(subscribe, () => info);
}

/** Whether the server has `feature` switched on; false until it answered. */
export function useFeature(feature: string): boolean {
  return useServerInfo()?.features?.includes(feature) ?? false;
}

/** The server's branding, when it has one of its own. */
export function useBranding(): Branding | null {
  const branding = useServerInfo()?.branding;
  return branding?.custom ? branding : null;
}

/**
 * New accent colours at once, without a reload: the admin portal after saving. `tokens` are the
 * CSS variables for both themes, as the server's preview gives them; none goes back to UwULock's.
 */
export function applyAccent(
  tokens: { light: Record<string, string>; dark: Record<string, string> } | null,
) {
  let style = document.getElementById('uwu-branding');
  if (!tokens) {
    style?.remove();
    return;
  }
  if (!style) {
    style = document.createElement('style');
    style.id = 'uwu-branding';
    document.head.append(style);
  }
  const block = (selector: string, values: Record<string, string>) =>
    `${selector} {\n${Object.entries(values)
      .filter(([name, value]) => /^--[a-z-]+$/.test(name) && /^[#0-9a-z (),./]+$/i.test(value))
      .map(([name, value]) => `  ${name}: ${value};`)
      .join('\n')}\n}\n`;
  style.textContent =
    block('html:root', tokens.light) + block('html:root[data-theme="dark"]', tokens.dark);
}
