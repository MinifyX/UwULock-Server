import { N_, t } from '../../lib/i18n';
import type { ShownKind, SpaceName } from '../../lib/suite/model';
import type { IconName } from '../Icon';

export const SPACE_LABEL: Record<SpaceName, string> = {
  ssh: N_('SSH (UwUSSH)'),
  rdp: N_('Remote Desktop (UwURDP)'),
};

export const KIND_ICON: Record<string, IconName> = {
  host: 'monitor',
  group: 'folder',
  identity: 'user',
  key: 'key',
  snippet: 'terminal',
  port_forward: 'network',
  known_host: 'shield',
};

const KIND_PLURAL: Record<ShownKind, string> = {
  host: N_('Hosts'),
  group: N_('Gruppen'),
  identity: N_('Identitäten'),
  key: N_('Schlüssel'),
  snippet: N_('Snippets'),
  port_forward: N_('Weiterleitungen'),
  known_host: N_('Bekannte Hosts'),
};

const KIND_ONE: Record<ShownKind, string> = {
  host: N_('Host'),
  group: N_('Gruppe'),
  identity: N_('Identität'),
  key: N_('Schlüssel'),
  snippet: N_('Snippet'),
  port_forward: N_('Port-Weiterleitung'),
  known_host: N_('Bekannter Host'),
};

export const kindsLabel = (kind: ShownKind) => t(KIND_PLURAL[kind]);
export const kindLabel = (kind: string) =>
  kind in KIND_ONE ? t(KIND_ONE[kind as ShownKind]) : kind;

export const workspaceLabel = (workspace: string) =>
  workspace === 'business' ? t('Geschäftlich') : t('Privat');

const AUTH: Record<string, string> = {
  password: N_('Passwort'),
  key: N_('Schlüssel'),
  agent: N_('SSH-Agent'),
  'keyboard-interactive': N_('Tastatur-Abfrage'),
  cert: N_('Zertifikat'),
};

export const authLabel = (auth: string) => (auth in AUTH ? t(AUTH[auth]!) : auth);
