/**
 * The English catalogue: German string → English string, one file per area of
 * the app. See `lib/i18n.ts`.
 */

import app from './app.json';
import editing from './editing.json';
import settings from './settings.json';
import vault from './vault.json';
import web from './web.json';

export const EN: Readonly<Record<string, string>> = {
  ...app,
  ...editing,
  ...settings,
  ...vault,
  ...web,
};
