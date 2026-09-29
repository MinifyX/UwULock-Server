/**
 * The English catalogue: German string → English string, one file per area of
 * the app. See `lib/i18n.ts`.
 */

import a11y from './a11y.json';
import app from './app.json';
import comfort from './comfort.json';
import editing from './editing.json';
import families from './families.json';
import features from './features.json';
import importing from './import.json';
import masked from './masked.json';
import operations from './operations.json';
import requests from './requests.json';
import senddomains from './senddomains.json';
import settings from './settings.json';
import sharing from './sharing.json';
import sso from './sso.json';
import suite from './suite.json';
import switches from './switches.json';
import vault from './vault.json';
import web from './web.json';

export const EN: Readonly<Record<string, string>> = {
  ...a11y,
  ...app,
  ...comfort,
  ...editing,
  ...families,
  ...features,
  ...importing,
  ...masked,
  ...operations,
  ...requests,
  ...senddomains,
  ...settings,
  ...sharing,
  ...sso,
  ...suite,
  ...switches,
  ...vault,
  ...web,
};
