import { useEffect, useRef, useState } from 'react';
import { Icon } from '../components/Icon';
import { ResultLine, Row, type Result } from '../components/web/controls';
import {
  branding,
  brandingPreview,
  domainBranding,
  removeBrandingImage,
  resetDomainBranding,
  saveBranding,
  SERVER_BRANDING,
  uploadBrandingImage,
  type BrandingAdmin,
  type BrandingImage,
  type BrandingPreview,
} from '../lib/admin';
import { applyAccent, loadServerInfo } from '../lib/branding';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';

const DEFAULT_COLOR = '#ff4d8d';
/** A few colours that stand out on white and on the dark theme alike. */
const PRESETS = [
  '#ff4d8d',
  '#db2777',
  '#d946ef',
  '#8b5cf6',
  '#6366f1',
  '#0891b2',
  '#16a34a',
  '#ea580c',
];

/**
 * The server's own look: a name, an accent colour, logos for the light and the dark theme, and a
 * favicon — for the web vault, the login, the Send and file-request pages and the mails. The
 * official apps stay as they are.
 *
 * With a `domain`, the same for one send domain (§14.4): its Send and file-request pages. It
 * starts as the server's and can go back to it.
 */
export function Branding({
  domain,
  onChanged,
}: {
  domain?: { id: string; host: string; custom: boolean };
  /** After a send domain's look changed: its list shows whether it has its own. */
  onChanged?: () => void;
} = {}) {
  useLanguage();
  const path = domain ? domainBranding(domain.id) : SERVER_BRANDING;
  const Heading = domain ? 'h3' : 'h2';
  const [current, setCurrent] = useState<BrandingAdmin | null>(null);
  const [name, setName] = useState('');
  const [color, setColor] = useState(DEFAULT_COLOR);
  const [preview, setPreview] = useState<BrandingPreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>(null);

  const take = (answer: BrandingAdmin) => {
    setCurrent(answer);
    setName(answer.nameSet ? answer.name : '');
    setColor(answer.color);
  };

  useEffect(() => {
    branding(path).then(take, (e) => setResult({ tone: 'error', text: errorText(e) }));
  }, [path]);

  // The contrast of the colour being picked, and the shades it would give.
  useEffect(() => {
    if (!/^#[0-9a-f]{6}$/i.test(color)) {
      setPreview(null);
      return;
    }
    const timer = setTimeout(() => {
      brandingPreview(color, path).then(setPreview, () => setPreview(null));
    }, 200);
    return () => clearTimeout(timer);
  }, [color, path]);

  const act = async (work: () => Promise<BrandingAdmin>, done: string) => {
    setBusy(true);
    setResult(null);
    try {
      const answer = await work();
      take(answer);
      setResult({ tone: 'info', text: done });
      if (domain) {
        onChanged?.();
        return;
      }
      // The portal shows it at once: colours here, name and logos from the server's answer.
      applyAccent(answer.colorSet ? await brandingPreview(answer.color) : null);
      await loadServerInfo(true);
    } catch (e) {
      setResult({ tone: 'error', text: errorText(e) });
    } finally {
      setBusy(false);
    }
  };

  const contrast = preview?.contrast;
  const readable = contrast?.ok ?? false;
  const unchanged =
    current &&
    name.trim() === (current.nameSet ? current.name : '') &&
    color.toLowerCase() === current.color.toLowerCase();

  return (
    <>
      <p className="settings-lead">
        {domain
          ? t(
              'Name, Farbe, Logos und Favicon der Send- und Datei-Anfrage-Seiten unter {host}. Solange hier nichts Eigenes steht, sehen sie aus wie der Server.',
              { host: domain.host },
            )
          : t(
              'Name, Farbe, Logos und Favicon für den Web-Tresor, die Anmeldung, die Seiten von Sends und Datei-Anfragen und die Mails dieses Servers. Die offiziellen Bitwarden-Apps bleiben, wie sie sind.',
            )}
      </p>
      {domain?.custom && (
        <div className="form-actions">
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void act(async () => {
                await resetDomainBranding(domain.id);
                return branding(path);
              }, t('Wieder wie der Server ✧'))
            }
          >
            {t('Aussehen des Servers übernehmen')}
          </button>
        </div>
      )}
      <Heading className="settings-heading">{t('Name und Farbe')}</Heading>
      <Row label={t('Name')} description={t('Leer lässt es bei UwULock. Höchstens 40 Zeichen.')}>
        <input
          aria-label={t('Name')}
          value={name}
          maxLength={40}
          placeholder="UwULock"
          onChange={(e) => setName(e.target.value)}
        />
      </Row>
      <Row
        label={t('Akzentfarbe')}
        description={t(
          'Braucht mindestens 3:1 Kontrast zu Weiß und zum dunklen Hintergrund. Die Farbtöne für Knöpfe und Links rechnet der Server daraus so, dass Text darauf gut lesbar bleibt (4,5:1).',
        )}
      >
        <div className="brand-colors" role="group" aria-label={t('Vorschläge')}>
          {PRESETS.map((preset) => (
            <button
              key={preset}
              type="button"
              className="brand-swatch"
              style={{ background: preset }}
              aria-label={preset}
              aria-pressed={preset === color.toLowerCase()}
              onClick={() => setColor(preset)}
            />
          ))}
        </div>
        <input
          type="color"
          aria-label={t('Farbe wählen')}
          value={/^#[0-9a-f]{6}$/i.test(color) ? color : DEFAULT_COLOR}
          onChange={(e) => setColor(e.target.value)}
        />
        <input
          className="brand-hex"
          aria-label={t('Farbe als Hex-Wert')}
          value={color}
          maxLength={7}
          onChange={(e) => setColor(e.target.value.trim())}
        />
      </Row>
      <div className="brand-preview" aria-live="polite">
        {contrast ? (
          <>
            <p className={readable ? 'brand-contrast' : 'brand-contrast form-error'}>
              {readable
                ? t('Kontrast: {light}:1 zu Weiß, {dark}:1 zum dunklen Hintergrund ✧', {
                    light: contrast.light.toFixed(1),
                    dark: contrast.dark.toFixed(1),
                  })
                : t(
                    'Zu wenig Kontrast: {light}:1 zu Weiß, {dark}:1 zum dunklen Hintergrund. Beide brauchen mindestens 3:1.',
                    { light: contrast.light.toFixed(1), dark: contrast.dark.toFixed(1) },
                  )}
            </p>
            <div className="brand-samples" aria-hidden>
              {(['light', 'dark'] as const).map((theme) => (
                <div key={theme} className="brand-sample" data-sample={theme}>
                  <span
                    className="brand-sample-button"
                    style={{
                      background: preview?.[theme]['--uwu-pink-solid'],
                      color: preview?.[theme]['--uwu-on-pink'],
                    }}
                  >
                    {t('Knopf')}
                  </span>
                  <span style={{ color: preview?.[theme]['--uwu-pink-ink'] }}>{t('Link')}</span>
                  <span
                    className="brand-sample-tint"
                    style={{ background: preview?.[theme]['--uwu-pink-tint'] }}
                  />
                </div>
              ))}
            </div>
          </>
        ) : (
          <p className="field-hint">{t('Eine Farbe wie #ff4d8d.')}</p>
        )}
      </div>
      <div className="form-actions">
        <button
          type="button"
          disabled={busy || !current || (!current.nameSet && !current.colorSet)}
          onClick={() => void act(() => saveBranding(null, null, path), t('Wieder UwULock ✧'))}
        >
          {t('Name und Farbe zurücksetzen')}
        </button>
        <span className="spacer" />
        <button
          className="primary"
          type="button"
          disabled={busy || !readable || Boolean(unchanged)}
          onClick={() =>
            void act(
              () =>
                saveBranding(
                  name.trim() || null,
                  color.toLowerCase() === DEFAULT_COLOR && !current?.colorSet ? null : color,
                  path,
                ),
              t('Gespeichert ✧'),
            )
          }
        >
          {t('Speichern')}
        </button>
      </div>

      <Heading className="settings-heading">{t('Bilder')}</Heading>
      <p className="settings-lead">
        {t(
          'PNG, JPEG, WebP, GIF, ICO oder SVG. Der Server zeichnet jedes Bild neu als PNG; was sonst in der Datei steckt, bleibt draußen. Logos bis 512 KB, das Favicon bis 128 KB.',
        )}
      </p>
      <ImageRow
        label={t('Logo, helles Design')}
        image="logo/light"
        url={current?.logoLight ?? null}
        busy={busy}
        act={act}
        path={path}
        dark={false}
      />
      <ImageRow
        label={t('Logo, dunkles Design')}
        image="logo/dark"
        url={current?.logoDark ?? null}
        busy={busy}
        act={act}
        path={path}
        dark
      />
      <ImageRow
        label={t('Favicon')}
        image="favicon"
        url={current?.favicon ?? null}
        busy={busy}
        act={act}
        path={path}
        dark={false}
      />
      <ResultLine result={result} />
    </>
  );
}

function ImageRow({
  label,
  image,
  url,
  busy,
  act,
  dark,
  path,
}: {
  label: string;
  image: BrandingImage;
  url: string | null;
  busy: boolean;
  act: (work: () => Promise<BrandingAdmin>, done: string) => Promise<void>;
  dark: boolean;
  path: string;
}) {
  useLanguage();
  const input = useRef<HTMLInputElement>(null);
  return (
    <Row
      label={label}
      description={
        image === 'favicon'
          ? t('Das Symbol im Browser-Tab. Quadratisch sieht am besten aus.')
          : t('Ersetzt Nyu in der Titelleiste. Fehlt eines der beiden, gilt das andere für beide.')
      }
    >
      <span className="brand-image" data-dark={dark || undefined}>
        {url ? <img src={url} alt={t('{what}, wie es jetzt ist', { what: label })} /> : t('keins')}
      </span>
      <input
        ref={input}
        type="file"
        hidden
        accept="image/png,image/jpeg,image/webp,image/gif,image/x-icon,image/svg+xml,.ico,.svg"
        onChange={(e) => {
          const file = e.target.files?.[0];
          e.target.value = '';
          if (file) void act(() => uploadBrandingImage(image, file, path), t('Bild gespeichert ✧'));
        }}
      />
      <button type="button" disabled={busy} onClick={() => input.current?.click()}>
        <Icon name="upload" size={15} />
        {t('Hochladen …')}
        <span className="sr-only">{label}</span>
      </button>
      {url && (
        <button
          type="button"
          className="quiet"
          disabled={busy}
          onClick={() => void act(() => removeBrandingImage(image, path), t('Bild entfernt.'))}
        >
          {t('Entfernen')}
          <span className="sr-only">{label}</span>
        </button>
      )}
    </Row>
  );
}
