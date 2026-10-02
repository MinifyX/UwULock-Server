import { useCallback, useEffect, useState } from 'react';
import { Button, ButtonRow, Table } from '../components/ui';
import { ipBlocks, placeText, unblockIp, type IpBlock } from '../lib/admin';
import { errorText } from '../lib/errors';
import { when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import { BlockDialog } from './FailedLogins';
import { EmptyNote } from '../components/NyuStates';

/**
 * *Sicherheit → Gesperrte Adressen*: the addresses and networks that may not log in, until when,
 * and the way to lift a block or add one by hand.
 */
export function IpBlocks() {
  useLanguage();
  const [list, setList] = useState<IpBlock[] | null>(null);
  const [mine, setMine] = useState('');
  const [adding, setAdding] = useState(false);
  const load = useCallback(() => {
    ipBlocks().then(
      (answer) => {
        setList(answer.blocks);
        setMine(answer.yourAddress);
      },
      (e) => toast(errorText(e), 'error'),
    );
  }, []);
  useEffect(load, [load]);

  const lift = async (block: IpBlock) => {
    try {
      await unblockIp(block.id);
      toast(t('Die Sperre von {network} ist aufgehoben.', { network: block.network }), 'info');
      load();
    } catch (e) {
      toast(errorText(e), 'error');
    }
  };

  return (
    <div className="stack">
      <p className="section-lead">
        {t(
          'Von diesen Adressen geht keine Anmeldung, bis die Sperre abläuft oder du sie aufhebst – auch keine Registrierung und keine Passwort-Hinweise. Deine Adresse gerade: {ip}.',
          { ip: mine || '–' },
        )}
      </p>
      <ButtonRow>
        <Button onClick={() => setAdding(true)}>{t('Adresse sperren …')}</Button>
      </ButtonRow>
      <Table
        label={t('Gesperrte Adressen')}
        head={
          <>
            <th>{t('Adresse')}</th>
            <th>{t('Bis')}</th>
            <th>{t('Notiz')}</th>
            <th>
              <span className="sr-only">{t('Aktionen')}</span>
            </th>
          </>
        }
      >
        {list?.map((block) => (
          <tr key={block.id}>
            <td>
              <span className="mono">{block.network}</span>
              {placeText(block.place) && <small>{placeText(block.place)}</small>}
            </td>
            <td>
              {block.expires ? when(block.expires) : t('bis sie aufgehoben wird')}
              <small>
                {t('gesperrt {when}', { when: when(block.created) ?? '' })}
                {block.createdBy ? ` · ${block.createdBy}` : ''}
              </small>
            </td>
            <td>{block.reason || '–'}</td>
            <td className="row-actions">
              <Button size="small" onClick={() => void lift(block)}>
                {t('Aufheben')}
                <span className="sr-only">{block.network}</span>
              </Button>
            </td>
          </tr>
        ))}
      </Table>
      {list?.length === 0 && <EmptyNote mood="happy">{t('Keine Adresse ist gesperrt.')}</EmptyNote>}
      <p className="field-hint">
        {t(
          'Auf der Kommandozeile: uwulock-server blocks listet die Sperren, uwulock-server blocks remove <Adresse> hebt eine auf – auch wenn du dich ausgesperrt hast.',
        )}
      </p>
      {adding && (
        <BlockDialog
          network=""
          onClose={(blocked) => {
            setAdding(false);
            if (blocked) load();
          }}
        />
      )}
    </div>
  );
}
