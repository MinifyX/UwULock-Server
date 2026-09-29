import { useState } from 'react';
import type { ItemKind, ItemSummary } from '../lib/api';
import { automaticIcon, hasOwnIcon, ownIcon, useComfort } from '../lib/comfort';
import { useSettings } from '../lib/settings';
import { Icon, type IconName } from './Icon';

const KIND_ICON: Record<ItemKind, IconName> = {
  login: 'globe',
  card: 'card',
  identity: 'id',
  note: 'note',
  'ssh-key': 'key',
};

/** Six soft tile colours; each item keeps its own, by name. */
const HUES = 6;

function hue(text: string): number {
  let hash = 0;
  for (const char of text) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  return hash % HUES;
}

/**
 * The little square in front of an item: its own icon, else the website's (fetched by this
 * server, never by the browser from the website), else the first letter of a login's name or
 * what kind of item it is.
 */
export function ItemTile({
  item,
  size = 'small',
}: {
  item: ItemSummary;
  size?: 'small' | 'large';
}) {
  useComfort();
  const settings = useSettings();
  const [failed, setFailed] = useState<string | null>(null);
  const own = ownIcon(item.id);
  const automatic =
    settings.showIcons && item.kind === 'login' && !hasOwnIcon(item.id)
      ? automaticIcon(item.host)
      : null;
  const picture = own ?? (automatic && automatic !== failed ? automatic : null);
  const letter = (item.name || item.host || '?').trim().charAt(0).toUpperCase();
  return (
    <span
      className="item-tile"
      data-size={size}
      data-hue={hue(item.name || item.id)}
      data-picture={picture ? '' : undefined}
      aria-hidden
    >
      {picture ? (
        <img
          src={picture}
          alt=""
          loading="lazy"
          decoding="async"
          onError={() => {
            if (!own) setFailed(automatic);
          }}
        />
      ) : item.kind === 'login' ? (
        letter
      ) : (
        <Icon name={KIND_ICON[item.kind]} size={size === 'large' ? 24 : 16} />
      )}
    </span>
  );
}
