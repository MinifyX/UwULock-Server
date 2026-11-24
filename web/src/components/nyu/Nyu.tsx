/**
 * Nyu, the padlock cat, from @uwusuite/design: the suite's palette, the
 * sticker edge, the ears and the face are the package's; the padlock shell is
 * UwULock's. The shackle arches up between the ears, a keyhole sits on her
 * forehead, and the plate on the lock body is the face — where the package's
 * NyuFace expects it, so every mood and scene fits.
 *
 * `Nyu` on its own (title bar, empty states, the update hint) is the
 * package's `<Nyu shell="lock">`. `NyuFigure` is the same cat as a group for
 * the scenes, with extra parts behind and in front, eyes that look somewhere,
 * and a place, size and tilt of her own.
 *
 * The colours are fixed artwork, not theme tokens: a sticker looks like itself
 * in dark mode too, and the white die-cut edge is what keeps the outlines
 * readable on a dark ground.
 *
 * Nothing in here may depend on the
 * app's stylesheet beyond the package's `nyu.css`.
 */

import { NYU, Nyu as SuiteNyu, NyuEars, NyuFace, Sticker, type NyuMood } from '@uwusuite/design';
import type { ReactNode } from 'react';

export { NYU, Sticker, type NyuMood };

/**
 * A paw in Nyu's own coordinates (the body spans 28–228 × 74–220; the
 * shackle arches above it, up to 11). A little bigger than the package's, to
 * match the padlock's 9 px outline.
 */
export function Paw({ x, y, className }: { x: number; y: number; className?: string }) {
  return (
    <g className={className}>
      <ellipse cx={x} cy={y} rx="19" ry="16" fill={NYU.body} stroke={NYU.ink} strokeWidth={9} />
      <path
        d={`M${x - 5} ${y + 3} v6 M${x + 5} ${y + 3} v6`}
        fill="none"
        stroke={NYU.ink}
        strokeWidth={5}
      />
    </g>
  );
}

type FigureProps = {
  mood?: NyuMood;
  /** Centre of the body in the parent's coordinates. */
  x?: number;
  y?: number;
  /** 1 is the size of the app symbol: the body is 200 wide. */
  scale?: number;
  tilt?: number;
  /** Extra parts in Nyu's own coordinates. */
  behind?: ReactNode;
  front?: ReactNode;
  /** Replaces the mood's eyes, e.g. pupils that follow something. The mouth stays the mood's. */
  eyes?: ReactNode;
  /** The white die-cut edge, in Nyu's own coordinates. */
  edge?: number;
};

/** Nyu as a group, for scenes: placed, scaled and tilted in the parent's coordinates. */
export function NyuFigure({
  mood = 'uwu',
  x = 128,
  y = 147,
  scale = 1,
  tilt = 0,
  behind,
  front,
  eyes,
  edge = 20,
}: FigureProps) {
  return (
    <g
      transform={`translate(${x} ${y}) rotate(${tilt}) scale(${scale}) translate(-128 -147)`}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <Sticker edge={edge}>
        {behind}
        <path
          className="nyu-shackle"
          d="M83 84 V56 A45 45 0 0 1 173 56 V84 H147 V56 A19 19 0 0 0 109 56 V84 Z"
          fill={NYU.lilac}
          stroke={NYU.ink}
          strokeWidth={9}
        />
        <NyuEars />
        <rect
          x={28}
          y={74}
          width={200}
          height={146}
          rx={24}
          fill={NYU.body}
          stroke={NYU.ink}
          strokeWidth={9}
        />
        <g className="no-edge" fill={NYU.ink}>
          <circle cx={128} cy={95} r={6.5} />
          <path d="M124.5 98 L122 108.5 H134 L131.5 98 Z" />
        </g>
        <rect
          x={44}
          y={116}
          width={168}
          height={88}
          rx={16}
          fill={NYU.flap}
          stroke={NYU.ink}
          strokeWidth={7}
        />
        <NyuFace mood={mood} eyes={eyes} />
        {front}
      </Sticker>
    </g>
  );
}

type NyuProps = {
  size?: number;
  mood?: NyuMood;
  /** Blinking is on by default and stops on its own when motion is reduced. */
  blink?: boolean;
  title?: string;
};

/** The symbol on its own: title bar, empty states, the update hint. */
export function Nyu({ size = 96, mood = 'uwu', blink = true, title = 'Nyu' }: NyuProps) {
  return <SuiteNyu shell="lock" mood={mood} size={size} blink={blink} title={title} />;
}
