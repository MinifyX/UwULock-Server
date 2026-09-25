import type { ReactNode } from 'react';
import { NYU, NyuFigure, Paw, Sticker } from './Nyu';

// Every scene is drawn on a 320 × 220 canvas, the same as UwUMail's. Nyu sits
// at about 0.6 scale, so props use a 6 px outline and an 18 px edge to match.

const S = { stroke: NYU.outline, strokeWidth: 6 } as const;
const EDGE = 18;
/** Nyu's own edge at scene scale: 30 × 0.6 ≈ the props' 18 px. */
const NYU_EDGE = 30;

export function Shadow({ cx = 160, rx = 104 }: { cx?: number; rx?: number }) {
  return (
    <ellipse
      className="no-edge"
      cx={cx}
      cy="204"
      rx={rx}
      ry="8"
      fill={NYU.outline}
      opacity="0.08"
    />
  );
}

export function Star({
  x,
  y,
  r = 12,
  className,
}: {
  x: number;
  y: number;
  r?: number;
  className?: string;
}) {
  const k = r * 0.2;
  return (
    <path
      className={className}
      d={`M${x} ${y - r} Q${x + k} ${y - k} ${x + r} ${y} Q${x + k} ${y + k} ${x} ${y + r} Q${x - k} ${y + k} ${x - r} ${y} Q${x - k} ${y - k} ${x} ${y - r}Z`}
      fill={NYU.star}
      stroke={NYU.outline}
      strokeWidth={r > 10 ? 4 : 3}
    />
  );
}

export function Heart({
  x,
  y,
  size = 1,
  fill = NYU.body,
}: {
  x: number;
  y: number;
  size?: number;
  fill?: string;
}) {
  return (
    <path
      transform={`translate(${x} ${y}) scale(${size})`}
      d="M0 13 C-15 3 -18 -4 -17 -8 C-16 -15 -7 -16 -3 -11 L0 -8 L3 -11 C7 -16 16 -15 17 -8 C18 -4 15 3 0 13Z"
      fill={fill}
      stroke={NYU.outline}
      strokeWidth={4 / size}
    />
  );
}

/** The key Nyu guards, as on the app icon. */
export function Key({
  x,
  y,
  rotate = 0,
  size = 1,
}: {
  x: number;
  y: number;
  rotate?: number;
  size?: number;
}) {
  return (
    <g transform={`translate(${x} ${y}) rotate(${rotate}) scale(${size})`}>
      <g fill="none" stroke={NYU.outline} strokeWidth={6}>
        <path d="M0 4 V40 M0 24 H13 M0 35 H10" />
      </g>
      <circle cx="0" cy="-9" r="13" fill={NYU.lilac} {...S} />
      <circle className="no-edge" cx="0" cy="-9" r="4.5" fill={NYU.tile} />
    </g>
  );
}

/**
 * A little login card, the kind Nyu keeps safe: a key badge, a name line and
 * a row of password dots (the last one blinking with `cursor`).
 */
export function VaultCard({
  x,
  y,
  rotate = 0,
  cursor = false,
}: {
  x: number;
  y: number;
  rotate?: number;
  cursor?: boolean;
}) {
  return (
    <g transform={`translate(${x} ${y}) rotate(${rotate})`}>
      <rect x="-28" y="-19" width="56" height="38" rx="8" fill={NYU.paper} {...S} strokeWidth={5} />
      <circle className="no-edge" cx="-15" cy="-6" r="6" fill={NYU.body} />
      <rect className="no-edge" x="-5" y="-9" width="24" height="5" rx="2.5" fill={NYU.screen} />
      <g className="no-edge" fill={NYU.outline}>
        <circle cx="-17" cy="9" r="2.6" />
        <circle cx="-9" cy="9" r="2.6" />
        <circle cx="-1" cy="9" r="2.6" />
        <circle cx="7" cy="9" r="2.6" />
        <circle className={cursor ? 'nyu-cursor' : undefined} cx="15" cy="9" r="2.6" />
      </g>
    </g>
  );
}

/** First start: Nyu says hello. */
function Welcome() {
  return (
    <>
      <Shadow />
      <path
        d="M246 44 q12 9 10 25 M262 32 q16 13 14 35"
        fill="none"
        stroke={NYU.outline}
        strokeWidth={4}
        opacity="0.4"
      />
      <NyuFigure
        mood="happy"
        x={150}
        y={134}
        scale={0.62}
        tilt={-6}
        edge={NYU_EDGE}
        front={<Paw x={238} y={104} className="nyu-wave" />}
      />
      <Sticker edge={12}>
        <Heart x={50} y={62} size={0.95} />
        <Star x={286} y={150} r={11} />
        <Star x={36} y={150} r={8} />
      </Sticker>
      <Sticker edge={EDGE}>
        <Key x={250} y={176} rotate={62} size={0.9} />
      </Sticker>
    </>
  );
}

const CONFETTI: [x: number, y: number, rotate: number, fill: string][] = [
  [42, 40, -20, NYU.body],
  [78, 16, 30, NYU.star],
  [118, 30, 70, NYU.mint],
  [210, 22, -40, NYU.lilac],
  [250, 44, 15, NYU.body],
  [284, 20, 60, NYU.sky],
  [30, 108, 45, NYU.sky],
  [292, 104, -30, NYU.star],
  [48, 170, 20, NYU.lilac],
  [276, 172, -60, NYU.mint],
];

/** Setup done: Nyu cheers with both paws up. */
function Done() {
  return (
    <>
      <Shadow />
      <Sticker edge={10}>
        {CONFETTI.map(([x, y, rotate, fill]) => (
          <rect
            key={`${x}-${y}`}
            x={x - 7}
            y={y - 4}
            width="14"
            height="8"
            rx="2"
            transform={`rotate(${rotate} ${x} ${y})`}
            fill={fill}
            stroke={NYU.outline}
            strokeWidth={3}
          />
        ))}
      </Sticker>
      <NyuFigure
        mood="cheer"
        x={160}
        y={138}
        scale={0.62}
        edge={NYU_EDGE}
        front={
          <>
            <Paw x={24} y={112} />
            <Paw x={232} y={112} />
          </>
        }
      />
      <Sticker edge={12}>
        <Star x={160} y={34} r={11} />
      </Sticker>
    </>
  );
}

/** Something failed: Nyu got tangled in a network cable. */
function LoadError() {
  const cable = 'M34 190 C66 160 90 208 124 176 S206 118 210 160 S140 180 182 198 S246 194 256 176';
  return (
    <>
      <Shadow cx={150} />
      <NyuFigure mood="sad" x={146} y={122} scale={0.6} tilt={6} edge={NYU_EDGE} />
      <Sticker edge={16}>
        <path d={cable} fill="none" stroke={NYU.outline} strokeWidth={12} />
      </Sticker>
      <path d={cable} fill="none" stroke={NYU.violet} strokeWidth={5} />
      <Sticker edge={EDGE}>
        <g transform="rotate(-28 270 168)">
          <path d="M284 162 h12 M284 174 h12" stroke={NYU.outline} strokeWidth={5} />
          <rect x="254" y="156" width="32" height="24" rx="6" fill={NYU.lilac} {...S} />
        </g>
      </Sticker>
    </>
  );
}

/** Something needs a decision first: Nyu holds up a page with a question mark. */
function Puzzled() {
  return (
    <>
      <Shadow cx={150} />
      <NyuFigure mood="puzzled" x={112} y={134} scale={0.6} tilt={-8} edge={NYU_EDGE} />
      <Sticker edge={EDGE}>
        <g transform="rotate(8 226 118)">
          <path d="M190 58 H240 L262 80 V176 H190Z" fill={NYU.paper} {...S} />
          <path d="M240 58 V80 H262" fill={NYU.screen} {...S} />
          <path
            d="M212 106 q0 -15 15 -15 q15 0 15 13 q0 10 -13 14 v8"
            fill="none"
            stroke={NYU.body}
            strokeWidth={9}
          />
          <circle cx="229" cy="145" r="5.5" fill={NYU.body} />
        </g>
        <ellipse cx="186" cy="138" rx="12" ry="10" fill={NYU.body} {...S} />
      </Sticker>
    </>
  );
}

/** Nothing picked: Nyu points at the list, a login card waiting next to her. */
function Pick() {
  return (
    <>
      <Shadow cx={170} />
      <Sticker edge={EDGE}>
        <VaultCard x={264} y={70} rotate={10} cursor />
      </Sticker>
      <NyuFigure
        mood="happy"
        x={168}
        y={134}
        scale={0.6}
        tilt={4}
        edge={NYU_EDGE}
        front={<Paw x={16} y={130} className="nyu-wave" />}
      />
      <path d="M34 118 h-18 M40 132 h-14" stroke={NYU.outline} strokeWidth={4} opacity="0.35" />
      <Sticker edge={12}>
        <Star x={290} y={172} r={9} />
        <Star x={46} y={52} r={11} />
      </Sticker>
    </>
  );
}

/** Saying goodbye: Nyu waves with a little tear. */
function Goodbye() {
  return (
    <>
      <Shadow />
      <NyuFigure
        mood="sad"
        x={160}
        y={134}
        scale={0.62}
        tilt={4}
        edge={NYU_EDGE}
        front={<Paw x={240} y={104} className="nyu-wave" />}
      />
      <Sticker edge={12}>
        <Heart x={58} y={58} size={0.85} fill={NYU.lilac} />
        <Star x={280} y={40} r={9} />
      </Sticker>
    </>
  );
}

/** The vault: Nyu, the padlock, holds up her key, a login card tucked beside her. */
function Vault() {
  return (
    <>
      <Shadow cx={160} rx={96} />
      <NyuFigure
        mood="happy"
        x={138}
        y={132}
        scale={0.58}
        tilt={-5}
        edge={NYU_EDGE}
        front={<Paw x={230} y={120} />}
      />
      <Sticker edge={EDGE}>
        <g className="nyu-bob">
          <Key x={262} y={86} rotate={28} size={1.1} />
        </g>
      </Sticker>
      <Sticker edge={EDGE}>
        <VaultCard x={56} y={170} rotate={-12} />
      </Sticker>
      <Sticker edge={12}>
        <Heart x={284} y={170} size={0.7} />
        <Star x={40} y={60} r={9} className="nyu-twinkle" />
      </Sticker>
    </>
  );
}

/** Syncing: Nyu carries a plug to the server, sparks flying. */
function Connecting() {
  return (
    <>
      <Shadow cx={150} />
      <path
        className="nyu-cable"
        d="M20 190 C60 150 90 196 128 170"
        fill="none"
        stroke={NYU.violet}
        strokeWidth={6}
      />
      <g className="nyu-hop">
        <NyuFigure
          mood="cheer"
          x={150}
          y={128}
          scale={0.56}
          tilt={-4}
          edge={NYU_EDGE}
          front={<Paw x={236} y={140} />}
        />
      </g>
      <Sticker edge={EDGE}>
        <g className="nyu-plug">
          <rect x="248" y="112" width="30" height="24" rx="6" fill={NYU.lilac} {...S} />
          <path d="M278 118 h14 M278 130 h14" stroke={NYU.outline} strokeWidth={5} />
        </g>
      </Sticker>
      <Sticker edge={10}>
        <g className="nyu-sparks">
          <Star x={300} y={100} r={8} />
          <Star x={292} y={150} r={6} />
        </g>
      </Sticker>
    </>
  );
}

/** Files: Nyu carries a cardboard box across. */
function Files() {
  return (
    <>
      <Shadow cx={160} />
      <g className="nyu-walk">
        <NyuFigure mood="happy" x={150} y={120} scale={0.55} tilt={3} edge={NYU_EDGE} />
        <Sticker edge={EDGE}>
          <g transform="rotate(-6 160 172)">
            <rect x="112" y="150" width="96" height="50" rx="6" fill={NYU.kraft} {...S} />
            <path d="M112 164 h96" stroke={NYU.outline} strokeWidth={5} />
            <rect
              className="no-edge"
              x="148"
              y="150"
              width="24"
              height="14"
              fill={NYU.kraftLight}
            />
          </g>
          <Paw x={112} y={170} />
          <Paw x={208} y={166} />
        </Sticker>
      </g>
      <Sticker edge={12}>
        <Heart x={48} y={70} size={0.7} fill={NYU.mint} />
        <Star x={278} y={58} r={9} className="nyu-twinkle" />
      </Sticker>
    </>
  );
}

/** Keys: Nyu holds up a freshly made key, glowing — a sync pairing, say. */
function Keys() {
  return (
    <>
      <Shadow cx={150} />
      <NyuFigure
        mood="sparkle"
        x={140}
        y={132}
        scale={0.58}
        tilt={-3}
        edge={NYU_EDGE}
        front={<Paw x={226} y={96} />}
      />
      <Sticker edge={EDGE}>
        <g className="nyu-bob">
          <Key x={262} y={70} rotate={24} size={1.2} />
        </g>
      </Sticker>
      <Sticker edge={10}>
        <g className="nyu-sparks">
          <Star x={296} y={36} r={9} />
          <Star x={232} y={34} r={6} />
          <Star x={300} y={112} r={6} />
        </g>
      </Sticker>
    </>
  );
}

/** Nothing going on: Nyu naps, a little "z" floating up. */
function Sleepy() {
  return (
    <>
      <Shadow cx={160} rx={90} />
      <NyuFigure mood="sleepy" x={160} y={140} scale={0.6} tilt={8} edge={NYU_EDGE} />
      <g className="nyu-zzz" fill="none" stroke={NYU.violet} strokeWidth={5}>
        <path d="M232 70 h16 l-16 16 h16" />
        <path d="M258 40 h11 l-11 11 h11" />
      </g>
    </>
  );
}

const SCENES = {
  welcome: Welcome,
  done: Done,
  loadError: LoadError,
  puzzled: Puzzled,
  pick: Pick,
  goodbye: Goodbye,
  vault: Vault,
  connecting: Connecting,
  files: Files,
  keys: Keys,
  sleepy: Sleepy,
} satisfies Record<string, () => ReactNode>;

export type SceneName = keyof typeof SCENES;

/** A small illustration of Nyu for empty and error states. Decorative only. */
export function NyuScene({ name, className }: { name: SceneName; className?: string }) {
  const Scene = SCENES[name];
  return (
    <svg
      viewBox="-10 -10 340 230"
      className={className ? `nyu-host nyu-blink ${className}` : 'nyu-host nyu-blink'}
      style={{ overflow: 'visible' }}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <Scene />
    </svg>
  );
}
