// Accessibility checks with axe-core, for the browser tests: one call per page or state worth
// looking at. axe comes from the package here (never a CDN) and goes into the page once per
// page load; a check takes a few hundred milliseconds.
//
//   import { checkA11y } from './axe.mjs';
//   await checkA11y(page, 'login page');
//
// Serious and critical findings fail the test; minor and moderate ones are printed as notes.

import { createRequire } from 'node:module';

const axePath = createRequire(import.meta.url).resolve('axe-core/axe.min.js');

/** The WCAG 2.0, 2.1 and 2.2 rules of level A and AA: what UwULock aims for. */
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

/** Checks what `page` shows now; throws when axe finds something serious or critical. */
export async function checkA11y(page, name) {
  const started = Date.now();
  if (!(await page.evaluate(() => 'axe' in window))) await page.addScriptTag({ path: axePath });
  const violations = await page.evaluate(async (tags) => {
    const result = await window.axe.run(document, {
      runOnly: { type: 'tag', values: tags },
      resultTypes: ['violations'],
    });
    return result.violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      help: v.help,
      url: v.helpUrl,
      targets: v.nodes.slice(0, 5).map((node) => node.target.join(' ')),
      more: Math.max(0, v.nodes.length - 5),
    }));
  }, TAGS);

  const describe = (v) =>
    `  ${v.impact} ${v.id}: ${v.help}\n    ${v.targets.join('\n    ')}` +
    `${v.more ? `\n    … and ${v.more} more` : ''}\n    ${v.url}`;
  const serious = violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
  const notes = violations.filter((v) => !serious.includes(v));
  const took = `${Date.now() - started} ms`;
  if (notes.length) console.log(`axe notes for ${name}:\n${notes.map(describe).join('\n')}`);
  if (serious.length) {
    throw new Error(`axe: ${name}: ${serious.length} serious problems (${took})\n${serious.map(describe).join('\n')}`);
  }
  console.log(`   axe: ${name} ok (${took})`);
}
