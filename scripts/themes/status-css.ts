/**
 * Prints the status-colour block for every theme, ready to paste into
 * index.css.
 *
 *   npx tsx scripts/themes/status-css.ts
 *
 * The stylesheet holds the values because they have to be right before first
 * paint (see statusColors.ts). This generates them so nobody hand-mixes eleven
 * colours per theme by hand, and `scripts/themes/status.ts` re-derives them
 * afterwards and fails if the two copies have drifted.
 *
 * It was eleven colours across eight themes when this was written and it is
 * eleven across two now - Day and Night. The generator is worth keeping at two:
 * the drift it prevents is between a derivation and a stylesheet, and that is
 * the same hazard whether there are two blocks or eight. It loops
 * `THEME_OPTIONS`, so it needs no edit when that changes.
 */
import { statusColors, STATUS_TOKENS, type StatusColors } from '../../src/services/statusColors';
import { THEME_OPTIONS } from '../../src/lib/themeOptions';
import { contrastRatio } from '../../src/lib/colorMix';
import { PALETTE_BY_THEME } from '../../src/services/themePalettes';

const ORDER: (keyof StatusColors)[] = [
  'success', 'successForeground', 'successMuted',
  'warning', 'warningForeground', 'warningMuted',
  'danger', 'dangerForeground', 'dangerMuted',
  'dangerStrong', 'dangerStrongForeground',
];

for (const { value: theme } of THEME_OPTIONS) {
  const c = statusColors(theme);
  const card = PALETTE_BY_THEME[theme]?.surface.card ?? '#ffffff';
  const selector = theme === 'light' ? ':root' : `.${theme}`;
  console.log(`\n/* ${selector} */`);
  for (const key of ORDER) {
    console.log(`  ${STATUS_TOKENS[key]}: ${c[key]};`);
  }
  console.log(`  /* fill contrast: success ${contrastRatio(c.success, c.successForeground).toFixed(2)}`
    + `, warning ${contrastRatio(c.warning, c.warningForeground).toFixed(2)}`
    + `, danger ${contrastRatio(c.danger, c.dangerForeground).toFixed(2)}`
    + `, strong ${contrastRatio(c.dangerStrong, c.dangerStrongForeground).toFixed(2)}`
    + ` | muted on card: ${contrastRatio(c.successMuted, card).toFixed(2)}`
    + `/${contrastRatio(c.warningMuted, card).toFixed(2)}`
    + `/${contrastRatio(c.dangerMuted, card).toFixed(2)} */`);
}
