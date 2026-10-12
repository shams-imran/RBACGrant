// Mantine v7 theme mapping the CSS tokens; a 10-shade `reddot`
// primary palette generated around #E52445.
import { createTheme, MantineColorsTuple } from '@mantine/core';

const reddot: MantineColorsTuple = [
  '#ffebef', // 0
  '#ffd6d6', // 1
  '#f9a8b4', // 2
  '#f64c6c', // 3
  '#ef3557', // 4
  '#e52445', // 5 — brand primary
  '#cf1f3c', // 6 — hover
  '#bd1e39', // 7 — active
  '#9c1830', // 8
  '#7c1226', // 9
];

export const theme = createTheme({
  primaryColor: 'reddot',
  primaryShade: { light: 5, dark: 3 },
  colors: { reddot },
  fontFamily: "'Inter', system-ui, sans-serif",
  fontFamilyMonospace: "'Geist Mono', ui-monospace, monospace",
  headings: { fontFamily: "'Poppins', 'Inter', sans-serif" },
  defaultRadius: 'md',
});
