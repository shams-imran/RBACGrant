import { ComboboxItem, OptionsFilter } from '@mantine/core';

// Autocomplete's default filter hides every other option once the field holds
// a picked/prefilled value (e.g. "default"), which makes the list look empty.
// Show the full list when the field is empty or exactly equals an option;
// otherwise do a substring filter.
export const showAllFilter: OptionsFilter = ({ options, search }) => {
  const items = options as ComboboxItem[];
  const q = (search ?? '').trim().toLowerCase();
  if (!q || items.some((o) => o.label.toLowerCase() === q)) return items;
  return items.filter((o) => o.label.toLowerCase().includes(q));
};
