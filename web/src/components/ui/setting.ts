import { createContext, useContext } from 'react';

/** The ids of a SettingRow's name and description, for the control inside it. */
export const SettingContext = createContext<{ labelId: string; descriptionId?: string } | null>(
  null,
);

/**
 * Inside a SettingRow: its name's and description's ids. A switch or a select there takes the
 * description as its own, so a screen reader reads what the setting does along with its state.
 */
export function useSettingRow() {
  return useContext(SettingContext);
}
