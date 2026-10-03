import type { ReactNode } from 'react';

/** A single aligned row of labelled controls (selects, inputs, run button) inside a card. */
export function Toolbar({ children }: { children: ReactNode }) {
  return (
    <div className="card px-4 py-3">
      <div className="flex flex-wrap items-end gap-x-4 gap-y-3">{children}</div>
    </div>
  );
}
