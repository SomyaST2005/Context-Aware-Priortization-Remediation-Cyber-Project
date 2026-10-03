import type { ReactNode } from 'react';

type Tone = 'accent' | 'danger' | 'warning' | 'success' | 'neutral';

const TONES: Record<Tone, string> = {
  accent: 'bg-[var(--color-accent-bg)] text-[var(--color-accent)]',
  danger: 'bg-[var(--color-danger-bg)] text-[var(--color-danger)]',
  warning: 'bg-[var(--color-warning-bg)] text-[var(--color-warning)]',
  success: 'bg-[var(--color-success-bg)] text-[var(--color-success)]',
  neutral: 'bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]',
};

interface StatCardProps {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon?: ReactNode;
  tone?: Tone;
}

/** Metric tile: label on top, prominent value, supporting context underneath. */
export function StatCard({ label, value, hint, icon, tone = 'accent' }: StatCardProps) {
  return (
    <div className="card p-4 flex items-start justify-between gap-3">
      <div className="min-w-0">
        <p className="text-xs font-medium uppercase tracking-wider text-[var(--color-text-muted)]">{label}</p>
        <p className="mt-1.5 text-2xl font-semibold leading-tight text-[var(--color-text-primary)] truncate font-mono tabular-nums">
          {value}
        </p>
        {hint && <p className="mt-1 text-xs text-[var(--color-text-secondary)]">{hint}</p>}
      </div>
      {icon && (
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${TONES[tone]}`} aria-hidden="true">
          {icon}
        </div>
      )}
    </div>
  );
}
