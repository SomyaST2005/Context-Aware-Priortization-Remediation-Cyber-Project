import type { HTMLAttributes } from 'react';

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: 'default' | 'critical' | 'high' | 'medium' | 'low' | 'none' | 'success' | 'warning';
}

export function Badge({ variant = 'default', className = '', children, ...props }: BadgeProps) {
  const variantClasses = {
    default: 'bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)]',
    critical: 'bg-[var(--color-critical)]/10 text-[var(--color-critical)]',
    high: 'bg-[var(--color-high)]/10 text-[var(--color-high)]',
    medium: 'bg-[var(--color-medium)]/10 text-[var(--color-medium)]',
    low: 'bg-[var(--color-low)]/10 text-[var(--color-low)]',
    none: 'bg-[var(--color-none)]/10 text-[var(--color-none)]',
    success: 'bg-[var(--color-success)]/10 text-[var(--color-success)]',
    warning: 'bg-[var(--color-warning)]/10 text-[var(--color-warning)]',
  };

  return (
    <span
      className={`badge ${variantClasses[variant]} ${className}`}
      {...props}
    >
      {children}
    </span>
  );
}