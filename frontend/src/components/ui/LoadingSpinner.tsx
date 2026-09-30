import type { HTMLAttributes } from 'react';

interface LoadingSpinnerProps extends HTMLAttributes<HTMLDivElement> {
  size?: 'sm' | 'md' | 'lg';
}

export function LoadingSpinner({ size = 'md', className = '', ...props }: LoadingSpinnerProps) {
  const sizeClasses = {
    sm: 'w-4 h-4 border-1.5',
    md: 'w-5 h-5 border-2',
    lg: 'w-8 h-8 border-2',
  };

  return (
    <div
      className={`loading-spinner ${sizeClasses[size]} ${className}`}
      role="status"
      aria-label="Loading"
      {...props}
    >
      <span className="sr-only">Loading...</span>
    </div>
  );
}

export function LoadingOverlay({ message = 'Loading...' }: { message?: string }) {
  return (
    <div className="fixed inset-0 bg-[var(--color-bg-primary)]/90 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="flex flex-col items-center gap-4">
        <LoadingSpinner size="lg" />
        <p className="text-[var(--color-text-secondary)]">{message}</p>
      </div>
    </div>
  );
}