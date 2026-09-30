import type { ReactNode } from 'react';
import { Card, CardBody, Button } from '../../components/ui';

interface PlaceholderPageProps {
  title: string;
  description: string;
  icon: ReactNode;
  phase: string;
}

export function PlaceholderPage({ title, description, icon, phase }: PlaceholderPageProps) {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="page-title">{title}</h1>
        <span className="badge-warning">{phase}</span>
      </div>

      <Card>
        <CardBody className="flex flex-col items-center justify-center min-h-[400px] text-center">
          <div className="w-16 h-16 rounded-xl bg-[var(--color-bg-tertiary)] flex items-center justify-center text-[var(--color-text-muted)] mb-6">
            {icon}
          </div>
          <h2 className="text-xl font-medium text-[var(--color-text-primary)] mb-2">
            {title} - Coming in {phase}
          </h2>
          <p className="text-[var(--color-text-secondary)] max-w-md mb-6">
            {description}
          </p>
          <Button variant="secondary" disabled>
            Not implemented yet
          </Button>
        </CardBody>
      </Card>
    </div>
  );
}