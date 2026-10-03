import { Badge } from './Badge';

const VARIANTS: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'none'> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  NONE: 'none',
};

/** Severity pill. Colour is reserved for real severity categories from the backend. */
export function SeverityBadge({ severity }: { severity: string }) {
  return <Badge variant={VARIANTS[severity] ?? 'none'}>{severity}</Badge>;
}
