import { NavLink } from 'react-router-dom';
import {
  Bot,
  Bug,
  Database,
  GitBranch,
  LayoutDashboard,
  Link2,
  ListOrdered,
  Radar,
  Server,
  ShieldCheck,
  Zap,
  type LucideIcon,
} from 'lucide-react';

interface SidebarProps {
  isOpen: boolean;
  onClose: () => void;
}

interface NavItem {
  path: string;
  label: string;
  icon: LucideIcon;
}

const navigation: Array<{ group: string; items: NavItem[] }> = [
  { group: 'Overview', items: [{ path: '/', label: 'Dashboard', icon: LayoutDashboard }] },
  {
    group: 'Analysis',
    items: [
      { path: '/scenario', label: 'Scenario', icon: Database },
      { path: '/assets', label: 'Assets', icon: Server },
      { path: '/findings', label: 'Findings', icon: Bug },
      { path: '/prioritization', label: 'Prioritization', icon: ListOrdered },
      { path: '/attack-paths', label: 'Attack Paths', icon: GitBranch },
      { path: '/blast-radius', label: 'Blast Radius', icon: Radar },
      { path: '/chokepoints', label: 'Chokepoints', icon: Link2 },
    ],
  },
  {
    group: 'Remediation',
    items: [
      { path: '/remediation', label: 'What-If Simulation', icon: ShieldCheck },
      { path: '/optimization', label: 'Optimization', icon: Zap },
    ],
  },
  { group: 'Intelligence', items: [{ path: '/explanation', label: 'AI Explanation', icon: Bot }] },
];

export function Sidebar({ isOpen, onClose }: SidebarProps) {
  return (
    <>
      {isOpen && (
        <div className="fixed inset-0 bg-black/50 z-40 lg:hidden" onClick={onClose} aria-hidden="true" />
      )}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-64 bg-[var(--color-bg-secondary)] border-r border-[var(--color-border-primary)] transform transition-transform duration-200 ease-in-out lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
        aria-label="Main navigation"
      >
        <div className="flex flex-col h-full">
          {/* Brand */}
          <div className="flex items-center gap-3 px-5 h-16 shrink-0 border-b border-[var(--color-border-primary)]">
            <div className="w-8 h-8 rounded-lg bg-[var(--color-accent)] flex items-center justify-center">
              <ShieldCheck className="w-4 h-4 text-[var(--color-bg-primary)]" aria-hidden="true" />
            </div>
            <div className="leading-tight">
              <p className="text-base font-semibold text-[var(--color-text-primary)]">RiskPath</p>
              <p className="text-[11px] text-[var(--color-text-muted)]">Attack-path risk analysis</p>
            </div>
          </div>

          {/* Navigation */}
          <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5" aria-label="Main">
            {navigation.map((group) => (
              <div key={group.group}>
                <p className="px-3 mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">
                  {group.group}
                </p>
                <div className="space-y-0.5">
                  {group.items.map((item) => (
                    <NavLink
                      key={item.path}
                      to={item.path}
                      end={item.path === '/'}
                      onClick={onClose}
                      className={({ isActive }) => `sidebar-link ${isActive ? 'sidebar-link-active' : ''}`}
                    >
                      <item.icon className="w-4 h-4 shrink-0" aria-hidden="true" />
                      {item.label}
                    </NavLink>
                  ))}
                </div>
              </div>
            ))}
          </nav>

          <div className="px-5 py-3 border-t border-[var(--color-border-primary)]">
            <p className="text-[11px] text-[var(--color-text-muted)]">Security Decision Platform</p>
          </div>
        </div>
      </aside>
    </>
  );
}
