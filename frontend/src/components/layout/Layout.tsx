import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { useScenario } from '../../context/ScenarioContext';
import { useState } from 'react';

export function Layout() {
  const { selectedScenario, setSelectedScenario, isLoadingScenarios } = useScenario();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[var(--color-bg-primary)]">
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="lg:pl-64 flex flex-col min-h-screen">
        <Header
          onMenuClick={() => setSidebarOpen(true)}
          selectedScenario={selectedScenario}
          onScenarioChange={setSelectedScenario}
          isLoadingScenarios={isLoadingScenarios}
        />
        <main className="flex-1 p-4 lg:p-6 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}