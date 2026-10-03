import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { useScenario } from '../../context/ScenarioContext';
import { useState } from 'react';

export function Layout() {
  const { scenarios, selectedScenario, setSelectedScenario, isLoadingScenarios } = useScenario();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[var(--color-bg-primary)]">
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="lg:pl-64 flex flex-col min-h-screen">
        <Header
          onMenuClick={() => setSidebarOpen(true)}
          scenarios={scenarios}
          selectedScenario={selectedScenario}
          onScenarioChange={setSelectedScenario}
          isLoadingScenarios={isLoadingScenarios}
        />
        <main className="flex-1 px-4 py-6 lg:px-8 lg:py-8">
          <div className="mx-auto w-full max-w-[1600px]">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
