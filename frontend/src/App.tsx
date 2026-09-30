import { BrowserRouter, Routes, Route, Outlet } from 'react-router-dom';
import { ScenarioProvider } from './context/ScenarioContext';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { Dashboard } from './features/dashboard/Dashboard';
import { ScenarioPage } from './features/scenario/ScenarioPage';
import { AssetsPage } from './features/assets/AssetsPage';
import { FindingsPage } from './features/findings/FindingsPage';
import { PrioritizationPage } from './features/prioritization/PrioritizationPage';
import { AttackPathsPage } from './features/attack-paths/AttackPathsPage';
import { BlastRadiusPage } from './features/blast-radius/BlastRadiusPage';
import { ChokepointsPage } from './features/chokepoints/ChokepointsPage';
import { RemediationPage } from './features/remediation/RemediationPage';
import { OptimizationPage } from './features/optimization/OptimizationPage';
import { ExplanationPage } from './features/explanation/ExplanationPage';
import { useScenario } from './context/ScenarioContext';
import { useState } from 'react';

function Layout() {
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

export default function App() {
  return (
    <BrowserRouter>
      <ScenarioProvider>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="scenario" element={<ScenarioPage />} />
            <Route path="assets" element={<AssetsPage />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="prioritization" element={<PrioritizationPage />} />
            <Route path="attack-paths" element={<AttackPathsPage />} />
            <Route path="blast-radius" element={<BlastRadiusPage />} />
            <Route path="chokepoints" element={<ChokepointsPage />} />
            <Route path="remediation" element={<RemediationPage />} />
            <Route path="optimization" element={<OptimizationPage />} />
            <Route path="explanation" element={<ExplanationPage />} />
          </Route>
        </Routes>
      </ScenarioProvider>
    </BrowserRouter>
  );
}
