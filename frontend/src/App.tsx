import React, { useState } from 'react';
import { IncidentProvider, useIncident } from './context/IncidentContext';
import { Header } from './components/layout/Header';
import { Sidebar, PageTab } from './components/layout/Sidebar';
import { OverviewPage } from './pages/OverviewPage';
import { IncidentPage } from './pages/IncidentPage';
import { GraphPage } from './pages/GraphPage';
import { HistoricalPage } from './pages/HistoricalPage';
import { PredictionPage } from './pages/PredictionPage';
import { ExplanationPage } from './pages/ExplanationPage';
import { InvestigationPage } from './pages/InvestigationPage';

const DashboardContent: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<PageTab>('overview');
  const { setActiveIncidentId } = useIncident();

  const handleNavigate = (tab: PageTab, incidentId?: string) => {
    if (incidentId) {
      setActiveIncidentId(incidentId);
    }
    setCurrentTab(tab);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>
      <Header />
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <Sidebar currentTab={currentTab} onSelectTab={setCurrentTab} />
        <main style={{ flex: 1, overflowY: 'auto', backgroundColor: 'var(--bg-primary)' }}>
          {currentTab === 'overview' && <OverviewPage onNavigate={handleNavigate} />}
          {currentTab === 'incident' && <IncidentPage />}
          {currentTab === 'graph' && <GraphPage />}
          {currentTab === 'historical' && <HistoricalPage />}
          {currentTab === 'prediction' && <PredictionPage />}
          {currentTab === 'explanation' && <ExplanationPage />}
          {currentTab === 'investigation' && <InvestigationPage />}
        </main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <IncidentProvider>
      <DashboardContent />
    </IncidentProvider>
  );
};

export default App;
