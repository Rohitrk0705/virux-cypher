import React, { useState } from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { IncidentProvider, useIncident } from './context/IncidentContext';
import { Header } from './components/layout/Header';
import { Sidebar, PageTab } from './components/layout/Sidebar';
import { BackgroundGrid } from './components/common/BackgroundGrid';
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
  const prefersReduced = useReducedMotion();

  const handleNavigate = (tab: PageTab, incidentId?: string) => {
    if (incidentId) {
      setActiveIncidentId(incidentId);
    }
    setCurrentTab(tab);
  };

  const pageVariants = {
    initial: { opacity: 0, y: prefersReduced ? 0 : 8 },
    animate: { opacity: 1, y: 0 },
    exit: { opacity: 0, y: prefersReduced ? 0 : -6 },
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden', position: 'relative' }}>
      <BackgroundGrid />
      <Header />
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden', position: 'relative', zIndex: 1 }}>
        <Sidebar currentTab={currentTab} onSelectTab={setCurrentTab} />
        <main style={{ flex: 1, overflowY: 'auto', backgroundColor: 'transparent', position: 'relative' }}>
          <AnimatePresence mode="wait">
            <motion.div
              key={currentTab}
              variants={pageVariants}
              initial="initial"
              animate="animate"
              exit="exit"
              transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
              style={{ minHeight: '100%' }}
            >
              {currentTab === 'overview' && <OverviewPage onNavigate={handleNavigate} />}
              {currentTab === 'incident' && <IncidentPage />}
              {currentTab === 'graph' && <GraphPage />}
              {currentTab === 'historical' && <HistoricalPage />}
              {currentTab === 'prediction' && <PredictionPage />}
              {currentTab === 'explanation' && <ExplanationPage />}
              {currentTab === 'investigation' && <InvestigationPage />}
            </motion.div>
          </AnimatePresence>
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
