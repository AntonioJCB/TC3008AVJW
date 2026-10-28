import { useEffect, useState } from 'react';
import { useParams } from 'react-router';
import DashboardHeader from './components/header/DashboardHeader';
import DashboardSidebar from './components/sidebar/DashboardSidebar';
import DemoAnalysisDialog from './components/DemoAnalysisDialog';
import { navigation, type DashboardSection } from './navigation';
import { demoProject } from './services/demoData';
import OverviewScreen from './screens/overview/OverviewScreen';
import AssetsScreen from './screens/assets/AssetsScreen';
import RelationsScreen from './screens/relations/RelationsScreen';
import SourcesScreen from './screens/sources/SourcesScreen';
import FindingsScreen from './screens/findings/FindingsScreen';
import HistoryScreen from './screens/history/HistoryScreen';
import AssistantScreen from './screens/assistant/AssistantScreen';
import SettingsScreen from './screens/settings/SettingsScreen';
import './dashboard.css';

const screens: Record<DashboardSection, React.ComponentType> = {
  resumen: OverviewScreen,
  activos: AssetsScreen,
  relaciones: RelationsScreen,
  fuentes: SourcesScreen,
  hallazgos: FindingsScreen,
  historial: HistoryScreen,
  asistente: AssistantScreen,
  configuracion: SettingsScreen,
};

export default function DashboardPage() {
  const { section } = useParams();
  const activeSection: DashboardSection =
    section && section in screens ? (section as DashboardSection) : 'resumen';
  const [analysisDialogOpen, setAnalysisDialogOpen] = useState(false);
  const ActiveScreen = screens[activeSection];
  const activeLabel =
    navigation.find((item) => item.section === activeSection)?.label ??
    'Resumen';

  useEffect(() => {
    document.title = `BaxterSec · ${activeLabel}`;
  }, [activeLabel]);

  return (
    <div className="dashboard-shell proposal-dashboard">
      <DashboardSidebar />
      <div className="dashboard-main">
        <DashboardHeader onNewAnalysis={() => setAnalysisDialogOpen(true)} />
        <main
          className={`dashboard-content${activeSection === 'relaciones' ? ' relations-content' : ''}`}>
          <div className="dashboard-view" key={activeSection}>
            {activeSection !== 'resumen' &&
              activeSection !== 'activos' &&
              activeSection !== 'relaciones' && (
                <div className="content-intro proposal-section-intro">
                  <div>
                    <div className="eyebrow">
                      {demoProject.domain} / VISTA DEMO
                    </div>
                    <h1>{activeLabel}</h1>
                    <p>
                      Escenario ficticio de {demoProject.company}. Ninguna
                      fuente externa está conectada.
                    </p>
                  </div>
                </div>
              )}
            <ActiveScreen />
          </div>
        </main>
      </div>
      {analysisDialogOpen && (
        <DemoAnalysisDialog onClose={() => setAnalysisDialogOpen(false)} />
      )}
    </div>
  );
}
