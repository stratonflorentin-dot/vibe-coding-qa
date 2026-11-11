import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "@/components/layout/app-shell";
import { ErrorBoundary } from "@/components/common/error-boundary";
import { ArchitecturePage } from "@/pages/architecture";
import { AssistantPage } from "@/pages/assistant";
import { DependenciesPage } from "@/pages/dependencies";
import { FindingDetailPage } from "@/pages/finding-detail";
import { FindingsPage } from "@/pages/findings";
import { NewScanPage } from "@/pages/new-scan";
import { NotFoundPage } from "@/pages/not-found";
import { OverviewPage } from "@/pages/overview";
import { RemediationsPage } from "@/pages/remediations";
import { ReportsPage } from "@/pages/reports";
import { RepositoriesPage } from "@/pages/repositories";
import { RepositoryDetailPage } from "@/pages/repository-detail";
import { ScanComparePage, ScanDetailPage } from "@/pages/scan-detail";
import { ScansPage } from "@/pages/scans";
import { SecurityLabPage } from "@/pages/security-lab";
import { SettingsPage } from "@/pages/settings";
import { TeamPage } from "@/pages/team";

export function App() {
  return (
    <BrowserRouter>
      <ErrorBoundary>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/repositories" element={<RepositoriesPage />} />
            <Route path="/repositories/:repositoryId" element={<RepositoryDetailPage />} />
            <Route path="/scans" element={<ScansPage />} />
            <Route path="/scans/new" element={<NewScanPage />} />
            <Route path="/scans/compare" element={<ScanComparePage />} />
            <Route path="/scans/:scanId" element={<ScanDetailPage />} />
            <Route path="/security" element={<SecurityLabPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/findings/:findingId" element={<FindingDetailPage />} />
            <Route path="/architecture" element={<ArchitecturePage />} />
            <Route path="/dependencies" element={<DependenciesPage />} />
            <Route path="/assistant" element={<AssistantPage />} />
            <Route path="/remediations" element={<RemediationsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/team" element={<TeamPage />} />
            <Route path="/index.html" element={<Navigate to="/" replace />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </ErrorBoundary>
    </BrowserRouter>
  );
}
