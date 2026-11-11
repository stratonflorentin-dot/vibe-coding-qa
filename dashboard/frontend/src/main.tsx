import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "@/App";
import { AppProvider } from "@/app/app-context";
import { AuthGate } from "@/components/common/auth-gate";
import { ErrorBoundary } from "@/components/common/error-boundary";
import { ThemeProvider } from "@/hooks/use-theme";
import { ToastProvider } from "@/components/ui/toast";
import "@/index.css";

const container = document.getElementById("root");
if (!container) throw new Error("The #root container is missing from index.html.");

createRoot(container).render(
  <StrictMode>
    <ThemeProvider>
      <ToastProvider>
        <ErrorBoundary>
          <AuthGate>
            <AppProvider>
              <App />
            </AppProvider>
          </AuthGate>
        </ErrorBoundary>
      </ToastProvider>
    </ThemeProvider>
  </StrictMode>,
);
