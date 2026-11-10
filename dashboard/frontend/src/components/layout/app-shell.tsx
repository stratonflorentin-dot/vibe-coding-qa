import { useState, type ReactNode } from "react";
import { Outlet } from "react-router-dom";

import { AssistantLauncher } from "@/components/layout/assistant-launcher";
import { SplashScreen } from "@/components/layout/splash-screen";
import { Sidebar } from "@/components/layout/sidebar";
import { Topbar } from "@/components/layout/topbar";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { TooltipProvider } from "@/components/ui/tooltip";

/** The persistent frame: sidebar on the left, topbar above the routed content. */
export function AppShell({ children }: { children?: ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <TooltipProvider delayDuration={200}>
      <SplashScreen />
      <div className="app-gradient flex h-full min-h-screen bg-background">
        <aside className="hidden w-60 shrink-0 lg:block">
          <div className="sticky top-0 h-screen">
            <Sidebar />
          </div>
        </aside>

        <Dialog open={mobileOpen} onOpenChange={setMobileOpen}>
          <DialogContent className="left-0 top-0 h-screen w-64 max-w-[16rem] translate-x-0 translate-y-0 rounded-none border-r p-0 sm:rounded-none">
            <Sidebar onNavigate={() => setMobileOpen(false)} />
          </DialogContent>
        </Dialog>

        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar onOpenMenu={() => setMobileOpen(true)} />
          <main className="flex-1 px-4 py-6 lg:px-8">
            <div className="mx-auto w-full max-w-7xl space-y-6">{children ?? <Outlet />}</div>
          </main>
        </div>
        <AssistantLauncher />
      </div>
    </TooltipProvider>
  );
}
