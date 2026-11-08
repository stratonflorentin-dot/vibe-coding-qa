import {
  Boxes,
  FileBarChart,
  GitBranchPlus,
  LayoutDashboard,
  PackageSearch,
  ScanSearch,
  Settings,
  ShieldAlert,
  Sparkles,
  Wrench,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** ``end`` keeps "/" from matching every route. */
  end?: boolean;
  description: string;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

/** The dashboard's information architecture. */
export const NAV_GROUPS: NavGroup[] = [
  {
    label: "Monitor",
    items: [
      {
        to: "/",
        label: "Overview",
        icon: LayoutDashboard,
        end: true,
        description: "Health, scores and recent activity across every repository.",
      },
      {
        to: "/repositories",
        label: "Repositories",
        icon: GitBranchPlus,
        description: "Register and inspect the repositories under analysis.",
      },
      {
        to: "/scans",
        label: "Scan History",
        icon: ScanSearch,
        description: "Every scan the engine has actually executed.",
      },
    ],
  },
  {
    label: "Investigate",
    items: [
      {
        to: "/findings",
        label: "Findings",
        icon: ShieldAlert,
        description: "Every issue with real source evidence and triage state.",
      },
      {
        to: "/architecture",
        label: "Architecture",
        icon: Boxes,
        description: "How the codebase is put together, derived from static analysis.",
      },
      {
        to: "/dependencies",
        label: "Dependencies",
        icon: PackageSearch,
        description: "Direct and transitive packages with advisory lookups.",
      },
    ],
  },
  {
    label: "Intelligence",
    items: [
      {
        to: "/assistant",
        label: "AI Assistant",
        icon: Sparkles,
        description: "Ask questions grounded in real scan results.",
      },
      {
        to: "/remediations",
        label: "Remediation",
        icon: Wrench,
        description: "Proposed patches that require explicit human approval.",
      },
      {
        to: "/reports",
        label: "Reports",
        icon: FileBarChart,
        description: "Executive summaries and per-scan reports.",
      },
    ],
  },
];

export const SETTINGS_ITEM: NavItem = {
  to: "/settings",
  label: "Settings",
  icon: Settings,
  description: "Scan defaults, AI provider configuration and safety switches.",
};
