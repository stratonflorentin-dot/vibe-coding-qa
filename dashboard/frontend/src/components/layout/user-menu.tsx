import { LogOut, ShieldCheck, UserCircle2, UserCog } from "lucide-react";
import { Link } from "react-router-dom";

import { ROLE_LABELS, useSession } from "@/app/session-context";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

/** Topbar account control: who is signed in, their role, and sign-out. */
export function UserMenu() {
  const { mode, user, isAdmin, logout } = useSession();

  // Open (localhost) mode has no identity; offer to enable accounts instead.
  if (mode === "open") {
    return (
      <Button asChild variant="ghost" size="sm" className="gap-1.5 text-muted-foreground">
        <Link to="/team">
          <ShieldCheck className="h-4 w-4" />
          <span className="hidden sm:inline">Enable accounts</span>
        </Link>
      </Button>
    );
  }

  const label = user?.username ?? "Operator";
  const role = user ? ROLE_LABELS[user.role] ?? user.role : "Single credential";

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" className="gap-2" aria-label="Account menu">
          <UserCircle2 className="h-5 w-5" />
          <span className="hidden max-w-[8rem] truncate sm:inline">{label}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel>
          <div className="font-medium">{label}</div>
          <div className="text-xs font-normal text-muted-foreground">{role}</div>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {isAdmin ? (
          <DropdownMenuItem asChild>
            <Link to="/team">
              <UserCog className="mr-2 h-4 w-4" />
              Team &amp; access
            </Link>
          </DropdownMenuItem>
        ) : null}
        <DropdownMenuItem onClick={() => void logout()}>
          <LogOut className="mr-2 h-4 w-4" />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
