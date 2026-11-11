import { useCallback, useEffect, useState, type FormEvent } from "react";
import { ShieldCheck, UserPlus, Users } from "lucide-react";

import { ROLE_LABELS, useSession } from "@/app/session-context";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";
import { ApiError, api, type AuditEntry, type AuthRole, type AuthUser } from "@/lib/api";

const ROLES: AuthRole[] = ["viewer", "security_analyst", "administrator", "owner"];

function errorMessage(caught: unknown, fallback: string): string {
  return caught instanceof ApiError ? caught.message : fallback;
}

export function TeamPage() {
  const { needsSetup, mode, isAdmin, user, refresh } = useSession();

  if (needsSetup) return <SetupCard onDone={refresh} />;
  if (mode !== "accounts" || !isAdmin) return <AccessNotice user={user} />;
  return <UserManagement currentUserId={user?.id ?? 0} />;
}

// ----------------------------------------------------------------- first owner
function SetupCard({ onDone }: { onDone: () => Promise<void> | void }) {
  const { toast } = useToast();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.auth.setup({ username, password });
      toast({ title: "Owner account created", description: "Accounts are now enabled.", variant: "success" });
      await onDone();
    } catch (caught) {
      setError(errorMessage(caught, "Could not complete setup."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-lg">
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-primary" />
            <CardTitle>Enable account-based access</CardTitle>
          </div>
          <CardDescription>
            No accounts exist yet. Create the first owner to turn on multi-user sign-in, roles and
            an audit trail. After this, anonymous access is disabled.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={submit}>
            <div className="space-y-1.5">
              <Label htmlFor="setup-username">Owner username</Label>
              <Input id="setup-username" value={username} autoComplete="username" autoFocus
                onChange={(e) => setUsername(e.target.value)} required />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="setup-password">Password</Label>
              <Input id="setup-password" type="password" value={password} autoComplete="new-password"
                onChange={(e) => setPassword(e.target.value)} required minLength={10} />
              <p className="text-xs text-muted-foreground">At least 10 characters.</p>
            </div>
            {error ? <p className="text-sm text-destructive" role="alert">{error}</p> : null}
            <Button type="submit" disabled={busy}>{busy ? "Creating…" : "Create owner & enable accounts"}</Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

function AccessNotice({ user }: { user: AuthUser | null }) {
  return (
    <div className="mx-auto max-w-lg">
      <Card>
        <CardHeader>
          <CardTitle>Team & access</CardTitle>
          <CardDescription>
            {user
              ? `You are signed in as ${user.username} (${ROLE_LABELS[user.role] ?? user.role}). An administrator or owner can manage users.`
              : "Administrator access is required to manage users."}
          </CardDescription>
        </CardHeader>
      </Card>
    </div>
  );
}

// -------------------------------------------------------------- administration
function UserManagement({ currentUserId }: { currentUserId: number }) {
  const { toast } = useToast();
  const [users, setUsers] = useState<AuthUser[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [u, a] = await Promise.all([api.auth.users.list(), api.auth.audit(50)]);
      setUsers(u.users);
      setAudit(a.entries);
    } catch (caught) {
      toast({ title: "Could not load users", description: errorMessage(caught, ""), variant: "error" });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  const act = useCallback(
    async (label: string, run: () => Promise<unknown>) => {
      try {
        await run();
        toast({ title: label, variant: "success" });
        await load();
      } catch (caught) {
        toast({ title: "Action failed", description: errorMessage(caught, ""), variant: "error" });
      }
    },
    [load, toast],
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Users className="h-5 w-5 text-primary" />
        <h1 className="text-xl font-semibold">Team & access</h1>
      </div>

      <CreateUserForm onCreated={load} />

      <Card>
        <CardHeader>
          <CardTitle>Users</CardTitle>
          <CardDescription>Roles control what each person can do. The last owner cannot be removed or demoted.</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last sign-in</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && users.length === 0 ? (
                <TableRow><TableCell colSpan={5} className="text-muted-foreground">Loading…</TableCell></TableRow>
              ) : null}
              {users.map((u) => (
                <TableRow key={u.id}>
                  <TableCell className="font-medium">
                    {u.username}
                    {u.id === currentUserId ? <span className="ml-2 text-xs text-muted-foreground">(you)</span> : null}
                  </TableCell>
                  <TableCell>
                    <Select value={u.role} onValueChange={(role) =>
                      act(`Role updated for ${u.username}`, () => api.auth.users.setRole(u.id, role as AuthRole))
                    }>
                      <SelectTrigger className="h-8 w-[11rem]"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {ROLES.map((role) => (
                          <SelectItem key={role} value={role}>{ROLE_LABELS[role] ?? role}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </TableCell>
                  <TableCell>
                    {u.is_active
                      ? <Badge variant="outline">Active</Badge>
                      : <Badge variant="destructive">Disabled</Badge>}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm">
                    {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "—"}
                  </TableCell>
                  <TableCell className="text-right space-x-1 whitespace-nowrap">
                    <Button variant="ghost" size="sm"
                      onClick={() => act(`${u.is_active ? "Disabled" : "Enabled"} ${u.username}`,
                        () => api.auth.users.setActive(u.id, !u.is_active))}>
                      {u.is_active ? "Disable" : "Enable"}
                    </Button>
                    <Button variant="ghost" size="sm" onClick={() => {
                      const pw = window.prompt(`New password for ${u.username} (min 10 characters):`);
                      if (!pw) return;
                      if (pw.length < 10) { toast({ title: "Password too short", variant: "error" }); return; }
                      void act(`Password reset for ${u.username}`, () => api.auth.users.setPassword(u.id, pw));
                    }}>
                      Reset password
                    </Button>
                    {u.id === currentUserId ? null : (
                      <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive"
                        onClick={() => {
                          if (!window.confirm(`Remove ${u.username}? This cannot be undone.`)) return;
                          void act(`${u.username} removed`, () => api.auth.users.remove(u.id));
                        }}>
                        Remove
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Audit log</CardTitle>
          <CardDescription>Recent sensitive actions on this installation.</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>When</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Target</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {audit.map((entry) => (
                <TableRow key={entry.id}>
                  <TableCell className="text-muted-foreground text-xs">{new Date(entry.ts).toLocaleString()}</TableCell>
                  <TableCell className="text-sm">{entry.username ?? "—"}</TableCell>
                  <TableCell><Badge variant="outline" className="font-mono text-[11px]">{entry.action}</Badge></TableCell>
                  <TableCell className="text-sm text-muted-foreground">{entry.target ?? (entry.detail ?? "—")}</TableCell>
                </TableRow>
              ))}
              {audit.length === 0 && !loading ? (
                <TableRow><TableCell colSpan={4} className="text-muted-foreground">No audit entries yet.</TableCell></TableRow>
              ) : null}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

function CreateUserForm({ onCreated }: { onCreated: () => Promise<void> | void }) {
  const { toast } = useToast();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<AuthRole>("viewer");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await api.auth.users.create({ username, password, role });
      toast({ title: "User created", description: username, variant: "success" });
      setUsername("");
      setPassword("");
      setRole("viewer");
      await onCreated();
    } catch (caught) {
      toast({ title: "Could not create user", description: errorMessage(caught, ""), variant: "error" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <UserPlus className="h-5 w-5 text-primary" />
          <CardTitle>Add a user</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        <form className="grid gap-3 sm:grid-cols-[1fr_1fr_12rem_auto] sm:items-end" onSubmit={submit}>
          <div className="space-y-1.5">
            <Label htmlFor="new-username">Username</Label>
            <Input id="new-username" value={username} autoComplete="off"
              onChange={(e) => setUsername(e.target.value)} required />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="new-password">Password</Label>
            <Input id="new-password" type="password" value={password} autoComplete="new-password"
              onChange={(e) => setPassword(e.target.value)} required minLength={10} />
          </div>
          <div className="space-y-1.5">
            <Label>Role</Label>
            <Select value={role} onValueChange={(value) => setRole(value as AuthRole)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {ROLES.map((r) => (<SelectItem key={r} value={r}>{ROLE_LABELS[r] ?? r}</SelectItem>))}
              </SelectContent>
            </Select>
          </div>
          <Button type="submit" disabled={busy}>{busy ? "Adding…" : "Add user"}</Button>
        </form>
      </CardContent>
    </Card>
  );
}
