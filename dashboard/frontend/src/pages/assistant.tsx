import { MessageSquare, Plus, Send, Sparkles, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

import { useApp } from "@/app/app-context";
import { DataState } from "@/components/common/data-state";
import { Markdown } from "@/components/common/markdown";
import { PageHeader } from "@/components/common/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Textarea } from "@/components/ui/textarea";
import { useAsync } from "@/hooks/use-async";
import { api, ApiError } from "@/lib/api";
import { formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { AIConversation, AIMessage } from "@/types/api";

/**
 * The codebase assistant.
 *
 * Every answer comes from the configured model through the API — the page never
 * invents a reply. When no provider is configured the page says so plainly and
 * stays usable instead of failing.
 */
export function AssistantPage() {
  const { activeRepositoryId, activeRepository, health } = useApp();

  const conversations = useAsync(() => api.ai.conversations(), []);

  const [activeId, setActiveId] = useState<number | null>(null);
  const [messages, setMessages] = useState<AIMessage[]>([]);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);
  const [notConfigured, setNotConfigured] = useState(false);
  const [sourcesByMessage, setSourcesByMessage] = useState<
    Record<number, Array<Record<string, unknown>>>
  >({});
  const [pendingDelete, setPendingDelete] = useState<AIConversation | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const detail = useAsync(() => api.ai.conversation(activeId as number), [activeId], {
    enabled: activeId !== null,
  });

  const endRef = useRef<HTMLDivElement | null>(null);

  // Adopt the persisted thread once the server has answered.
  useEffect(() => {
    if (activeId === null) {
      setMessages([]);
      return;
    }
    if (detail.data && detail.data.id === activeId) {
      setMessages(detail.data.messages);
    }
  }, [detail.data, activeId]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end", behavior: "smooth" });
  }, [messages, sending]);

  const aiUnavailable = notConfigured || health?.ai_configured === false;

  function startNewConversation() {
    setActiveId(null);
    setMessages([]);
    setSendError(null);
    setNotConfigured(false);
  }

  async function handleSend() {
    const text = draft.trim();
    if (!text || sending) return;
    setSending(true);
    setSendError(null);
    try {
      const response = await api.ai.chat({
        message: text,
        repository_id: activeRepositoryId ?? null,
        conversation_id: activeId ?? null,
      });
      setDraft("");
      setNotConfigured(response.configured === false);

      const question: AIMessage = {
        id: -Date.now(),
        role: "user",
        content: text,
        created_at: new Date().toISOString(),
        metadata: {},
      };
      setMessages((previous) => [...previous, question, response.message]);

      if (response.sources.length) {
        const sources = response.sources;
        setSourcesByMessage((previous) => ({ ...previous, [response.message.id]: sources }));
      }

      if (response.conversation_id !== activeId) {
        setActiveId(response.conversation_id);
        void conversations.reload(true);
      }
    } catch (error) {
      setSendError(error instanceof ApiError ? error.message : "The message could not be sent.");
    } finally {
      setSending(false);
    }
  }

  async function handleDelete() {
    if (!pendingDelete) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await api.ai.deleteConversation(pendingDelete.id);
      if (activeId === pendingDelete.id) {
        setActiveId(null);
        setMessages([]);
      }
      setPendingDelete(null);
      await conversations.reload(true);
    } catch (error) {
      setDeleteError(
        error instanceof ApiError ? error.message : "The conversation could not be deleted.",
      );
    } finally {
      setDeleting(false);
    }
  }

  const conversationList = conversations.data ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI Assistant"
        description="Ask questions grounded in the scan results stored for this dashboard. Answers come from the configured model — nothing here is fabricated."
      />

      {aiUnavailable ? (
        <Alert variant="warning">
          <AlertTitle>AI is not configured</AlertTitle>
          <AlertDescription>
            The assistant cannot answer until an AI provider is configured. Add a provider and API
            key in{" "}
            <Link to="/settings" className="font-medium underline underline-offset-4">
              settings
            </Link>
            . Until then no answers will be produced.
          </AlertDescription>
        </Alert>
      ) : null}

      {activeRepositoryId === null ? (
        <Alert variant="info">
          <AlertTitle>No repository selected</AlertTitle>
          <AlertDescription>
            The assistant will answer without repository context. Select a repository in the top bar
            to ground the conversation in a specific codebase.
          </AlertDescription>
        </Alert>
      ) : (
        <p className="text-sm text-muted-foreground">
          Grounded in {activeRepository?.name ?? `repository #${activeRepositoryId}`}.
        </p>
      )}

      <div className="grid gap-4 lg:grid-cols-[300px_1fr]">
        <Card className="flex flex-col">
          <CardHeader className="flex-row items-center justify-between space-y-0 pb-3">
            <CardTitle>Conversations</CardTitle>
            <Button size="sm" variant="outline" onClick={startNewConversation}>
              <Plus />
              New
            </Button>
          </CardHeader>
          <CardContent className="px-0">
            <DataState
              loading={conversations.loading}
              error={conversations.error}
              onRetry={() => void conversations.reload()}
              loadingRows={3}
            >
              {conversationList.length ? (
                <ScrollArea className="h-[420px]">
                  <ul className="space-y-1 px-2">
                    {conversationList.map((conversation) => {
                      const active = conversation.id === activeId;
                      return (
                        <li key={conversation.id}>
                          <div
                            className={cn(
                              "group flex items-center gap-1 rounded-md",
                              active ? "bg-muted" : "hover:bg-muted/60",
                            )}
                          >
                            <button
                              type="button"
                              onClick={() => {
                                setActiveId(conversation.id);
                                setSendError(null);
                              }}
                              className="flex min-w-0 flex-1 flex-col items-start gap-0.5 px-3 py-2 text-left"
                            >
                              <span className="w-full truncate text-sm font-medium">
                                {conversation.title || `Conversation ${conversation.id}`}
                              </span>
                              <span className="text-[11px] text-muted-foreground">
                                {conversation.message_count} messages ·{" "}
                                {formatRelative(conversation.updated_at)}
                              </span>
                            </button>
                            <Button
                              size="icon"
                              variant="ghost"
                              className="mr-1 h-7 w-7 shrink-0 opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100"
                              aria-label="Delete conversation"
                              onClick={() => {
                                setDeleteError(null);
                                setPendingDelete(conversation);
                              }}
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                </ScrollArea>
              ) : (
                <div className="px-4">
                  <EmptyState
                    icon={MessageSquare}
                    title="No conversations yet"
                    description="Ask a question to start the first conversation."
                    className="border-0 bg-transparent px-0 py-6"
                  />
                </div>
              )}
            </DataState>
          </CardContent>
        </Card>

        <Card className="flex min-h-[560px] flex-col">
          <CardHeader className="pb-3">
            <CardTitle>
              {activeId === null
                ? "New conversation"
                : detail.data?.title || `Conversation ${activeId}`}
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-1 flex-col gap-3">
            <ScrollArea className="h-[360px] rounded-md border bg-muted/20 p-3">
              <DataState
                loading={detail.loading && messages.length === 0}
                error={detail.error}
                onRetry={() => void detail.reload()}
                loadingRows={2}
              >
                {messages.length ? (
                  <div className="space-y-4">
                    {messages.map((message) => (
                      <MessageRow
                        key={`${message.id}-${message.role}`}
                        message={message}
                        sources={sourcesByMessage[message.id]}
                      />
                    ))}
                    {sending ? (
                      <p className="text-xs text-muted-foreground">Waiting for the model…</p>
                    ) : null}
                    <div ref={endRef} />
                  </div>
                ) : (
                  <div className="flex h-full items-center justify-center py-10">
                    <p className="max-w-sm text-center text-sm text-muted-foreground">
                      {activeId === null
                        ? "Ask a question about the selected repository. An answer is produced only when an AI provider is configured."
                        : "This conversation has no messages yet."}
                    </p>
                  </div>
                )}
              </DataState>
            </ScrollArea>

            {sendError ? (
              <Alert variant="destructive">
                <AlertDescription>{sendError}</AlertDescription>
              </Alert>
            ) : null}

            <form
              className="space-y-2"
              onSubmit={(event) => {
                event.preventDefault();
                void handleSend();
              }}
            >
              <Textarea
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    void handleSend();
                  }
                }}
                placeholder="Ask about the codebase, for example: which findings are the most severe?"
                rows={3}
                disabled={sending}
              />
              <div className="flex items-center justify-between gap-2">
                <p className="text-[11px] text-muted-foreground">
                  Enter to send, Shift+Enter for a new line.
                </p>
                <Button type="submit" size="sm" disabled={sending || !draft.trim()}>
                  <Send />
                  {sending ? "Sending…" : "Send"}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>

      {aiUnavailable ? (
        <p className="flex items-center gap-2 text-xs text-muted-foreground">
          <Sparkles className="h-3.5 w-3.5" />
          Configure an AI provider in settings to receive answers.
        </p>
      ) : null}

      <Dialog
        open={pendingDelete !== null}
        onOpenChange={(open) => {
          if (!open && !deleting) {
            setPendingDelete(null);
            setDeleteError(null);
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete conversation</DialogTitle>
            <DialogDescription>
              This permanently deletes{" "}
              {pendingDelete ? `"${pendingDelete.title || `Conversation ${pendingDelete.id}`}"` : "this conversation"}{" "}
              and all of its messages. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          {deleteError ? (
            <Alert variant="destructive">
              <AlertDescription>{deleteError}</AlertDescription>
            </Alert>
          ) : null}
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setPendingDelete(null)}
              disabled={deleting}
            >
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => void handleDelete()} disabled={deleting}>
              {deleting ? "Deleting…" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function MessageRow({
  message,
  sources,
}: {
  message: AIMessage;
  sources?: Array<Record<string, unknown>>;
}) {
  const isAssistant = message.role === "assistant" || message.role === "ai";
  return (
    <div className={cn("flex", isAssistant ? "justify-start" : "justify-end")}>
      <div
        className={cn(
          "max-w-[85%] rounded-lg border px-3 py-2",
          isAssistant ? "bg-card" : "bg-primary/10",
        )}
      >
        <p className="mb-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
          {isAssistant ? "Assistant" : "You"}
        </p>
        {isAssistant ? (
          <Markdown text={message.content} />
        ) : (
          <p className="whitespace-pre-wrap text-sm">{message.content}</p>
        )}
        {sources && sources.length ? (
          <div className="mt-2 border-t pt-2">
            <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              Sources
            </p>
            <ul className="mt-1 space-y-0.5">
              {sources.map((source, index) => (
                <li key={index} className="truncate text-xs text-muted-foreground">
                  {sourceLabel(source)}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
    </div>
  );
}

/** Render a source entry as compact text without inventing any fields. */
function sourceLabel(source: Record<string, unknown>): string {
  const candidate =
    source.title ?? source.file ?? source.path ?? source.label ?? source.finding_id ?? source.id;
  if (typeof candidate === "string" || typeof candidate === "number") {
    const line = source.line ?? source.start_line;
    const suffix =
      typeof line === "string" || typeof line === "number" ? `:${String(line)}` : "";
    return `${String(candidate)}${suffix}`;
  }
  return JSON.stringify(source);
}
