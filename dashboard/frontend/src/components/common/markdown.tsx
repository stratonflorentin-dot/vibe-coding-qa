import { Fragment, type ReactNode } from "react";

import { cn } from "@/lib/utils";

/**
 * Render light Markdown as React elements.
 *
 * AI output is untrusted text, so it is never passed through
 * ``dangerouslySetInnerHTML``: the parser builds React nodes, which makes HTML
 * injection structurally impossible. Supports headings, lists, fenced code,
 * bold, inline code and paragraphs.
 */
export function Markdown({ text, className }: { text: string; className?: string }) {
  if (!text.trim()) return null;
  return (
    <div className={cn("min-w-0 space-y-3 break-words text-sm leading-relaxed", className)}>
      {parse(text)}
    </div>
  );
}

function inline(source: string, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  // Only backticks and bold markers are interpreted.
  const pattern = /(`[^`]+`|\*\*[^*]+\*\*)/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let counter = 0;

  while ((match = pattern.exec(source)) !== null) {
    if (match.index > lastIndex) nodes.push(source.slice(lastIndex, match.index));
    const token = match[0];
    const key = `${keyPrefix}-i${counter++}`;
    if (token.startsWith("`")) {
      nodes.push(
        <code
          key={key}
          className="rounded bg-muted px-1.5 py-0.5 font-mono text-[0.85em] text-foreground"
        >
          {token.slice(1, -1)}
        </code>,
      );
    } else {
      nodes.push(
        <strong key={key} className="font-semibold text-foreground">
          {token.slice(2, -2)}
        </strong>,
      );
    }
    lastIndex = match.index + token.length;
  }
  if (lastIndex < source.length) nodes.push(source.slice(lastIndex));
  return nodes;
}

function parse(text: string): ReactNode[] {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let listBuffer: string[] = [];
  let ordered = false;
  let codeBuffer: string[] | null = null;
  let key = 0;

  const flushList = () => {
    if (!listBuffer.length) return;
    const items = listBuffer.map((item, index) => (
      <li key={index} className="ml-1">
        {inline(item, `l${key}-${index}`)}
      </li>
    ));
    blocks.push(
      ordered ? (
        <ol key={`ol-${key++}`} className="ml-5 list-decimal space-y-1">
          {items}
        </ol>
      ) : (
        <ul key={`ul-${key++}`} className="ml-5 list-disc space-y-1">
          {items}
        </ul>
      ),
    );
    listBuffer = [];
  };

  for (const line of lines) {
    if (line.trim().startsWith("```")) {
      if (codeBuffer) {
        blocks.push(
          <pre
            key={`pre-${key++}`}
            className="max-w-full overflow-x-auto rounded-md border bg-muted/50 p-3 font-mono text-xs"
          >
            <code>{codeBuffer.join("\n")}</code>
          </pre>,
        );
        codeBuffer = null;
      } else {
        flushList();
        codeBuffer = [];
      }
      continue;
    }

    if (codeBuffer) {
      codeBuffer.push(line);
      continue;
    }

    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      flushList();
      const level = heading[1].length;
      const sizes = ["text-lg", "text-base", "text-sm", "text-sm", "text-sm", "text-sm"];
      blocks.push(
        <p key={`h-${key++}`} className={cn("font-semibold text-foreground", sizes[level - 1])}>
          {inline(heading[2], `h${key}`)}
        </p>,
      );
      continue;
    }

    const bullet = /^\s*[-*+]\s+(.*)$/.exec(line);
    const numbered = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    if (bullet || numbered) {
      const wasOrdered: boolean = ordered;
      ordered = Boolean(numbered);
      if (listBuffer.length && wasOrdered !== ordered) flushList();
      listBuffer.push((bullet ?? numbered)![1]);
      continue;
    }

    if (!line.trim()) {
      flushList();
      continue;
    }

    flushList();
    blocks.push(
      <p key={`p-${key++}`} className="text-muted-foreground">
        {inline(line, `p${key}`)}
      </p>,
    );
  }

  if (codeBuffer) {
    blocks.push(
      <pre key={`pre-${key++}`} className="max-w-full overflow-x-auto rounded-md border bg-muted/50 p-3 font-mono text-xs">
        <code>{codeBuffer.join("\n")}</code>
      </pre>,
    );
  }
  flushList();

  return blocks.map((block, index) => <Fragment key={index}>{block}</Fragment>);
}
