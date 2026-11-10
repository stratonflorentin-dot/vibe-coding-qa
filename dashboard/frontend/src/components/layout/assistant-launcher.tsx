import { MessageCircle } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

const STORAGE_KEY = "vcqa-assistant-pos";
const MARGIN = 12;
const DRAG_THRESHOLD = 4;

type Pos = { x: number; y: number };

/** Keep the launcher fully inside the viewport. */
function clamp(x: number, y: number, el: HTMLElement | null): Pos {
  const w = el?.offsetWidth ?? 180;
  const h = el?.offsetHeight ?? 64;
  const maxX = Math.max(MARGIN, window.innerWidth - w - MARGIN);
  const maxY = Math.max(MARGIN, window.innerHeight - h - MARGIN);
  return {
    x: Math.min(Math.max(MARGIN, x), maxX),
    y: Math.min(Math.max(MARGIN, y), maxY),
  };
}

/**
 * Floating "Ask AI" launcher. Drag it anywhere (the position is remembered);
 * a plain click still opens the assistant. Defaults to the bottom-right via CSS
 * until the user moves it.
 */
export function AssistantLauncher() {
  const ref = useRef<HTMLAnchorElement | null>(null);
  const [pos, setPos] = useState<Pos | null>(null);
  const drag = useRef({ startX: 0, startY: 0, dx: 0, dy: 0, moved: false, active: false });

  // Restore a saved position (per browser).
  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const saved = JSON.parse(raw) as Pos;
        if (Number.isFinite(saved?.x) && Number.isFinite(saved?.y)) {
          setPos(clamp(saved.x, saved.y, ref.current));
        }
      }
    } catch {
      /* storage unavailable — fall back to the default corner */
    }
  }, []);

  // Keep it on-screen when the window resizes.
  useEffect(() => {
    if (!pos) return;
    const onResize = () => setPos((p) => (p ? clamp(p.x, p.y, ref.current) : p));
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [pos]);

  const onPointerDown = useCallback((e: React.PointerEvent<HTMLAnchorElement>) => {
    if (e.button !== 0) return;
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    drag.current = {
      startX: e.clientX,
      startY: e.clientY,
      dx: e.clientX - rect.left,
      dy: e.clientY - rect.top,
      moved: false,
      active: true,
    };
    try {
      el.setPointerCapture(e.pointerId);
    } catch {
      /* ignore */
    }
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent<HTMLAnchorElement>) => {
    const d = drag.current;
    if (!d.active) return;
    if (!d.moved && Math.hypot(e.clientX - d.startX, e.clientY - d.startY) < DRAG_THRESHOLD) return;
    d.moved = true;
    setPos(clamp(e.clientX - d.dx, e.clientY - d.dy, ref.current));
  }, []);

  const endDrag = useCallback((e: React.PointerEvent<HTMLAnchorElement>) => {
    const d = drag.current;
    if (!d.active) return;
    d.active = false;
    try {
      ref.current?.releasePointerCapture(e.pointerId);
    } catch {
      /* ignore */
    }
    if (d.moved) {
      const final = clamp(e.clientX - d.dx, e.clientY - d.dy, ref.current);
      setPos(final);
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(final));
      } catch {
        /* ignore */
      }
    }
  }, []);

  // Swallow the navigation click if the pointer was actually dragged.
  const onClick = useCallback((e: React.MouseEvent<HTMLAnchorElement>) => {
    if (drag.current.moved) {
      e.preventDefault();
      drag.current.moved = false;
    }
  }, []);

  return (
    <Link
      ref={ref}
      to="/assistant"
      aria-label="Open AI coding assistant"
      title="Drag to move · click to open the AI assistant"
      className="assistant-launcher cursor-grab touch-none select-none active:cursor-grabbing"
      draggable={false}
      style={pos ? { left: pos.x, top: pos.y, right: "auto", bottom: "auto" } : undefined}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
      onClick={onClick}
    >
      <span className="assistant-launcher-mascots">
        <img src="/phone-mascots.gif" alt="" aria-hidden="true" draggable={false} />
      </span>
      <span className="assistant-launcher-copy">
        <span className="assistant-launcher-eyebrow">Need a hand?</span>
        <span className="assistant-launcher-title">
          Ask AI <MessageCircle className="h-4 w-4" />
        </span>
      </span>
    </Link>
  );
}
