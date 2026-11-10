import { useEffect, useState } from "react";

/**
 * Cinematic boot splash. On app load it plays a short Lionsgate-style reveal -
 * the Mario/Luigi mascots swirl in with a spinning halo and a light glint while
 * "Mario & Luigi patch the pipes" - then fades out to reveal the dashboard.
 * Click anywhere (or Skip) to dismiss early; respects prefers-reduced-motion.
 */
export function SplashScreen() {
  const [stage, setStage] = useState<"play" | "out" | "gone">("play");

  // Auto-advance to the fade-out after the hold.
  useEffect(() => {
    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
    const hold = reduced ? 800 : 2800;
    const t = setTimeout(() => setStage((s) => (s === "play" ? "out" : s)), hold);
    return () => clearTimeout(t);
  }, []);

  // Once fading, remove it from the tree.
  useEffect(() => {
    if (stage !== "out") return;
    const t = setTimeout(() => setStage("gone"), 650);
    return () => clearTimeout(t);
  }, [stage]);

  if (stage === "gone") return null;

  const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
  const dismiss = () => setStage((s) => (s === "play" ? "out" : s));

  return (
    <div
      className={`vcqa-splash${stage === "out" ? " is-leaving" : ""}${reduced ? " is-reduced" : ""}`}
      role="status"
      aria-label="Loading Vibe Coding QA"
      onClick={dismiss}
    >
      <div className="vcqa-splash-stage">
        <div className="vcqa-splash-rings" aria-hidden="true" />
        <div className="vcqa-splash-badge">
          <img src="/phone-mascots.gif" alt="" aria-hidden="true" draggable={false} />
          <span className="vcqa-splash-glint" aria-hidden="true" />
        </div>
      </div>

      <div className="vcqa-splash-wordmark">
        <span className="vcqa-splash-title">VIBE CODING QA</span>
        <span className="vcqa-splash-tagline">Mario &amp; Luigi are patching the pipes…</span>
      </div>

      <div className="vcqa-splash-bar" aria-hidden="true">
        <span />
      </div>

      <button
        type="button"
        className="vcqa-splash-skip"
        onClick={(e) => {
          e.stopPropagation();
          dismiss();
        }}
      >
        Skip ›
      </button>
    </div>
  );
}
