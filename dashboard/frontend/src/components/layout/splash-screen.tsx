import { Volume2, VolumeX } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { BootTheme } from "@/lib/chiptune";

const SOUND_PREF_KEY = "vcqa-boot-sound";
const HOLD_MS = 2800;
const HOLD_REDUCED_MS = 900;
const HOLD_AFTER_THEME_MS = 500;

function readSoundPref(): boolean {
  try {
    return window.localStorage.getItem(SOUND_PREF_KEY) !== "off";
  } catch {
    return true;
  }
}

function writeSoundPref(enabled: boolean): void {
  try {
    window.localStorage.setItem(SOUND_PREF_KEY, enabled ? "on" : "off");
  } catch {
    /* Preference persistence is best-effort. */
  }
}

function prefersReducedMotion(): boolean {
  return window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
}

/**
 * Cinematic boot splash. It plays a short Mario/Luigi-style reveal - the mascots
 * swirl in with a spinning halo and a light glint while the boot theme plays -
 * then fades out to reveal the dashboard.
 *
 * The theme is an original chiptune tribute (see lib/chiptune.ts). Browsers mute
 * audio until the visitor interacts with the page, so when autoplay is refused
 * the splash offers a click-to-play control rather than failing silently.
 *
 * Click anywhere (or Skip) to dismiss early; respects prefers-reduced-motion.
 */
export function SplashScreen() {
  const [stage, setStage] = useState<"play" | "out" | "gone">("play");
  const [soundOn, setSoundOn] = useState(readSoundPref);
  const [needsGesture, setNeedsGesture] = useState(false);
  const themeRef = useRef<BootTheme | null>(null);
  const holdRef = useRef<number | null>(null);

  const clearHold = useCallback(() => {
    if (holdRef.current !== null) {
      window.clearTimeout(holdRef.current);
      holdRef.current = null;
    }
  }, []);

  /** Keep the splash up long enough to hear a theme that is actually playing. */
  const holdFor = useCallback(
    (themeMs: number) => {
      clearHold();
      const total = themeMs > 0 ? themeMs + HOLD_AFTER_THEME_MS : prefersReducedMotion() ? HOLD_REDUCED_MS : HOLD_MS;
      holdRef.current = window.setTimeout(() => setStage((s) => (s === "play" ? "out" : s)), total);
    },
    [clearHold],
  );

  /** Start a fresh run of the theme; used on load and by the click-to-play control. */
  const playTheme = useCallback(() => {
    themeRef.current?.stop();
    const theme = new BootTheme();
    themeRef.current = theme;
    void theme.play().then((started) => {
      setNeedsGesture(!started);
      holdFor(started ? theme.durationMs : 0);
    });
  }, [holdFor]);

  // Start (or stop) the theme whenever the preference changes, including on mount.
  useEffect(() => {
    if (soundOn) playTheme();
    else holdFor(0);
    return () => {
      clearHold();
      themeRef.current?.stop();
      themeRef.current = null;
    };
  }, [soundOn, playTheme, holdFor, clearHold]);

  // Once fading, remove it from the tree.
  useEffect(() => {
    if (stage !== "out") return;
    const t = setTimeout(() => setStage("gone"), 650);
    return () => clearTimeout(t);
  }, [stage]);

  if (stage === "gone") return null;

  const reduced = prefersReducedMotion();
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
          <img src="/pet-badge.svg" alt="" aria-hidden="true" draggable={false} />
          <span className="vcqa-splash-glint" aria-hidden="true" />
        </div>
      </div>

      <div className="vcqa-splash-wordmark">
        <span className="vcqa-splash-title">VIBE CODING QA</span>
        <span className="vcqa-splash-tagline">Mario &amp; Luigi are patching the pipes…</span>
        <span className="vcqa-splash-credit">
          Inspired by Mario &amp; Luigi — an independent fan-made tribute, not affiliated with Nintendo.
        </span>
      </div>

      <div className="vcqa-splash-bar" aria-hidden="true">
        <span />
      </div>

      <div className="vcqa-splash-sound">
        {soundOn && needsGesture ? (
          <button
            type="button"
            className="vcqa-splash-sound-btn is-cta"
            onClick={(event) => {
              event.stopPropagation();
              playTheme();
            }}
          >
            <Volume2 aria-hidden="true" /> Tap to play the boot theme
          </button>
        ) : (
          <button
            type="button"
            className="vcqa-splash-sound-btn"
            aria-pressed={soundOn}
            onClick={(event) => {
              event.stopPropagation();
              const next = !soundOn;
              writeSoundPref(next);
              setSoundOn(next);
            }}
          >
            {soundOn ? <Volume2 aria-hidden="true" /> : <VolumeX aria-hidden="true" />}
            {soundOn ? "Sound on" : "Sound off"}
          </button>
        )}
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
