/**
 * Boot theme for the splash screen.
 *
 * There are two sources, in priority order:
 *
 * 1. An audio file the operator drops at `public/audio/boot-theme.mp3`. Use this
 *    only with a track you have the rights to publish; the application ships no
 *    third-party music.
 * 2. Otherwise an original chiptune fanfare synthesised here with the Web Audio
 *    API. It is written for this project - deliberately not a rendition of any
 *    existing game theme - and is a nod to the 8-bit era the mascots come from.
 *
 * Browsers block sound until the visitor has interacted with the page, so
 * :meth:`BootTheme.play` reports whether it actually started. When it returns
 * false the splash offers a deliberate click-to-play control instead of staying
 * silent with no explanation.
 */

/** Optional operator-supplied track. Checked once per page load. */
const SUPPLIED_THEME_URL = "/audio/boot-theme.mp3";

const BEAT_SECONDS = 0.4; // 150 BPM
const FULL_THEME_BEATS = 11;

/** Semitone offset from A4 (440 Hz) for every note the fanfare uses. */
const SEMITONE: Record<string, number> = {
  C3: -21, D3: -19, E3: -17, F3: -16, G3: -14, A3: -12, B3: -10,
  C4: -9, D4: -7, E4: -5, F4: -4, G4: -2, A4: 0, B4: 2,
  C5: 3, D5: 5, E5: 7, F5: 8, G5: 10, A5: 12, B5: 14,
  C6: 15, D6: 17, E6: 19,
};

type VoiceName = "lead" | "bass" | "blip";

interface VoiceProfile {
  type: OscillatorType;
  peak: number;
  attack: number;
  release: number;
}

const VOICES: Record<VoiceName, VoiceProfile> = {
  lead: { type: "square", peak: 0.13, attack: 0.008, release: 0.09 },
  bass: { type: "triangle", peak: 0.24, attack: 0.012, release: 0.14 },
  blip: { type: "square", peak: 0.035, attack: 0.002, release: 0.03 },
};

/** [note, start beat, length in beats] */
type Note = readonly [string, number, number];

const LEAD: readonly Note[] = [
  ["G4", 0, 0.5], ["C5", 0.5, 0.5], ["E5", 1, 0.5], ["G5", 1.5, 0.5],
  ["A5", 2, 0.5], ["G5", 2.5, 0.5], ["E5", 3, 0.5], ["C5", 3.5, 0.5],
  ["D5", 4, 0.5], ["F5", 4.5, 0.5], ["A5", 5, 0.5], ["C6", 5.5, 0.5],
  ["B5", 6, 0.5], ["G5", 6.5, 0.5], ["E5", 7, 0.5], ["D5", 7.5, 0.5],
  ["C5", 8, 0.5], ["E5", 8.5, 0.5], ["G5", 9, 0.5], ["C6", 9.5, 1.5],
];

const BASS: readonly Note[] = [
  ["C3", 0, 2], ["A3", 2, 2], ["D3", 4, 2], ["G3", 6, 2], ["C3", 8, 3],
];

/** Downbeats get a short high click so the fanfare keeps a pulse. */
const BLIP_BEATS: readonly number[] = [0, 2, 4, 6, 8, 10];

type ThemeSource = "file" | "synth";

let resolvedSource: Promise<ThemeSource> | null = null;

/**
 * Decide once whether a supplied file is usable. A missing file falls through
 * to the dev server's SPA handler, which answers with HTML, so the content type
 * is checked rather than the status alone.
 */
function resolveSource(): Promise<ThemeSource> {
  if (!resolvedSource) {
    resolvedSource = (async (): Promise<ThemeSource> => {
      try {
        const controller = new AbortController();
        const timer = window.setTimeout(() => controller.abort(), 500);
        const response = await fetch(SUPPLIED_THEME_URL, {
          method: "HEAD",
          signal: controller.signal,
        });
        window.clearTimeout(timer);
        const contentType = response.headers.get("content-type") ?? "";
        return response.ok && contentType.startsWith("audio/") ? "file" : "synth";
      } catch {
        return "synth";
      }
    })();
  }
  return resolvedSource;
}

/** Whether the page has already seen a user gesture that unlocks audio. */
function gestureAllowsAudio(): boolean {
  const activation = (navigator as unknown as {
    userActivation?: { hasBeenActive?: boolean };
  }).userActivation;
  if (activation && typeof activation.hasBeenActive === "boolean") {
    return activation.hasBeenActive;
  }
  // Older browsers give no signal; report true and let the caller fall back to
  // the click-to-play control if playback still cannot start.
  return true;
}

function frequencyFor(semitone: number): number {
  return 440 * 2 ** (semitone / 12);
}

/**
 * A single run of the boot theme. Create a new instance to play it again; an
 * instance is finished once :meth:`stop` has been called.
 */
export class BootTheme {
  private context: AudioContext | null = null;
  private master: GainNode | null = null;
  private element: HTMLAudioElement | null = null;
  private stopped = false;
  private started = false;

  /** How long the synthesised fanfare runs, in milliseconds. */
  readonly durationMs = FULL_THEME_BEATS * BEAT_SECONDS * 1000;

  /**
   * Begin playback. Resolves to true when sound actually started, false when
   * the browser requires a user gesture first.
   */
  async play(): Promise<boolean> {
    if (this.started || this.stopped) return false;
    this.started = true;
    // Checked before touching either source: neither an audio element nor a
    // suspended AudioContext can be started without a prior user gesture.
    if (!gestureAllowsAudio()) return false;
    const source = await resolveSource();
    if (this.stopped) return false;
    return source === "file" ? this.playFile() : this.playSynth();
  }

  /** Stop playback and release the audio context. Safe to call at any time. */
  stop(): void {
    this.stopped = true;

    const element = this.element;
    this.element = null;
    if (element) {
      element.pause();
      element.currentTime = 0;
    }

    const master = this.master;
    const context = this.context;
    this.master = null;
    this.context = null;
    if (!context || context.state === "closed") return;

    if (master) {
      const now = context.currentTime;
      master.gain.cancelScheduledValues(now);
      master.gain.setValueAtTime(Math.max(master.gain.value, 0.0001), now);
      master.gain.linearRampToValueAtTime(0.0001, now + 0.08);
      window.setTimeout(() => void context.close().catch(() => undefined), 160);
      return;
    }
    void context.close().catch(() => undefined);
  }

  private playFile(): boolean {
    try {
      const element = new Audio(SUPPLIED_THEME_URL);
      element.preload = "auto";
      element.volume = 0.6;
      this.element = element;
      const attempt = element.play();
      if (attempt) {
        attempt.catch(() => {
          this.element = null;
          if (!this.stopped) this.playSynth();
        });
      }
      return true;
    } catch {
      return this.playSynth();
    }
  }

  private playSynth(): boolean {
    if (this.stopped) return false;
    const Ctor =
      window.AudioContext ??
      (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!Ctor) return false;

    const context = this.context ?? new Ctor();
    this.context = context;

    if (context.state === "suspended") {
      void context.resume();
      // Scheduling notes now would fire them in a burst once a gesture finally
      // resumes the context, so report back and let the UI ask for a click.
      if (!gestureAllowsAudio()) return false;
    }

    const master = context.createGain();
    const base = context.currentTime + 0.06;
    master.gain.setValueAtTime(0.0001, base);
    master.gain.linearRampToValueAtTime(1, base + 0.08);
    master.connect(context.destination);
    this.master = master;

    for (const [note, start, length] of LEAD) {
      this.schedule(context, master, note, base, start, length, "lead");
    }
    for (const [note, start, length] of BASS) {
      this.schedule(context, master, note, base, start, length, "bass");
    }
    for (const beat of BLIP_BEATS) {
      this.schedule(context, master, "C6", base, beat, 0.15, "blip");
    }
    return true;
  }

  private schedule(
    context: AudioContext,
    destination: AudioNode,
    note: string,
    base: number,
    startBeat: number,
    lengthBeats: number,
    voice: VoiceName,
  ): void {
    const profile = VOICES[voice];
    const startAt = base + startBeat * BEAT_SECONDS;
    const duration = Math.max(0.06, lengthBeats * BEAT_SECONDS);
    const attack = Math.min(profile.attack, duration / 2);
    const release = Math.min(profile.release, duration / 2);

    const oscillator = context.createOscillator();
    const gain = context.createGain();
    oscillator.type = profile.type;
    oscillator.frequency.setValueAtTime(frequencyFor(SEMITONE[note] ?? 0), startAt);

    gain.gain.setValueAtTime(0.0001, startAt);
    gain.gain.linearRampToValueAtTime(profile.peak, startAt + attack);
    gain.gain.setValueAtTime(profile.peak, startAt + Math.max(attack, duration - release));
    gain.gain.linearRampToValueAtTime(0.0001, startAt + duration);

    oscillator.connect(gain).connect(destination);
    oscillator.start(startAt);
    oscillator.stop(startAt + duration + 0.05);
  }
}
