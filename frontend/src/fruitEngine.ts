/**
 * FRUIT (1) by Nothing — Hardware Diagnostic & Acoustic Engine
 * Production-grade nothing-phone inspired fruit hardware simulator.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type GlyphMode = 'flip' | 'ripeness' | 'essential' | 'audio_sync' | 'floodlight';
export type DiagnosticTestId = 'brix' | 'crunch' | 'drop' | 'voltage' | 'latency';
export type EvaluatedStatus = 'OPTIMAL' | 'ACCEPTABLE' | 'DEGRADED';

export interface TestResult {
  id: DiagnosticTestId;
  name: string;
  tag: string;
  status: 'idle' | 'running' | 'passed' | 'failed';
  value: number;
  unit: string;
  nominalRange: string;
  score: number;
  message: string;
  details: string;
}

export interface QualityCertificate {
  certificateId: string;
  batchNumber: string;
  timestamp: string;
  model: string;
  compositeScore: number;
  overallRating: EvaluatedStatus;
  signatureHash: string;
  tests: Record<DiagnosticTestId, { name: string; score: number; status: 'PASSED' | 'FAILED' }>;
}

export interface FruitProduct {
  id: string;
  name: string;
  tagline: string;
  priceUsd: number;
  glyphZones: number;
  storageOptions: string[];
  colorOptions: string[];
  specs: string[];
  description: string;
}

// ─── Fruit Products ───────────────────────────────────────────────────────────

export const FRUIT_PRODUCTS: FruitProduct[] = [
  {
    id: 'fruit-1',
    name: 'FRUIT (1)',
    tagline: 'The original transparent organic flagship.',
    priceUsd: 399,
    glyphZones: 33,
    storageOptions: ['128GB', '256GB', '512GB'],
    colorOptions: ['White', 'Black'],
    specs: [
      '120Hz Pro-Crunch Display',
      '14.4° Brix Natural Sucrose',
      '33-Zone Glyph Matrix',
      '100% Recycled Cellulose Body',
      'Gorilla Cellulose 2.5D Peel',
      '5000mAh Photosynthesis Cell',
      'Zero Bloatware OS 3.0',
    ],
    description:
      'Born from raw organic matter. Engineered with transparent cellulose hardware and a 33-zone glyph interface that pulses with every notification.',
  },
  {
    id: 'fruit-2a',
    name: 'FRUIT (2a)',
    tagline: 'Democratising the Glyph experience.',
    priceUsd: 299,
    glyphZones: 96,
    storageOptions: ['128GB', '256GB'],
    colorOptions: ['White', 'Black', 'Mint'],
    specs: [
      '96-Zone Glyph Matrix (Enhanced)',
      '60Hz Crunch Panel',
      '12.8° Brix Efficiency Profile',
      'Recycled Cellulose Hybrid',
      '4500mAh Photosynthesis Cell',
      'Nothing OS 3.0',
    ],
    description:
      'The 2a brings 96 glyph zones and flagship-grade purity to a compact, accessible form factor with nothing to hide.',
  },
  {
    id: 'fruit-ear',
    name: 'FRUIT (Ear)',
    tagline: 'Acoustic isolation meets Glyph choreography.',
    priceUsd: 99,
    glyphZones: 6,
    storageOptions: ['N/A'],
    colorOptions: ['White', 'Black'],
    specs: [
      '6-Zone Glyph Stems',
      'Custom Organic Acoustic Driver',
      '40dB Active Noise Cancellation',
      '100% Recycled Cellulose Case',
      '36hr Total Battery Life',
      'Instant Audio Sync with FRUIT (1)',
    ],
    description:
      'Transparent stem design with active glyph choreography. The ears of the fruit ecosystem.',
  },
];

// ─── Comparison Data ──────────────────────────────────────────────────────────

export const COMPARISON_DATA: {
  feature: string;
  fruit1: string;
  cupertino: string;
  winner: 'FRUIT (1)';
}[] = [
  {
    feature: 'Transparency Policy',
    fruit1: 'Full hardware transparency. Literal.',
    cupertino: 'Opaque ecosystem. Hidden.',
    winner: 'FRUIT (1)',
  },
  {
    feature: 'Glyph Interface',
    fruit1: '33-Zone programmable LED glyph matrix',
    cupertino: 'No glyph system. Static case.',
    winner: 'FRUIT (1)',
  },
  {
    feature: 'Sucrose Brix Score',
    fruit1: '14.4° Brix — Ideal natural sweetness',
    cupertino: 'Artificially processed. Unknown Brix.',
    winner: 'FRUIT (1)',
  },
  {
    feature: 'Cellulose Material',
    fruit1: '100% Recycled Gorilla Cellulose 2.5D',
    cupertino: 'Aluminium & glass. Non-organic.',
    winner: 'FRUIT (1)',
  },
  {
    feature: 'Bloatware',
    fruit1: 'Zero Bloatware — Nothing OS 3.0',
    cupertino: 'Pre-installed locked ecosystem apps.',
    winner: 'FRUIT (1)',
  },
  {
    feature: 'Repairability Score',
    fruit1: '8.5/10 — Modular organic components',
    cupertino: '3/10 — Proprietary sealed chassis',
    winner: 'FRUIT (1)',
  },
  {
    feature: 'Price',
    fruit1: '$399 — Flagship organic transparency',
    cupertino: '$1199+ — Premium opacity tax',
    winner: 'FRUIT (1)',
  },
];

// ─── Diagnostic Functions ─────────────────────────────────────────────────────

/**
 * TEST 01: Brix Sucrose Spectral Scan
 * Measures natural sucrose density via Brix refractometry.
 */
export function calculateBrixScore(brix: number): { score: number; status: 'passed' | 'failed'; message: string } {
  if (brix >= 12.0 && brix <= 16.0) {
    // Perfect sucrose band
    const score = brix === 14.0 ? 100 : Math.max(90, Math.min(99, Math.round(100 - Math.abs(brix - 14.0) * 4)));
    return {
      score,
      status: 'passed',
      message: `${brix.toFixed(1)}°Bx — Ideal sucrose density. Optimal photosynthetic yield confirmed.`,
    };
  }
  if (brix >= 10.0 && brix < 12.0) {
    return {
      score: 75,
      status: 'passed',
      message: `${brix.toFixed(1)}°Bx — Crisp and tart profile. Early harvest characteristic.`,
    };
  }
  if (brix > 16.0 && brix <= 18.0) {
    return {
      score: 80,
      status: 'passed',
      message: `${brix.toFixed(1)}°Bx — Rich dessert profile. Peak ripeness detected.`,
    };
  }
  return {
    score: 40,
    status: 'failed',
    message: `${brix.toFixed(1)}°Bx — Out-of-tolerance. Sucrose degradation or under-development detected.`,
  };
}

/**
 * TEST 02: 120Hz Crunch Acoustic Snap
 * Verifies structural acoustic resonance at 120Hz nominal.
 */
export function calculateCrunchAcoustics(
  hz: number,
  db: number
): { score: number; status: 'passed' | 'failed'; message: string } {
  if (hz >= 110 && hz <= 130 && db >= 55 && db <= 80) {
    const score = hz === 120 && db >= 65 ? 100 : Math.max(85, Math.min(99, Math.round(90 + (hz - 110) / 2)));
    return {
      score,
      status: 'passed',
      message: `${hz}Hz / ${db}dB — Optimal cellular acoustic snap verified. Crunch integrity nominal.`,
    };
  }
  if (hz < 110 || hz > 140) {
    return {
      score: 45,
      status: 'failed',
      message: `${hz}Hz — Dampened acoustic response. Out-of-band frequency detected.`,
    };
  }
  if (db < 50) {
    return {
      score: 40,
      status: 'failed',
      message: `${db}dB — Acoustic signal too quiet. Cellulose structural weakness suspected.`,
    };
  }
  return {
    score: 72,
    status: 'passed',
    message: `${hz}Hz / ${db}dB — Marginal crunch tolerance. Within acceptable range.`,
  };
}

/**
 * TEST 03: Peel Tensile Drop Resistance
 * Validates Gorilla Cellulose 2.5D structural integrity.
 */
export function calculateDropResistance(
  meters: number,
  microfractures: number
): { score: number; status: 'passed' | 'failed'; message: string } {
  if (meters >= 1.0 && microfractures === 0) {
    return {
      score: 100,
      status: 'passed',
      message: `${meters.toFixed(1)}m drop — Gorilla Cellulose 2.5D intact. Zero microfractures detected.`,
    };
  }
  if (microfractures === 1) {
    return {
      score: 65,
      status: 'passed',
      message: `${meters.toFixed(1)}m — Microfracture absorbed by plant lignin matrix. Structural integrity maintained.`,
    };
  }
  if (microfractures >= 2 && microfractures <= 3) {
    return {
      score: 45,
      status: 'failed',
      message: `${meters.toFixed(1)}m — Multiple microfractures. Peel replacement recommended.`,
    };
  }
  return {
    score: 30,
    status: 'failed',
    message: `${meters.toFixed(1)}m / ${microfractures} fractures — Structural breach. Gorilla Cellulose compromised.`,
  };
}

/**
 * TEST 04: Citric Electrolyte Voltage
 * Measures organic galvanic potential across cellulose matrix.
 */
export function calculateElectrolyteVoltage(
  volts: number
): { score: number; status: 'passed' | 'failed'; message: string } {
  if (volts >= 1.10 && volts <= 1.65) {
    const score = Math.max(90, Math.min(100, Math.round(100 - Math.abs(volts - 1.35) * 20)));
    return {
      score,
      status: 'passed',
      message: `${volts.toFixed(2)}V — Strong galvanic electrolyte active. Citric pathway nominal.`,
    };
  }
  if (volts < 1.10) {
    return {
      score: 50,
      status: 'failed',
      message: `${volts.toFixed(2)}V — Depleted electrolyte potential. Fruit dehydration suspected.`,
    };
  }
  return {
    score: 55,
    status: 'failed',
    message: `${volts.toFixed(2)}V — Over-voltage detected. Fermentation byproducts suspected.`,
  };
}

/**
 * TEST 05: Seed Matrix Biological Latency
 * Tests osmotic transport timing through seed neural network.
 */
export function calculateSeedLatency(
  latencyMs: number
): { score: number; status: 'passed' | 'failed'; message: string } {
  if (latencyMs <= 1.5) {
    const score = Math.max(90, Math.min(100, Math.round(100 - latencyMs * 6)));
    return {
      score,
      status: 'passed',
      message: `${latencyMs.toFixed(1)}ms — Sub-millisecond neural biological impulse delay. Seed matrix optimal.`,
    };
  }
  return {
    score: 55,
    status: 'failed',
    message: `${latencyMs.toFixed(1)}ms — Elevated latency. Osmotic transport lag detected.`,
  };
}

/**
 * Evaluates full test bench and calculates composite score.
 */
export function evaluateFullDiagnostics(results: Record<DiagnosticTestId, TestResult>): {
  compositeScore: number;
  overallRating: EvaluatedStatus;
  allPassed: boolean;
} {
  const keys: DiagnosticTestId[] = ['brix', 'crunch', 'drop', 'voltage', 'latency'];
  const totalScore = keys.reduce((acc, k) => acc + (results[k]?.score ?? 0), 0);
  const compositeScore = Math.round(totalScore / keys.length);
  const allPassed = keys.every((k) => results[k]?.status === 'passed');
  let overallRating: EvaluatedStatus = 'DEGRADED';
  if (compositeScore >= 88 && allPassed) {
    overallRating = 'OPTIMAL';
  } else if (compositeScore >= 70) {
    overallRating = 'ACCEPTABLE';
  }
  return { compositeScore, overallRating, allPassed };
}

/**
 * Generates an official Nothing Quality Inspection Certificate.
 */
export function generateCertificate(
  model = 'FRUIT (1)',
  batchId = 'BATCH-00-NOTHING-ORGANIC',
  customScores?: Partial<Record<DiagnosticTestId, number>>
): QualityCertificate {
  const timestamp = new Date().toISOString();
  const testIds: DiagnosticTestId[] = ['brix', 'crunch', 'drop', 'voltage', 'latency'];
  const testNames: Record<DiagnosticTestId, string> = {
    brix: 'Brix Sucrose Spectral Scan',
    crunch: '120Hz Crunch Acoustic Snap',
    drop: 'Peel Tensile Drop Resistance',
    voltage: 'Citric Electrolyte Voltage',
    latency: 'Seed Matrix Biological Latency',
  };
  const defaultScores: Record<DiagnosticTestId, number> = {
    brix: 98,
    crunch: 97,
    drop: 95,
    voltage: 94,
    latency: 99,
  };

  const tests = {} as Record<DiagnosticTestId, { name: string; score: number; status: 'PASSED' | 'FAILED' }>;
  let sum = 0;
  for (const tid of testIds) {
    const sc = customScores?.[tid] ?? defaultScores[tid];
    sum += sc;
    tests[tid] = {
      name: testNames[tid],
      score: sc,
      status: sc >= 70 ? 'PASSED' : 'FAILED',
    };
  }

  const compositeScore = Math.round(sum / testIds.length);
  const overallRating: EvaluatedStatus =
    compositeScore >= 88 ? 'OPTIMAL' : compositeScore >= 70 ? 'ACCEPTABLE' : 'DEGRADED';

  // Deterministic signature hash simulation
  const rawHash = `${model}-${batchId}-${timestamp}-${compositeScore}`
    .split('')
    .reduce((acc, char) => (acc * 31 + char.charCodeAt(0)) >>> 0, 0)
    .toString(16)
    .toUpperCase()
    .padStart(8, '0');

  const signatureHash = `NOTHING-FRUIT-${rawHash}-SECURE-CERT`;

  return {
    certificateId: `CERT-${Date.now().toString(36).toUpperCase()}`,
    batchNumber: batchId,
    timestamp,
    model,
    compositeScore,
    overallRating,
    signatureHash,
    tests,
  };
}

/**
 * Web Audio API Synthesizer for Teenage Engineering / Nothing mechanical sound feedback.
 * Safe to execute anywhere; silently falls back if AudioContext is unavailable or muted.
 */
export class NothingAcousticEngine {
  private ctx: AudioContext | null = null;
  private isEnabled: boolean = true;

  constructor(enabled = true) {
    this.isEnabled = enabled;
  }

  setEnabled(enabled: boolean): void {
    this.isEnabled = enabled;
  }

  getEnabled(): boolean {
    return this.isEnabled;
  }

  private initContext(): AudioContext | null {
    if (!this.isEnabled) return null;
    if (typeof globalThis === 'undefined') return null;
    const g = globalThis as Record<string, unknown>;
    try {
      if (!this.ctx) {
        const AudioCtx = (g['AudioContext'] || (g['window'] as Record<string, unknown>)?.['AudioContext']) as
          | typeof AudioContext
          | undefined;
        if (AudioCtx) {
          this.ctx = new AudioCtx();
        }
      }
      if (this.ctx && this.ctx.state === 'suspended') {
        void this.ctx.resume();
      }
      return this.ctx;
    } catch {
      return null;
    }
  }

  /** Short, sharp mechanical click inspired by Nothing Phone switches */
  playClick(pitch = 800): void {
    const ctx = this.initContext();
    if (!ctx) return;
    try {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(pitch, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(120, ctx.currentTime + 0.035);
      gain.gain.setValueAtTime(0.18, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.035);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.035);
    } catch {
      // Ignore audio synthesis errors
    }
  }

  /** Dot-matrix glyph activation chime */
  playGlyphChime(): void {
    const ctx = this.initContext();
    if (!ctx) return;
    try {
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(440, now);
      osc.frequency.setValueAtTime(880, now + 0.04);
      osc.frequency.setValueAtTime(1320, now + 0.08);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.16);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(now + 0.16);
    } catch {
      // Ignore
    }
  }

  /** Crisp 120Hz acoustic snap test */
  playCrunchAcoustic(): void {
    const ctx = this.initContext();
    if (!ctx) return;
    try {
      const now = ctx.currentTime;
      // Low frequency crunch body
      const oscLow = ctx.createOscillator();
      const gainLow = ctx.createGain();
      oscLow.type = 'square';
      oscLow.frequency.setValueAtTime(120, now);
      oscLow.frequency.exponentialRampToValueAtTime(40, now + 0.12);
      gainLow.gain.setValueAtTime(0.2, now);
      gainLow.gain.exponentialRampToValueAtTime(0.001, now + 0.12);
      oscLow.connect(gainLow);
      gainLow.connect(ctx.destination);
      oscLow.start();
      oscLow.stop(now + 0.12);
      // High frequency snap
      const oscHigh = ctx.createOscillator();
      const gainHigh = ctx.createGain();
      oscHigh.type = 'sine';
      oscHigh.frequency.setValueAtTime(3200, now);
      oscHigh.frequency.exponentialRampToValueAtTime(600, now + 0.05);
      gainHigh.gain.setValueAtTime(0.25, now);
      gainHigh.gain.exponentialRampToValueAtTime(0.001, now + 0.05);
      oscHigh.connect(gainHigh);
      gainHigh.connect(ctx.destination);
      oscHigh.start();
      oscHigh.stop(now + 0.05);
    } catch {
      // Ignore
    }
  }

  /** Success diagnostic completion sweep */
  playDiagnosticSuccess(): void {
    const ctx = this.initContext();
    if (!ctx) return;
    try {
      const now = ctx.currentTime;
      const notes = [523.25, 659.25, 783.99, 1046.5]; // C5, E5, G5, C6
      notes.forEach((freq, i) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(freq, now + i * 0.07);
        gain.gain.setValueAtTime(0.12, now + i * 0.07);
        gain.gain.exponentialRampToValueAtTime(0.001, now + i * 0.07 + 0.12);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(now + i * 0.07);
        osc.stop(now + i * 0.07 + 0.12);
      });
    } catch {
      // Ignore
    }
  }
}
