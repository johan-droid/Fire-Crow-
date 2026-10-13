import { useCallback, useEffect, useRef, useState } from 'react';
import { SAMPLE_FINDINGS, type FindingMock } from '../data/landingData';

type Stage = { id: string; label: string; scanner: FindingMock['scanner'] | null };

const STAGES: Stage[] = [
  { id: 'intake', label: 'Fetch repository', scanner: null },
  { id: 'gitleaks', label: 'Gitleaks', scanner: 'gitleaks v8.18.2' },
  { id: 'semgrep', label: 'Semgrep', scanner: 'semgrep v1.62.0' },
  { id: 'osv', label: 'OSV-Scanner', scanner: 'osv-scanner v1.7.0' },
  { id: 'ledger', label: 'Write ledger', scanner: null },
];

const WEIGHT: Record<FindingMock['severity'], number> = { critical: 20, high: 10, medium: 4, low: 1 };
const STEP_MS = 650;

function prefersReducedMotion() {
  return typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

export function Ledger() {
  const [done, setDone] = useState(0); // number of finished stages
  const [open, setOpen] = useState<string | null>(null);
  const timer = useRef<number | null>(null);

  const stop = () => {
    if (timer.current !== null) window.clearInterval(timer.current);
    timer.current = null;
  };

  const run = useCallback(() => {
    stop();
    setOpen(null);
    if (prefersReducedMotion()) {
      setDone(STAGES.length);
      return;
    }
    setDone(0);
    timer.current = window.setInterval(() => {
      setDone((d) => {
        if (d + 1 >= STAGES.length) stop();
        return Math.min(d + 1, STAGES.length);
      });
    }, STEP_MS);
  }, []);

  useEffect(() => {
    run();
    return stop;
  }, [run]);

  const finishedScanners = new Set(STAGES.slice(0, done).map((s) => s.scanner).filter(Boolean));
  const visible = SAMPLE_FINDINGS.filter((f) => finishedScanners.has(f.scanner));
  const deduction = visible.reduce((sum, f) => sum + WEIGHT[f.severity], 0);
  const complete = done >= STAGES.length;
  const score = 100 - deduction;

  return (
    <section className="lp-ledger" aria-label="Sample audit">
      <header className="lp-ledger-head">
        <div>
          <p className="lp-ledger-repo">acme/payments-api</p>
          <p className="lp-ledger-meta">branch main · commit 9f3c2e1</p>
        </div>
        <button type="button" className="lp-ledger-replay" onClick={run}>
          Replay sample
        </button>
      </header>

      <ol className="lp-stages" aria-label="Scan progress">
        {STAGES.map((s, i) => {
          const state = i < done ? 'done' : i === done && !complete ? 'active' : 'wait';
          return (
            <li key={s.id} className="lp-stage" data-state={state}>
              <span className="lp-stage-mark" aria-hidden="true" />
              <span className="lp-stage-label">{s.label}</span>
              <span className="lp-sr">{state === 'done' ? ', finished' : state === 'active' ? ', running' : ', waiting'}</span>
            </li>
          );
        })}
      </ol>

      <div className="lp-findings" aria-live="polite">
        {visible.length === 0 && <p className="lp-findings-empty">Waiting for the first scanner to report.</p>}
        {visible.map((f) => {
          const isOpen = open === f.id;
          return (
            <div key={f.id} className="lp-finding" data-sev={f.severity}>
              <button
                type="button"
                className="lp-finding-row"
                aria-expanded={isOpen}
                aria-controls={`${f.id}-detail`}
                onClick={() => setOpen(isOpen ? null : f.id)}
              >
                <span className="lp-sev">{f.severity}</span>
                <span className="lp-finding-main">
                  <span className="lp-finding-title">{f.title}</span>
                  <span className="lp-finding-where">
                    {f.filePath}:{f.lineNumber}
                  </span>
                </span>
                <span className="lp-cvss">CVSS {f.cvss.toFixed(1)}</span>
              </button>
              {isOpen && (
                <div className="lp-finding-detail" id={`${f.id}-detail`}>
                  <code className="lp-evidence">{f.evidence}</code>
                  <p className="lp-detail-line">
                    <span>Weakness</span> {f.cwe}
                  </p>
                  <p className="lp-detail-line">
                    <span>Found by</span> {f.scanner}
                  </p>
                  <p className="lp-detail-line">
                    <span>Fix</span> {f.remediation}
                  </p>
                </div>
              )}
            </div>
          );
        })}
      </div>

      <footer className="lp-score" data-complete={complete}>
        <div className="lp-score-num" aria-label={`Risk score ${score} out of 100`}>
          <strong>{score}</strong>
          <span>/ 100</span>
        </div>
        <p className="lp-score-note">
          {complete
            ? `Score = 100 − ${visible.map((f) => `${WEIGHT[f.severity]} (${f.severity})`).join(' − ')}. Sample weights; same findings always give the same score.`
            : 'Score is calculated from findings only, once every scanner has reported.'}
        </p>
      </footer>
    </section>
  );
}
