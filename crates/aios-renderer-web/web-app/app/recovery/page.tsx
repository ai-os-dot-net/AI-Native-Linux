export default function RecoveryPage() {
  return (
    <main className="aios-shell">
      <div className="aios-recovery-banner">
        <h1>Recovery Mode</h1>
        <p>
          This page is served from the recovery origin. Full origin gating and
          recovery-mode UI wiring land in T-149.
        </p>
        <p className="aios-caption">
          The recovery surface uses the same design tokens as the primary
          renderer; the warning-role accent marks the recovery origin.
        </p>
      </div>
    </main>
  );
}
