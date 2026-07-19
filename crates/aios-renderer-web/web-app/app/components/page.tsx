import "../aios-ui-generated.css";

// The AIOS shared component library, rendered by the Web renderer from the
// generated `.aios-*` classes — the SAME ComponentRecipes the KDE renderer
// materialises as QML. No hand-authored component styling lives here: every
// colour, border, depth, and layout value comes from the generated stylesheet.
const CONSTITUTIONAL = [
  { cls: "aios-security-banner", tag: "🛡", label: "System integrity verified · SELinux enforcing" },
  { cls: "aios-recovery-shield", tag: "🔒", label: "RECOVERY MODE — cognition offline" },
  { cls: "aios-ai-subject-badge", tag: "◆", label: "AI agent" },
  { cls: "aios-human-subject-badge", tag: "◉", label: "operator" },
  { cls: "aios-trust-indicator", tag: "✓", label: "verified" },
  { cls: "aios-evidence-link-tile", tag: "⛓", label: "ev:9f2a…c1 · FOREVER" },
  { cls: "aios-tamper-warning", tag: "⚠", label: "Evidence hash mismatch at seq 4211" },
] as const;

const RECOGNIZABLE = [
  { cls: "aios-agent-message", tag: "◆ Cognitive Core", label: "· Предлагам да приложа update-а (R2)." },
  { cls: "aios-approval-prompt", tag: "◉ Requires operator approval", label: "system.apply_update(channel=stable) · risk R2" },
  { cls: "aios-audit-trail", tag: "AUDIT", label: "09:41 AI proposed · 09:39 HUMAN approved" },
  { cls: "aios-action-envelope-view", tag: "⟶", label: "created → policy → approved → executing → verifying" },
  { cls: "aios-group-header", tag: "▸", label: "Security & Integrity · 4 surfaces" },
  { cls: "aios-inbox-tile", tag: "▸", label: "Off-host backup pending · INV-033" },
] as const;

function Chip({ cls, tag, label }: { cls: string; tag: string; label: string }) {
  return (
    <div className={cls}>
      <span style={{ fontFamily: "var(--aios-font-code-family), monospace", fontWeight: 700 }}>{tag}</span> {label}
    </div>
  );
}

export default function ComponentsPage() {
  return (
    <main style={{ maxWidth: 980, margin: "0 auto", padding: "40px 24px" }}>
      <h1 style={{ fontSize: "var(--aios-font-display-size)", fontWeight: 700, margin: "0 0 8px" }}>
        AIOS компонентна библиотека
      </h1>
      <p style={{ color: "var(--aios-color-text-secondary)", maxWidth: "64ch", margin: "0 0 32px" }}>
        Всеки блок е стилизиран от своя генериран <code>.aios-*</code> клас — материализация на неговия
        ComponentRecipe. Същите рецепти KDE рендерира като QML.
      </p>
      <h2 style={{ fontSize: "var(--aios-font-heading-size)" }}>Конституционни (7)</h2>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 16, alignItems: "flex-start", marginBottom: 32 }}>
        {CONSTITUTIONAL.map((c) => (<Chip key={c.cls} {...c} />))}
      </div>
      <h2 style={{ fontSize: "var(--aios-font-heading-size)" }}>Разпознаваеми (6)</h2>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 16, alignItems: "flex-start" }}>
        {RECOGNIZABLE.map((c) => (<Chip key={c.cls} {...c} />))}
      </div>
    </main>
  );
}
