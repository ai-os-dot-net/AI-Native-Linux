const ROUTES = [
  { href: "/", label: "Landing" },
  { href: "/recovery", label: "Recovery" },
] as const;

export default function Page() {
  return (
    <main className="aios-shell">
      <h1>AIOS Web Renderer</h1>
      <p className="aios-caption">
        L7 Interaction Layer — styled from the shared AIOS design tokens, so
        this surface matches the KDE renderer.
      </p>
      <nav aria-label="Renderer routes">
        <ul className="aios-nav-list">
          {ROUTES.map((r) => (
            <li key={r.href}>
              <a className="aios-nav-link" href={r.href}>
                {r.label}
              </a>
            </li>
          ))}
        </ul>
      </nav>
      <section
        className="aios-card"
        style={{ marginTop: "var(--aios-spacing-lg)" }}
      >
        <p>gRPC-Web client wiring lands in T-149.</p>
        <p className="aios-caption">
          Colors, spacing, radii, and typography here all resolve from
          <code> var(--aios-*) </code> custom properties.
        </p>
      </section>
    </main>
  );
}
