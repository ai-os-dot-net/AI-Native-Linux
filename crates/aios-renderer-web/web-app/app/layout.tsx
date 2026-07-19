import type { Metadata } from "next";
// Generated design-token custom properties (:root light / dark / prefers dark).
// Source of truth: `aios-design-tokens` crate — see aios-tokens.css header.
import "./aios-tokens.css";
// Base element styling that consumes the tokens above.
import "./globals.css";

export const metadata: Metadata = {
  title: "AIOS Renderer",
  description: "AIOS Web Renderer — L7 Interaction Layer",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        {children}
        {/* INV I2: closed shadow root attachment happens client-side in T-149 */}
        <div
          id="aios-chrome-shadow-root-host"
          style={{ position: "fixed", top: 0, left: 0, zIndex: 9999 }}
        />
      </body>
    </html>
  );
}
