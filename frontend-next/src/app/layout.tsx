import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "BaxterSec",
  description: "Evaluación de riesgo de exposición digital con OSINT pasivo",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="es">
      <body>{children}</body>
    </html>
  );
}
