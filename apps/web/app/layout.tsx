import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "GuardianOps AI",
  description: "Plateforme d'audit permanent SI, monitoring et sécurité.",
};

// Applique le thème AVANT le premier rendu pour éviter tout flash (FOUC).
const themeScript = `
(function(){try{
  var k='guardian_theme';var t=localStorage.getItem(k);
  if(t!=='light'&&t!=='dark'){t=window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';}
  var e=document.documentElement;
  if(t==='dark')e.classList.add('dark');else e.classList.remove('dark');
  e.style.colorScheme=t;
}catch(_){}})();
`;

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="fr" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body className="min-h-screen bg-slate-50 text-slate-900 antialiased dark:bg-guardian-bg dark:text-slate-100">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
