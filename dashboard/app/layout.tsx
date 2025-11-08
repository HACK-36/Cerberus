import './globals.css';
import { Rajdhani, Space_Mono } from 'next/font/google';
import type { Metadata } from 'next';

const rajdhani = Rajdhani({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-display',
});

const spaceMono = Space_Mono({
  subsets: ['latin'],
  weight: ['400', '700'],
  variable: '--font-mono',
});

export const metadata: Metadata = {
  title: 'Cerberus War Room',
  description: 'Real-time active defense operations console for Project Cerberus.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${rajdhani.variable} ${spaceMono.variable}`} suppressHydrationWarning>
      <body className="bg-cerberus-darker text-white antialiased">{children}</body>
    </html>
  );
}
