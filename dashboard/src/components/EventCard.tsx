'use client';

import { motion } from 'framer-motion';
import { AlertTriangle, Shield, ShieldOff, ScanLine } from 'lucide-react';

interface EventCardProps {
  event: {
    id: string;
    type: string;
    timestamp: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    source_ip: string;
    session_id: string;
    action: string;
    score: number;
    details: any;
  };
}

export default function EventCard({ event }: EventCardProps) {
  const severityColors = {
    low: 'from-yellow-500/10 to-yellow-500/5 border-yellow-500/30 shadow-[0_18px_40px_rgba(255,193,7,0.08)]',
    medium: 'from-orange-500/10 to-orange-500/5 border-orange-500/30 shadow-[0_22px_50px_rgba(255,152,0,0.12)]',
    high: 'from-red-500/15 to-red-500/5 border-red-500/40 shadow-[0_25px_60px_rgba(255,82,82,0.18)]',
    critical: 'from-red-600/20 to-red-500/10 border-red-500/60 shadow-[0_30px_80px_rgba(255,23,68,0.25)]',
  };

  const actionColors = {
    allow: { label: 'Allowed', classes: 'text-cerberus-primary/80', Icon: Shield },
    tag_poi: { label: 'Tagged', classes: 'text-cerberus-warning', Icon: ScanLine },
    block: { label: 'Blocked', classes: 'text-cerberus-danger', Icon: ShieldOff },
  };

  const actionMeta = actionColors[event.action as keyof typeof actionColors] ?? {
    label: event.action,
    classes: 'text-gray-300',
    Icon: Shield,
  };

  return (
    <motion.div
      initial={{ x: 100, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: -100, opacity: 0 }}
      className={`relative overflow-hidden rounded-xl border bg-gradient-to-br px-4 py-3 transition-all duration-300 hover:border-cerberus-primary/60 hover:shadow-[0_28px_90px_rgba(0,255,65,0.18)] ${
        severityColors[event.severity]
      }`}
    >
      <div className="absolute inset-0 opacity-10" style={{ backgroundImage: 'var(--cerberus-grid)' }} />
      <div className="relative flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[#131a27]/80">
            <AlertTriangle className="h-5 w-5 text-cerberus-danger" />
          </div>
          <div>
            <span className="text-[0.65rem] uppercase tracking-[0.35em] text-gray-500">Threat</span>
            <p className="text-base font-semibold uppercase tracking-widest text-gray-100">{event.type}</p>
          </div>
        </div>
        <div className="text-xs text-gray-400">
          {new Date(event.timestamp).toLocaleTimeString([], { timeStyle: 'medium' })}
        </div>
      </div>

      <div className="relative mt-3 grid gap-2 text-xs text-gray-300">
        <div className="flex items-center justify-between gap-2">
          <span className="tracking-[0.3em] uppercase text-gray-500">Source IP</span>
          <span className="font-mono text-sm text-gray-100">{event.source_ip}</span>
        </div>
        <div className="flex items-center justify-between gap-2">
          <span className="tracking-[0.3em] uppercase text-gray-500">Session</span>
          <span className="font-mono text-xs text-gray-300">{event.session_id.slice(0, 20)}...</span>
        </div>
        <div className="flex items-center justify-between gap-2">
          <span className="tracking-[0.3em] uppercase text-gray-500">Combined Score</span>
          <span
            className={`font-semibold ${
              event.score >= 80 ? 'text-cerberus-danger' : event.score >= 50 ? 'text-cerberus-warning' : 'text-cerberus-primary'
            }`}
          >
            {event.score.toFixed(2)}
          </span>
        </div>
        <div className="flex items-center justify-between gap-2">
          <span className="tracking-[0.3em] uppercase text-gray-500">Decision</span>
          <span className={`flex items-center gap-2 font-semibold uppercase ${actionMeta.classes}`}>
            <actionMeta.Icon className="h-3 w-3" /> {actionMeta.label}
          </span>
        </div>
      </div>
    </motion.div>
  );
}
