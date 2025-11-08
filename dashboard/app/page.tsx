'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Activity, Target, Brain, AlertTriangle } from 'lucide-react';
import ThreatMap from '../src/components/ThreatMap';
import EventCard from '../src/components/EventCard';
import RoutingVisualizer from '../src/components/RoutingVisualizer';
import LabyrinthTerminal from '../src/components/LabyrinthTerminal';
import SentinelPanel from '../src/components/SentinelPanel';
import MetricsBar from '../src/components/MetricsBar';
import { useWarRoom } from '../src/hooks/useWarRoom';

export default function WarRoom() {
  const {
    events,
    normalTraffic,
    attackTraffic,
    routingState,
    labyrinthActivity,
    sentinelAnalysis,
    metrics,
    isConnected,
    demoStep,
  } = useWarRoom();

  const [currentStep, setCurrentStep] = useState<string>('idle');

  useEffect(() => {
    if (demoStep !== null) {
      setCurrentStep(String(demoStep));
    }
  }, [demoStep]);

  return (
    <div className="relative min-h-screen overflow-hidden bg-cerberus-darker text-white">
      <div className="absolute inset-0 bg-cerberus-radial opacity-90 pointer-events-none" />
      <div className="absolute inset-0 bg-[rgba(5,8,16,0.85)]" />
      <div className="absolute inset-0 mix-blend-screen opacity-50 bg-[radial-gradient(circle_at_top_left,rgba(0,255,65,0.25),transparent_55%)]" />
      <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(115deg,rgba(0,255,65,0.1)_0%,rgba(0,0,0,0)_40%,rgba(255,0,64,0.15)_90%)]" />
      <div className="scan-lines" />

      <main className="relative z-10 mx-auto flex min-h-screen w-full max-w-[1600px] flex-col px-6 pb-10">
        {/* Header */}
        <header className="relative mt-6 overflow-hidden rounded-2xl border border-cerberus-primary/30 bg-gradient-to-r from-[#0c121d]/80 via-[#091019]/70 to-[#0f111a]/80 px-8 py-6 shadow-[0_25px_80px_rgba(0,255,65,0.12)]">
          <div className="absolute -top-24 -right-24 h-64 w-64 rounded-full bg-cerberus-primary/15 blur-3xl" />
          <div className="absolute -bottom-20 -left-16 h-48 w-48 rounded-full bg-cerberus-danger/20 blur-3xl" />
          <div className="relative flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
            <div className="flex items-start gap-4">
              <div className="relative flex h-16 w-16 items-center justify-center rounded-2xl border border-cerberus-primary/40 bg-[#0d141f] shadow-neon">
                <Shield className="h-9 w-9 text-cerberus-primary" />
                <span className="absolute -bottom-3 rounded-full bg-[#0d141f] px-3 py-1 text-[0.6rem] uppercase tracking-[0.3em] text-cerberus-primary/70">Live</span>
              </div>
              <div className="space-y-1">
                <p className="text-xs uppercase tracking-[0.4em] text-gray-400">Project Cerberus</p>
                <h1 className="text-3xl font-semibold text-white md:text-4xl lg:text-5xl">
                  Active Defense War Room
                </h1>
                <p className="max-w-xl text-sm text-gray-400 md:text-base">
                  Real-time visualization of the Cerberus immune system. Watch detection, deception, analysis, and
                  neutralization unfold live.
                </p>
              </div>
            </div>

            <div className="flex flex-col items-end gap-4">
              <div className="flex items-center gap-3 rounded-full border border-cerberus-primary/40 bg-[#0d141f]/70 px-4 py-2 text-xs uppercase tracking-[0.35em] text-gray-300">
                <div className={`h-2 w-2 rounded-full ${isConnected ? 'bg-cerberus-primary' : 'bg-gray-500'} animate-pulse`} />
                {isConnected ? 'Secure telemetry link established' : 'Establishing secure feed'}
              </div>
              <MetricsBar metrics={metrics} />
            </div>
          </div>
        </header>

        {/* Main layout */}
        <section className="mt-6 grid flex-1 grid-cols-1 gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          {/* Left Column - Map & Routing */}
          <div className="flex h-full flex-col gap-6">
            {/* Threat Map */}
            <motion.div
              layout
              className="relative h-[680px] md:h-[760px] xl:h-[840px] overflow-hidden rounded-2xl border border-cerberus-primary/20 bg-[#0b121d]/90 shadow-card"
            >
              <div className="absolute inset-0 grid-overlay opacity-40" />
              <div className="relative z-10 flex items-center justify-between border-b border-cerberus-primary/30 px-6 py-4">
                <div className="flex items-center gap-3">
                  <Target className="h-5 w-5 text-cerberus-primary" />
                  <div>
                    <h2 className="text-lg font-semibold text-white uppercase tracking-widest">Global threat map</h2>
                    <p className="text-xs text-gray-500 tracking-[0.3em] uppercase">Live traffic telemetry</p>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-xs text-gray-400">
                  <span className="flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-cerberus-primary" /> Normal
                  </span>
                  <span className="flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-cerberus-danger" /> Threat
                  </span>
                </div>
              </div>
              <ThreatMap normalTraffic={normalTraffic} attackTraffic={attackTraffic} />
            </motion.div>

            {/* Routing Visualizer */}
            <motion.div
              layout
              className="relative h-56 overflow-hidden rounded-2xl border border-cerberus-primary/20 bg-[#0b121d]/90 px-6 py-5 shadow-card"
            >
              <div className="absolute inset-0 opacity-30" style={{ backgroundImage: 'var(--cerberus-grid)' }} />
              <div className="relative flex items-center justify-between border-b border-cerberus-primary/20 pb-4">
                <div className="flex items-center gap-3">
                  <Activity className="h-5 w-5 text-cerberus-warning" />
                  <div>
                    <h2 className="text-sm font-semibold uppercase tracking-[0.4em] text-gray-200">Traffic routing</h2>
                    <p className="text-xs text-gray-500">Dynamic session pinning and deception pathways</p>
                  </div>
                </div>
                {routingState.sessionId && (
                  <div className="text-[0.65rem] uppercase tracking-[0.35em] text-gray-500">
                    Session {routingState.sessionId.slice(-6)}
                  </div>
                )}
              </div>
              <div className="relative mt-4 h-[calc(100%-80px)]">
                <RoutingVisualizer state={routingState} />
              </div>
            </motion.div>
          </div>

          {/* Right Column - Events & Analysis */}
          <div className="flex h-full flex-col gap-6">
            {/* Event Stream */}
            <motion.div
              layout
              className="relative flex-1 overflow-hidden rounded-2xl border border-cerberus-primary/20 bg-[#0b121d]/95 shadow-card"
            >
              <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-cerberus-primary/60 via-transparent to-cerberus-danger/50" />
              <div className="relative flex items-center justify-between border-b border-cerberus-primary/20 px-6 py-4">
                <div className="flex items-center gap-3">
                  <AlertTriangle className="h-5 w-5 text-cerberus-danger" />
                  <div>
                    <h2 className="text-sm font-semibold uppercase tracking-[0.4em] text-gray-200">Threat events</h2>
                    <p className="text-xs text-gray-500">Live feed from Gatekeeper &amp; Switch</p>
                  </div>
                </div>
                <div className="text-[0.65rem] uppercase tracking-[0.3em] text-gray-500">{events.length} recent</div>
              </div>
              <div className="relative flex-1 overflow-y-auto px-6 py-5 scrollbar-thin">
                <div className="grid gap-3">
                  <AnimatePresence>
                    {events.map((event) => (
                      <EventCard key={event.id} event={event} />
                    ))}
                  </AnimatePresence>
                </div>
              </div>
            </motion.div>

            {/* Labyrinth Terminal */}
            {labyrinthActivity.active && (
              <motion.div
                layout
                className="relative overflow-hidden rounded-2xl border border-cerberus-danger/40 bg-[#0b101a]/90 shadow-[0_20px_60px_rgba(255,0,64,0.15)]"
              >
                <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cerberus-danger/70 to-transparent" />
                <div className="relative flex items-center justify-between border-b border-cerberus-danger/40 bg-cerberus-danger/10 px-6 py-4">
                  <div className="flex items-center gap-3">
                    <Target className="h-5 w-5 text-cerberus-danger animate-pulse" />
                    <div>
                      <h2 className="text-sm font-semibold uppercase tracking-[0.4em] text-gray-100">Live attacker activity</h2>
                      <p className="text-xs text-gray-500">Cerberus Labyrinth deception layer</p>
                    </div>
                  </div>
                  <div className="text-[0.65rem] uppercase tracking-[0.3em] text-gray-300">
                    Session {labyrinthActivity.sessionId?.slice(-6)}
                  </div>
                </div>
                <div className="relative px-4 pb-4 pt-3">
                  <LabyrinthTerminal activity={labyrinthActivity.logs} />
                </div>
              </motion.div>
            )}

            {/* Sentinel AI Panel */}
            {sentinelAnalysis.active && (
              <motion.div
                layout
                className="relative overflow-hidden rounded-2xl border border-blue-500/30 bg-[#0a1320]/90 shadow-[0_20px_60px_rgba(0,153,255,0.15)]"
              >
                <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-blue-500/0 via-blue-400/60 to-blue-500/0" />
                <div className="relative border-b border-blue-500/30 bg-blue-500/10 px-6 py-4">
                  <div className="flex items-center gap-3">
                    <Brain className="h-5 w-5 text-blue-300" />
                    <div>
                      <h2 className="text-sm font-semibold uppercase tracking-[0.4em] text-blue-100">Sentinel AI analysis</h2>
                      <p className="text-xs text-blue-200/70">Behavioral profiler • sandbox • rule generator</p>
                    </div>
                  </div>
                </div>
                <div className="relative px-4 py-4">
                  <SentinelPanel analysis={sentinelAnalysis} />
                </div>
              </motion.div>
            )}
          </div>
        </section>
      </main>

      {/* Step Indicator */}
      {currentStep !== 'idle' && (
        <motion.div
          initial={{ y: 80, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ type: 'spring', stiffness: 160, damping: 18 }}
          className="fixed bottom-6 left-1/2 z-20 w-[90vw] max-w-xl -translate-x-1/2 overflow-hidden rounded-2xl border border-cerberus-primary/30 bg-[#0d141f]/95 px-6 py-4 shadow-[0_25px_80px_rgba(0,255,65,0.18)]"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[0.65rem] uppercase tracking-[0.35em] text-cerberus-primary/80">Cerberus Immune Response</p>
              <p className="mt-1 font-mono text-sm text-gray-300">
                <span className="text-cerberus-primary">STEP {currentStep}:</span> {getStepDescription(currentStep)}
              </p>
            </div>
            <div className="text-right text-xs text-gray-500">
              {new Date().toLocaleTimeString([], { timeStyle: 'medium' })}
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}

function getStepDescription(step: string): string {
  const descriptions: Record<string, string> = {
    '1': 'Normal traffic baseline',
    '2': 'Attack detected - SQL Injection',
    '3': 'Rerouting attacker to honeypot',
    '4': 'Attacker engaging with decoy',
    '5': 'Behavioral profiling in progress',
    '6': 'Simulating payload in sandbox',
    '7': 'Generating WAF rule',
    '8': 'Policy orchestrator decision',
    '9': 'Verifying protection'
  };
  return descriptions[step] || 'Processing...';
}
