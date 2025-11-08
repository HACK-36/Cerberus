'use client';

import { motion } from 'framer-motion';

interface RoutingVisualizerProps {
  state: {
    sessionId: string | null;
    isRerouting: boolean;
    target: 'production' | 'labyrinth' | null;
    attackerIp: string | null;
  };
}

export default function RoutingVisualizer({ state }: RoutingVisualizerProps) {
  return (
    <div className="flex items-center justify-center h-full">
      <div className="flex items-center gap-8">
        {/* Production App Box */}
        <motion.div
          className={`px-6 py-4 rounded-lg border-2 font-bold text-sm ${
            state.target === 'production' || !state.isRerouting
              ? 'bg-green-500/20 border-green-500 text-green-400'
              : 'bg-gray-500/20 border-gray-500 text-gray-400'
          }`}
          animate={{
            scale: state.target === 'production' ? 1.1 : 1,
            opacity: state.target === 'production' ? 1 : 0.7,
          }}
        >
          PRODUCTION APP
        </motion.div>

        {/* Routing Arrow */}
        <motion.div
          className="flex flex-col items-center"
          animate={{ opacity: state.isRerouting ? 1 : 0.5 }}
        >
          <motion.div
            className="w-16 h-0.5 bg-cerberus-primary"
            animate={{
              backgroundColor: state.isRerouting ? '#00ff41' : '#666',
              scaleX: state.isRerouting ? 1.2 : 1,
            }}
          />
          <motion.div
            className="text-2xl"
            animate={{
              x: state.isRerouting ? 10 : 0,
              color: state.isRerouting ? '#00ff41' : '#666',
            }}
            transition={{ duration: 0.5, repeat: state.isRerouting ? Infinity : 0, repeatType: 'reverse' }}
          >
            →
          </motion.div>
        </motion.div>

        {/* Labyrinth Box */}
        <motion.div
          className={`px-6 py-4 rounded-lg border-2 font-bold text-sm ${
            state.target === 'labyrinth'
              ? 'bg-red-500/20 border-red-500 text-red-400 animate-pulse-red'
              : 'bg-gray-500/20 border-gray-500 text-gray-400'
          }`}
          animate={{
            scale: state.target === 'labyrinth' ? 1.1 : 1,
            opacity: state.target === 'labyrinth' ? 1 : 0.7,
          }}
        >
          LABYRINTH
        </motion.div>
      </div>

      {/* Status Text */}
      <div className="absolute bottom-2 left-1/2 transform -translate-x-1/2 text-xs text-gray-400">
        {state.isRerouting ? (
          <span className="text-cerberus-primary">
            Routing session {state.sessionId?.slice(-8)} to honeypot...
          </span>
        ) : (
          <span>All traffic → Production</span>
        )}
      </div>
    </div>
  );
}
