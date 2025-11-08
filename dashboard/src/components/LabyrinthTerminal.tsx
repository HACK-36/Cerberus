'use client';

import { useEffect, useRef } from 'react';

interface LabyrinthTerminalProps {
  activity: Array<{
    timestamp: string;
    action: string;
    endpoint: string;
  }>;
}

export default function LabyrinthTerminal({ activity }: LabyrinthTerminalProps) {
  const terminalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [activity]);

  return (
    <div className="h-full bg-black rounded p-3 font-mono text-xs overflow-hidden flex flex-col">
      <div className="text-green-400 mb-2 text-xs border-b border-gray-700 pb-1">
        $ Attacker Activity Monitor - Session Active
      </div>

      <div
        ref={terminalRef}
        className="flex-1 overflow-y-auto space-y-1"
      >
        {activity.length === 0 ? (
          <div className="text-gray-500 italic">
            Waiting for attacker engagement...
          </div>
        ) : (
          activity.map((log, index) => (
            <div key={index} className="text-green-300">
              <span className="text-gray-500">
                {new Date(log.timestamp).toLocaleTimeString()}
              </span>
              <span className="text-blue-400 ml-2">{log.action}</span>
              <span className="text-yellow-400 ml-2">{log.endpoint}</span>
            </div>
          ))
        )}
      </div>

      {/* Blinking cursor */}
      <div className="text-green-400 mt-2">
        {activity.length > 0 && <span className="animate-pulse">█</span>}
      </div>
    </div>
  );
}
