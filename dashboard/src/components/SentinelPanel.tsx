'use client';

import { motion } from 'framer-motion';
import { Brain, Target, Shield, AlertTriangle } from 'lucide-react';

interface SentinelPanelProps {
  analysis: {
    active: boolean;
    profile: {
      intent: string;
      sophistication: number;
      ttps: string[];
    } | null;
    simulation: {
      status: 'idle' | 'running' | 'completed' | 'failed';
      verdict: string | null;
      severity: number | null;
    };
    ruleGeneration: {
      status: 'idle' | 'generating' | 'generated';
      ruleId: string | null;
      confidence: number | null;
      action: string | null;
    };
  };
}

export default function SentinelPanel({ analysis }: SentinelPanelProps) {
  if (!analysis.active) {
    return (
      <div className="h-full flex items-center justify-center text-gray-500">
        <Brain className="w-8 h-8 mr-2" />
        <span>Awaiting threat analysis...</span>
      </div>
    );
  }

  return (
    <div className="h-full overflow-y-auto space-y-4 p-2">
      {/* Behavioral Profile */}
      {analysis.profile && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-blue-500/10 border border-blue-500/20 rounded p-3"
        >
          <div className="flex items-center gap-2 mb-2">
            <Target className="w-4 h-4 text-blue-400" />
            <h3 className="font-semibold text-sm text-blue-400">BEHAVIORAL PROFILE</h3>
          </div>
          <div className="space-y-1 text-xs">
            <div className="flex justify-between">
              <span className="text-gray-400">Intent:</span>
              <span className="text-white font-medium">{analysis.profile.intent}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Sophistication:</span>
              <span className={`font-bold ${
                analysis.profile.sophistication >= 8 ? 'text-red-400' :
                analysis.profile.sophistication >= 5 ? 'text-yellow-400' : 'text-green-400'
              }`}>
                {analysis.profile.sophistication}/10
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">TTPs:</span>
              <span className="text-orange-400 text-xs">
                {analysis.profile.ttps.join(', ')}
              </span>
            </div>
          </div>
        </motion.div>
      )}

      {/* Sandbox Simulation */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="bg-purple-500/10 border border-purple-500/20 rounded p-3"
      >
        <div className="flex items-center gap-2 mb-2">
          <Shield className="w-4 h-4 text-purple-400" />
          <h3 className="font-semibold text-sm text-purple-400">SANDBOX SIMULATION</h3>
        </div>
        <div className="space-y-1 text-xs">
          <div className="flex justify-between">
            <span className="text-gray-400">Status:</span>
            <span className={`font-medium ${
              analysis.simulation.status === 'completed' ? 'text-green-400' :
              analysis.simulation.status === 'running' ? 'text-yellow-400 animate-pulse' :
              analysis.simulation.status === 'failed' ? 'text-red-400' : 'text-gray-400'
            }`}>
              {analysis.simulation.status.toUpperCase()}
            </span>
          </div>
          {analysis.simulation.verdict && (
            <div className="flex justify-between">
              <span className="text-gray-400">Verdict:</span>
              <span className={`font-bold ${
                analysis.simulation.verdict.includes('possible') ? 'text-red-400' : 'text-green-400'
              }`}>
                {analysis.simulation.verdict.toUpperCase()}
              </span>
            </div>
          )}
          {analysis.simulation.severity !== null && (
            <div className="flex justify-between">
              <span className="text-gray-400">Severity:</span>
              <span className={`font-bold ${
                analysis.simulation.severity >= 7 ? 'text-red-400' :
                analysis.simulation.severity >= 4 ? 'text-yellow-400' : 'text-green-400'
              }`}>
                {analysis.simulation.severity}/10
              </span>
            </div>
          )}
        </div>
      </motion.div>

      {/* Rule Generation */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="bg-green-500/10 border border-green-500/20 rounded p-3"
      >
        <div className="flex items-center gap-2 mb-2">
          <AlertTriangle className="w-4 h-4 text-green-400" />
          <h3 className="font-semibold text-sm text-green-400">RULE GENERATION</h3>
        </div>
        <div className="space-y-1 text-xs">
          <div className="flex justify-between">
            <span className="text-gray-400">Status:</span>
            <span className={`font-medium ${
              analysis.ruleGeneration.status === 'generated' ? 'text-green-400' :
              analysis.ruleGeneration.status === 'generating' ? 'text-yellow-400 animate-pulse' : 'text-gray-400'
            }`}>
              {analysis.ruleGeneration.status.toUpperCase()}
            </span>
          </div>
          {analysis.ruleGeneration.ruleId && (
            <div className="flex justify-between">
              <span className="text-gray-400">Rule ID:</span>
              <span className="text-cyan-400 font-mono text-xs">
                {analysis.ruleGeneration.ruleId}
              </span>
            </div>
          )}
          {analysis.ruleGeneration.confidence !== null && (
            <div className="flex justify-between">
              <span className="text-gray-400">Confidence:</span>
              <span className={`font-bold ${
                analysis.ruleGeneration.confidence >= 0.9 ? 'text-green-400' :
                analysis.ruleGeneration.confidence >= 0.7 ? 'text-yellow-400' : 'text-orange-400'
              }`}>
                {(analysis.ruleGeneration.confidence * 100).toFixed(1)}%
              </span>
            </div>
          )}
          {analysis.ruleGeneration.action && (
            <div className="flex justify-between">
              <span className="text-gray-400">Action:</span>
              <span className="text-white font-bold">
                {analysis.ruleGeneration.action.toUpperCase()}
              </span>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
