'use client';

import { Activity, Shield, AlertTriangle, FileText } from 'lucide-react';

interface MetricsBarProps {
  metrics: {
    totalRequests: number;
    attacksDetected: number;
    attacksBlocked: number;
    sessionsRerouted: number;
    rulesGenerated: number;
  };
}

export default function MetricsBar({ metrics }: MetricsBarProps) {
  const metricsData = [
    {
      label: 'Total Requests',
      value: metrics.totalRequests,
      icon: Activity,
      color: 'text-blue-400',
    },
    {
      label: 'Attacks Detected',
      value: metrics.attacksDetected,
      icon: AlertTriangle,
      color: 'text-orange-400',
    },
    {
      label: 'Attacks Blocked',
      value: metrics.attacksBlocked,
      icon: Shield,
      color: 'text-red-400',
    },
    {
      label: 'Sessions Rerouted',
      value: metrics.sessionsRerouted,
      icon: Activity,
      color: 'text-purple-400',
    },
    {
      label: 'Rules Generated',
      value: metrics.rulesGenerated,
      icon: FileText,
      color: 'text-green-400',
    },
  ];

  return (
    <div className="flex gap-6 text-sm">
      {metricsData.map((metric, index) => {
        const Icon = metric.icon;
        return (
          <div key={index} className="flex items-center gap-2">
            <Icon className={`w-4 h-4 ${metric.color}`} />
            <div>
              <div className="text-gray-400 text-xs">{metric.label}</div>
              <div className="font-bold text-white">{metric.value.toLocaleString()}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
