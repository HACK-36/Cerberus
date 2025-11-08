import { useState, useEffect } from 'react';
import { io, Socket } from 'socket.io-client';

export interface ThreatEvent {
  id: string;
  type: string;
  timestamp: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source_ip: string;
  session_id: string;
  action: string;
  score: number;
  details: any;
}

export interface TrafficPoint {
  id: string;
  lat: number;
  lng: number;
  type: 'normal' | 'attack';
  timestamp: number;
}

export interface RoutingState {
  sessionId: string | null;
  isRerouting: boolean;
  target: 'production' | 'labyrinth' | null;
  attackerIp: string | null;
}

export interface LabyrinthActivity {
  active: boolean;
  sessionId: string | null;
  logs: Array<{
    timestamp: string;
    action: string;
    endpoint: string;
  }>;
}

export interface SentinelAnalysis {
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
}

export interface Metrics {
  totalRequests: number;
  attacksDetected: number;
  attacksBlocked: number;
  sessionsRerouted: number;
  rulesGenerated: number;
}

export function useWarRoom() {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [normalTraffic, setNormalTraffic] = useState<TrafficPoint[]>([]);
  const [attackTraffic, setAttackTraffic] = useState<TrafficPoint[]>([]);
  const [routingState, setRoutingState] = useState<RoutingState>({
    sessionId: null,
    isRerouting: false,
    target: null,
    attackerIp: null,
  });
  const [labyrinthActivity, setLabyrinthActivity] = useState<LabyrinthActivity>({
    active: false,
    sessionId: null,
    logs: [],
  });
  const [sentinelAnalysis, setSentinelAnalysis] = useState<SentinelAnalysis>({
    active: false,
    profile: null,
    simulation: {
      status: 'idle',
      verdict: null,
      severity: null,
    },
    ruleGeneration: {
      status: 'idle',
      ruleId: null,
      confidence: null,
      action: null,
    },
  });
  const [metrics, setMetrics] = useState<Metrics>({
    totalRequests: 0,
    attacksDetected: 0,
    attacksBlocked: 0,
    sessionsRerouted: 0,
    rulesGenerated: 0,
  });
  const [demoStep, setDemoStep] = useState<number | null>(null);

  useEffect(() => {
    // Connect to WebSocket server
    const newSocket = io('http://localhost:8004', {
      transports: ['websocket'],
    });

    newSocket.on('connect', () => {
      console.log('Connected to War Room server');
      setIsConnected(true);
    });

    newSocket.on('disconnect', () => {
      console.log('Disconnected from War Room server');
      setIsConnected(false);
    });

    // Event handlers
    newSocket.on('threat_event', (event: ThreatEvent) => {
      setEvents((prev: ThreatEvent[]) => [event, ...prev].slice(0, 50)); // Keep last 50
      setMetrics((prev: Metrics) => ({
        ...prev,
        totalRequests: prev.totalRequests + 1,
        attacksDetected:
          event.action === 'tag_poi' || event.action === 'block'
            ? prev.attacksDetected + 1
            : prev.attacksDetected,
        attacksBlocked:
          event.action === 'block'
            ? prev.attacksBlocked + 1
            : prev.attacksBlocked,
      }));
    });

    newSocket.on('normal_traffic', (traffic: TrafficPoint) => {
      setNormalTraffic((prev: TrafficPoint[]) => [...prev, traffic].slice(-100));
      setMetrics((prev: Metrics) => ({ ...prev, totalRequests: prev.totalRequests + 1 }));
    });

    newSocket.on('attack_traffic', (traffic: TrafficPoint) => {
      setAttackTraffic((prev: TrafficPoint[]) => [...prev, traffic].slice(-50));
    });

    newSocket.on('routing_update', (state: RoutingState) => {
      setRoutingState(state);
      if (state.target === 'labyrinth') {
        setMetrics((prev: Metrics) => ({
          ...prev,
          sessionsRerouted: prev.sessionsRerouted + 1,
        }));
      }
    });

    newSocket.on('labyrinth_activity', (activity: { sessionId: string; action: string; endpoint: string }) => {
      setLabyrinthActivity((prev: LabyrinthActivity) => ({
        active: true,
        sessionId: activity.sessionId,
        logs: [
          ...prev.logs,
          {
            timestamp: new Date().toISOString(),
            action: activity.action,
            endpoint: activity.endpoint,
          },
        ].slice(-50),
      }));
    });

    newSocket.on('sentinel_profile', (profile: any) => {
      setSentinelAnalysis((prev: SentinelAnalysis) => ({
        ...prev,
        active: true,
        profile,
      }));
    });

    newSocket.on('sentinel_simulation', (simulation: any) => {
      setSentinelAnalysis((prev: SentinelAnalysis) => ({
        ...prev,
        simulation,
      }));
    });

    newSocket.on('sentinel_rule', (rule: any) => {
      setSentinelAnalysis((prev: SentinelAnalysis) => ({
        ...prev,
        ruleGeneration: rule,
      }));
      if (rule.status === 'generated') {
        setMetrics((prev: Metrics) => ({
          ...prev,
          rulesGenerated: prev.rulesGenerated + 1,
        }));
      }
    });

    newSocket.on('demo_step', (step: number) => {
      console.log(`Demo Step ${step}`);
      setDemoStep(step);
    });

    setSocket(newSocket);

    return () => {
      newSocket.close();
    };
  }, []);

  return {
    socket,
    isConnected,
    events,
    normalTraffic,
    attackTraffic,
    routingState,
    labyrinthActivity,
    sentinelAnalysis,
    metrics,
    demoStep,
  };
}
