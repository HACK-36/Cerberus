'use client';

import { useEffect, useRef } from 'react';
import { motion } from 'framer-motion';

interface ThreatMapProps {
  normalTraffic: Array<{ id: string; lat: number; lng: number; timestamp: number }>;
  attackTraffic: Array<{ id: string; lat: number; lng: number; timestamp: number }>;
}

export default function ThreatMap({ normalTraffic, attackTraffic }: ThreatMapProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set canvas size
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;

    // Draw world map (simplified)
    ctx.fillStyle = '#0a0e14';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Draw grid
    ctx.strokeStyle = '#00ff4120';
    ctx.lineWidth = 1;
    for (let i = 0; i < canvas.width; i += 50) {
      ctx.beginPath();
      ctx.moveTo(i, 0);
      ctx.lineTo(i, canvas.height);
      ctx.stroke();
    }
    for (let i = 0; i < canvas.height; i += 50) {
      ctx.beginPath();
      ctx.moveTo(0, i);
      ctx.lineTo(canvas.width, i);
      ctx.stroke();
    }

    // Server location (center)
    const serverX = canvas.width / 2;
    const serverY = canvas.height / 2;

    // Draw server
    ctx.fillStyle = '#00ff41';
    ctx.beginPath();
    ctx.arc(serverX, serverY, 8, 0, Math.PI * 2);
    ctx.fill();
    ctx.strokeStyle = '#00ff41';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Draw normal traffic (green lines)
    normalTraffic.slice(-20).forEach((traffic, index) => {
      const opacity = 1 - index / 20;
      const startX = Math.random() * canvas.width;
      const startY = Math.random() * canvas.height;

      ctx.strokeStyle = `rgba(0, 255, 65, ${opacity * 0.3})`;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(startX, startY);
      ctx.lineTo(serverX, serverY);
      ctx.stroke();

      ctx.fillStyle = `rgba(0, 255, 65, ${opacity})`;
      ctx.beginPath();
      ctx.arc(startX, startY, 3, 0, Math.PI * 2);
      ctx.fill();
    });

    // Draw attack traffic (red lines with pulse)
    attackTraffic.forEach((attack, index) => {
      const opacity = 1 - index / attackTraffic.length;
      const startX = Math.random() * canvas.width;
      const startY = Math.random() * canvas.height;

      // Pulsing effect
      const pulse = Math.sin(Date.now() / 300 + index) * 0.3 + 0.7;

      ctx.strokeStyle = `rgba(255, 0, 64, ${opacity * pulse})`;
      ctx.lineWidth = 2;
      ctx.setLineDash([5, 5]);
      ctx.beginPath();
      ctx.moveTo(startX, startY);
      ctx.lineTo(serverX, serverY);
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.fillStyle = `rgba(255, 0, 64, ${opacity * pulse})`;
      ctx.beginPath();
      ctx.arc(startX, startY, 5, 0, Math.PI * 2);
      ctx.fill();

      // Outer pulse ring
      ctx.strokeStyle = `rgba(255, 0, 64, ${opacity * pulse * 0.5})`;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(startX, startY, 8 * pulse, 0, Math.PI * 2);
      ctx.stroke();
    });

    // Animation loop
    const animate = () => {
      requestAnimationFrame(animate);
    };
    const animationId = requestAnimationFrame(animate);

    return () => cancelAnimationFrame(animationId);
  }, [normalTraffic, attackTraffic]);

  return (
    <div className="relative w-full h-full">
      <canvas
        ref={canvasRef}
        className="w-full h-full"
      />
      <div className="absolute top-4 right-4 bg-cerberus-dark/90 border border-cerberus-primary/20 rounded p-3 text-xs space-y-1">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 bg-cerberus-primary rounded-full" />
          <span>Normal Traffic ({normalTraffic.length})</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 bg-cerberus-danger rounded-full animate-pulse" />
          <span>Active Threats ({attackTraffic.length})</span>
        </div>
      </div>
    </div>
  );
}
