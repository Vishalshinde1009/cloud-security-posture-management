import React, { useState, useEffect } from 'react';
import { Terminal, Activity } from 'lucide-react';

interface TelemetryEvent {
  id: number;
  time: string;
  message: string;
  delta?: string;
  type: 'info' | 'success' | 'warn' | 'score';
}

const INITIAL_EVENTS: TelemetryEvent[] = [
  { id: 1, time: '19:59:21', message: 'AWS connection verified', type: 'success' },
  { id: 2, time: '19:59:23', message: 'IAM resources discovered', delta: '+12', type: 'info' },
  { id: 3, time: '19:59:25', message: 'S3 configuration evaluated', delta: '+08', type: 'info' },
  { id: 4, time: '19:59:27', message: 'EC2 instances inspected', delta: '+04', type: 'info' },
  { id: 5, time: '19:59:29', message: 'Security rules evaluated', delta: '+26', type: 'warn' },
  { id: 6, time: '19:59:31', message: 'Risk calculation completed', type: 'info' },
  { id: 7, time: '19:59:32', message: 'POSTURE SCORE EVALUATED', delta: '47.8', type: 'score' },
];

const STREAMING_POOL = [
  { message: 'VPC route tables analyzed', delta: '+03', type: 'info' as const },
  { message: 'CloudTrail multi-region audit logged', type: 'success' as const },
  { message: 'S3 public bucket policy detected', delta: 'WARN', type: 'warn' as const },
  { message: 'IAM Root MFA enforcement verified', type: 'success' as const },
  { message: 'CIS AWS Foundations 1.4 benchmark mapped', delta: '72.4%', type: 'info' as const },
  { message: 'RDS automated backup retention inspected', delta: '+02', type: 'info' as const },
  { message: 'STS AssumeRole session renewed (1h)', type: 'success' as const },
  { message: 'Deterministic score recalculated', delta: '48.2', type: 'score' as const },
];

export const TelemetryTerminal: React.FC = () => {
  const [events, setEvents] = useState<TelemetryEvent[]>(INITIAL_EVENTS);

  useEffect(() => {
    let counter = 10;
    const interval = setInterval(() => {
      const now = new Date();
      const timeStr = now.toTimeString().split(' ')[0];
      const template = STREAMING_POOL[Math.floor(Math.random() * STREAMING_POOL.length)];

      const nextEvent: TelemetryEvent = {
        id: counter++,
        time: timeStr,
        message: template.message,
        delta: template.delta,
        type: template.type,
      };

      setEvents((prev) => [...prev.slice(-6), nextEvent]);
    }, 2800);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="glass-panel rounded-2xl border border-slate-800/90 p-4 sm:p-5 shadow-2xl relative overflow-hidden flex flex-col justify-between h-full">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-mono font-bold text-white tracking-wider">
            LIVE SECURITY TELEMETRY
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1 text-[9px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/60 uppercase">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            SIMULATED LIVE TELEMETRY
          </span>
        </div>
      </div>

      {/* Terminal Stream Feed */}
      <div className="py-3 space-y-2 font-mono text-[11px] select-none flex-1 overflow-hidden">
        {events.map((evt) => (
          <div
            key={evt.id}
            className="flex items-center justify-between gap-3 text-slate-300 hover:bg-slate-800/30 px-1.5 py-0.5 rounded transition-all animate-fadeIn"
          >
            <div className="flex items-center gap-2.5 truncate">
              <span className="text-slate-400 text-[10px] shrink-0">{evt.time}</span>
              <span
                className={`truncate ${
                  evt.type === 'score'
                    ? 'text-cyan-300 font-bold'
                    : evt.type === 'warn'
                    ? 'text-amber-300'
                    : evt.type === 'success'
                    ? 'text-emerald-300'
                    : 'text-slate-200'
                }`}
              >
                {evt.message}
              </span>
            </div>

            {evt.delta && (
              <span
                className={`text-[10px] px-1.5 py-0.2 rounded font-bold shrink-0 ${
                  evt.type === 'score'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : evt.type === 'warn'
                    ? 'bg-amber-500/10 text-amber-300 border border-amber-500/30'
                    : 'bg-slate-800 text-slate-400 border border-slate-700'
                }`}
              >
                {evt.delta}
              </span>
            )}
          </div>
        ))}
      </div>

      {/* Footer Status Bar */}
      <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
        <span className="flex items-center gap-1.5">
          <Activity className="w-3 h-3 text-emerald-400 animate-pulse" />
          Telemetry Pipeline Active
        </span>
        <span>Polling interval: 2.8s</span>
      </div>
    </div>
  );
};
