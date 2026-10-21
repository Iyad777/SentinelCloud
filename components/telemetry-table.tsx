'use client';

import { useEffect, useRef, useState } from 'react';
import { api } from '@/lib/api';
import { useSocket } from './socket-provider';
import { LoadingSpinner } from './loading-spinner';
import { EmptyState } from './empty-state';
import { Download, Filter, Pause, Play, AlertCircle } from 'lucide-react';

export interface TelemetryEvent {
  event_id: string;
  timestamp: string;
  pod_name: string;
  namespace: string;
  syscall_name: string;
  binary: string;
  target: string;
  port: number;
  anomaly_score: number | null;
  is_alert: boolean;
  source?: string;
  data_mode?: string;
}

function mergeEvents(prev: TelemetryEvent[], incoming: TelemetryEvent[], limit: number): TelemetryEvent[] {
  const map = new Map<string, TelemetryEvent>();
  for (const event of [...incoming, ...prev]) {
    if (event?.event_id) map.set(event.event_id, event);
  }
  return Array.from(map.values())
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, limit);
}

export function TelemetryTable({ limit = 20 }: { limit?: number }) {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const { socket } = useSocket();
  const scrollRef = useRef<HTMLDivElement>(null);
  const followLiveRef = useRef(true);

  // Filter state
  const [filterPod, setFilterPod] = useState('');
  const [filterSyscall, setFilterSyscall] = useState('');
  const [filterAlertOnly, setFilterAlertOnly] = useState(false);
  const [paused, setPaused] = useState(false);

  // Derived filtered events
  const filteredEvents = events.filter((e) => {
    if (filterPod && !e.pod_name.toLowerCase().includes(filterPod.toLowerCase())) return false;
    if (filterSyscall && !e.syscall_name.toLowerCase().includes(filterSyscall.toLowerCase())) return false;
    if (filterAlertOnly && !e.is_alert) return false;
    return true;
  });

  useEffect(() => {
    const fetchTelemetry = () => {
      api.get<{ events: TelemetryEvent[] }>(`/api/telemetry/recent?limit=${limit}`)
        .then((data) => {
          if (data.events && data.events.length > 0) {
            setEvents((prev) => mergeEvents(prev, data.events, limit));
          }
        })
        .catch(() => {})
        .finally(() => setLoading(false));
    };

    fetchTelemetry();
    const interval = setInterval(fetchTelemetry, 2000);
    return () => clearInterval(interval);
  }, [limit]);

  useEffect(() => {
    if (!socket) return;
    const handler = (event: TelemetryEvent) => {
      setEvents((prev) => mergeEvents(prev, [event], limit));
    };
    socket.on('telemetry_event', handler);
    return () => {
      socket.off('telemetry_event', handler);
    };
  }, [socket, limit]);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el || !followLiveRef.current) return;
    el.scrollTop = 0;
  }, [events]);

  const handleExport = () => {
    const headers = ['Time', 'Source', 'Pod', 'Syscall', 'Binary', 'Target', 'Port', 'Score', 'Alert'];
    const rows = filteredEvents.map((e) => [
      new Date(e.timestamp).toLocaleTimeString(),
      e.source || '-',
      e.pod_name,
      e.syscall_name,
      e.binary,
      e.target,
      e.port || '-',
      e.anomaly_score !== null ? e.anomaly_score.toFixed(3) : 'N/A',
      e.is_alert ? 'ALERT' : '-'
    ]);
    const csv = [headers, ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'telemetry.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) return <LoadingSpinner />;
  if (!events.length) return <EmptyState message="No telemetry events yet" subtitle="Awaiting eBPF kernel telemetry stream" />;

  return (
    <div className="flex flex-col">
      <div className="flex items-center gap-3 mb-4">
        <h2 className="text-lg font-semibold text-foreground">Telemetry Events</h2>
        <span className="text-xs text-muted-foreground">{events.length} events</span>
      </div>

      {/* Controls bar */}
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-muted-foreground" />
          <input
            type="text"
            placeholder="Filter by Pod..."
            value={filterPod}
            onChange={(e) => setFilterPod(e.target.value)}
            className="px-2 py-1 rounded text-xs bg-background border border-border text-foreground text-sm placeholder-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          />
          <input
            type="text"
            placeholder="Filter by Syscall..."
            value={filterSyscall}
            onChange={(e) => setFilterSyscall(e.target.value)}
            className="px-2 py-1 rounded text-xs bg-background border border-border text-foreground text-sm placeholder-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          />
          <label className="flex items-center gap-2 px-2 py-1 rounded text-xs bg-background border border-border text-foreground text-sm cursor-pointer">
            <input
              type="checkbox"
              checked={filterAlertOnly}
              onChange={(e) => setFilterAlertOnly(e.target.checked)}
              className="rounded border-border text-primary focus:ring-primary"
            />
            Alert Only
          </label>
          <button
            onClick={() => setPaused((p) => !p)}
            className="flex items-center gap-2 px-2 py-1 rounded text-xs bg-muted border border-border text-muted-foreground hover:bg-muted/50"
          >
            <span className="w-3.5 h-3.5 shrink-0">{paused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}</span>
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-2.5 py-1 rounded text-xs bg-blue-500/10 border border-blue-500/30 text-blue-600 hover:bg-blue-500/20"
          >
            <Download className="w-3.5 h-3.5" /> Export CSV
          </button>
        </div>
      </div>

      <div
        ref={scrollRef}
        onScroll={() => {
          const el = scrollRef.current;
          if (!el) return;
          followLiveRef.current = el.scrollTop < 48;
        }}
        className="max-h-[28rem] overflow-y-auto overflow-x-auto overscroll-contain border border-border rounded-lg bg-card"
      >
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10">
            <tr className="border-b border-border bg-muted text-left text-muted-foreground text-xs uppercase tracking-wider">
              <th className="p-2.5">Time</th>
              <th className="p-2.5">Provenance</th>
              <th className="p-2.5">Pod</th>
              <th className="p-2.5">Syscall</th>
              <th className="p-2.5">Binary</th>
              <th className="p-2.5">Target</th>
              <th className="p-2.5">Port</th>
              <th className="p-2.5">Score</th>
              <th className="p-2.5 text-center">Alert</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border font-mono text-xs">
            {filteredEvents.length === 0 ? (
              <tr>
                <td className="p-4 text-center text-muted-foreground" colSpan={9}>
                  No matching events found
                </td>
              </tr>
            ) : (
              filteredEvents.map((e) => (
                <tr key={e.event_id} className={`hover:bg-muted/50 transition-colors ${e.is_alert ? 'bg-destructive/5' : ''}`}>
                  <td className="p-2.5 whitespace-nowrap text-muted-foreground">
                    {new Date(e.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="p-2.5 whitespace-nowrap">
                    {e.source === 'lab_test' ? (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-500/15 text-amber-500 border border-amber-500/30">
                        API Test (PC2)
                      </span>
                    ) : e.source === 'replay' ? (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-purple-500/15 text-purple-400 border border-purple-500/30">
                        Replay
                      </span>
                    ) : e.source === 'tetragon' || e.source === 'ebpf_probe' ? (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                        Kernel eBPF
                      </span>
                    ) : (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-500/15 text-blue-400 border border-blue-500/30">
                        Telemetry Stream
                      </span>
                    )}
                  </td>
                  <td className="p-2.5 font-medium text-foreground">{e.pod_name}</td>
                  <td className="p-2.5 text-primary">{e.syscall_name}</td>
                  <td className="p-2.5 truncate max-w-[140px]" title={e.binary}>{e.binary}</td>
                  <td className="p-2.5 truncate max-w-[160px]" title={e.target}>{e.target}</td>
                  <td className="p-2.5">{e.port || '-'}</td>
                  <td className="p-2.5 font-semibold">
                    {e.anomaly_score !== null && e.anomaly_score !== undefined
                      ? <span className={e.anomaly_score > 0.72 ? 'text-destructive font-bold' : 'text-foreground'}>
                          {e.anomaly_score.toFixed(3)}
                        </span>
                      : <span className="text-muted-foreground">N/A</span>}
                  </td>
                  <td className="p-2.5 text-center">
                    {e.is_alert ? <span className="text-destructive font-bold" title="High Anomaly Alert">⚠️</span> : <span className="text-muted-foreground/30">-</span>}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
