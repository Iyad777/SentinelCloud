'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { useSocket } from '@/components/socket-provider';
import { MetricCard } from '@/components/metric-card';
import { ServiceCard, ServiceInfo } from '@/components/service-card';
import { TelemetryTable } from '@/components/telemetry-table';
import { LoadingSpinner } from '@/components/loading-spinner';
import { Sparkline, DonutChart } from '@/components/charts';
import { PageShell } from '@/components/ui/page-shell';
import { Card } from '@/components/ui/card';

export default function DashboardOverviewPage() {
  const [metrics, setMetrics] = useState<any>(null);
  const [services, setServices] = useState<Record<string, ServiceInfo>>({});
  const [loading, setLoading] = useState(true);
  const { socket } = useSocket();

  // Chart data
  const [scoreHistory, setScoreHistory] = useState<number[]>([]);
  const [eventCounts, setEventCounts] = useState({ normal: 0, anomaly: 0 });

  useEffect(() => {
    const fetchData = () => {
      Promise.all([
        api.get<any>('/api/metrics/').then((m) => {
          setMetrics(m);
          if (m) {
            setEventCounts({
              normal: Math.max(0, (m.events_processed || 0) - (m.alerts_total || 0)),
              anomaly: m.alerts_total || 0,
            });
          }
        }).catch(() => null),
        api.get<{ services: Record<string, ServiceInfo> }>('/api/services/')
          .then((res) => setServices(res.services || {}))
          .catch(() => ({})),
        api.get<any>('/api/detection/recent?limit=30')
          .then((d) => {
            const scores = (d.detections || []).map((x: any) => x.anomaly_score ?? 0);
            if (scores.length >= 5) {
              setScoreHistory((prev) => (prev.length === 0 ? scores : prev));
            } else {
              setScoreHistory((prev) => (prev.length === 0 ? Array(25).fill(0.02) : prev));
            }
          })
          .catch(() => setScoreHistory((prev) => (prev.length === 0 ? Array(25).fill(0.02) : prev))),
      ]).finally(() => setLoading(false));
    };

    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!socket) return;

    const onMetrics = (data: any) => setMetrics(data);
    const onService = (data: { name: string; service: ServiceInfo }) => {
      setServices((prev) => ({ ...prev, [data.name]: data.service }));
    };

    const onDetection = (data: any) => {
      setScoreHistory((prev) => [...prev.slice(-39), data.anomaly_score ?? 0]);
      setEventCounts((prev) => ({
        normal: prev.normal + (data.is_anomaly ? 0 : 1),
        anomaly: prev.anomaly + (data.is_anomaly ? 1 : 0),
      }));
    };

    const onResult = (data: any) => {
      setScoreHistory((prev) => [...prev.slice(-39), data.anomaly_score ?? 0]);
      setEventCounts((prev) => ({ normal: prev.normal + 1, anomaly: prev.anomaly }));
    };

    socket.on('metrics_update', onMetrics);
    socket.on('service_update', onService);
    socket.on('detection_alert', onDetection);
    socket.on('detection_result', onResult);

    return () => {
      socket.off('metrics_update', onMetrics);
      socket.off('service_update', onService);
      socket.off('detection_alert', onDetection);
      socket.off('detection_result', onResult);
    };
  }, [socket]);

  if (loading) return <LoadingSpinner />;

  const totalEvents = eventCounts.normal + eventCounts.anomaly;

  return (
    <PageShell
      title="Cyber-Resilience Overview"
      subtitle="Autonomous defense, real-time eBPF streaming anomaly detection, and MAPE-K mitigation loop."
      icon={<svg className="w-7 h-7" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" /></svg>}
    >
      {/* Metrics Row */}
      <Card className="p-5">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <MetricCard label="Events Processed" value={metrics?.events_processed ?? 0} />
          <MetricCard label="Alerts Total" value={metrics?.alerts_total ?? 0} />
          <MetricCard label="Avg MTTD" value={metrics?.mttd_label ?? 'N/A'} sublabel={metrics?.mttd_samples ? `${metrics.mttd_samples} sample(s)` : 'No alerts recorded'} />
          <MetricCard label="Avg MTTR" value={metrics?.mttr_label ?? 'N/A'} sublabel={metrics?.mttr_samples ? `${metrics.mttr_samples} sample(s)` : 'No recoveries recorded'} />
        </div>
      </Card>

      {/* Charts Row */}
      <Card className="p-5">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Anomaly Score Sparkline */}
          <div className="bg-card border border-border rounded-lg p-5 lg:col-span-2">
            <div className="flex justify-between items-center mb-3">
              <h2 className="text-sm font-semibold text-foreground">Live Anomaly Scores</h2>
              <span className="text-[10px] text-muted-foreground font-mono">
                {scoreHistory.length > 0 ? `${scoreHistory.length} events` : 'Waiting for events...' }
              </span>
            </div>
            <Sparkline
              data={scoreHistory}
              width={620}
              height={90}
              color="#6366f1"
              showDots={false}
              threshold={0.72}
              thresholdColor="#ef4444"
              label="overview-score"
            />
            <div className="flex justify-between mt-2 text-[10px] text-muted-foreground">
              <span>Score: 0.0</span>
              <span className="text-destructive font-medium">— threshold: 0.72</span>
              <span>1.0</span>
            </div>
          </div>

          {/* Detection Distribution Donut */}
          <div className="bg-card border border-border rounded-lg p-5 flex flex-col items-center justify-center">
            <h2 className="text-sm font-semibold text-foreground mb-4 self-start">Detection Summary</h2>
            <DonutChart
              data={[
                { label: 'Normal', value: eventCounts.normal, color: '#10b981' },
                { label: 'Anomaly', value: eventCounts.anomaly, color: '#ef4444' },
              ]}
              size={120}
              centerValue={totalEvents}
              centerLabel="total"
            />
          </div>
        </div>
      </Card>

      {/* Protected Services */}
      <div className="mt-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold text-foreground">Medical Microservices</h2>
          <span className="text-xs text-muted-foreground">Namespace: medical</span>
        </div>
        <Card className="p-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {Object.values(services).map((svc) => (
              <ServiceCard key={svc.name} service={svc} />
            ))}
          </div>
        </Card>
      </div>

      {/* Telemetry Stream */}
      <div className="mt-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold text-foreground">Live Telemetry Ingestion</h2>
          <span className="text-xs text-muted-foreground">Real-time eBPF/Tetragon Stream</span>
        </div>
        <TelemetryTable limit={150} />
      </div>
    </PageShell>
  );
}
