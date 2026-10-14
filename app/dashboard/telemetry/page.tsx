'use client';

import { TelemetryTable } from '@/components/telemetry-table';

export default function TelemetryPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-foreground">Live Telemetry Stream</h1>
        <p className="text-xs text-muted-foreground mt-1">Raw eBPF syscall events captured across medical namespaces</p>
      </div>
      <TelemetryTable limit={50} />
    </div>
  );
}
