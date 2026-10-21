import React from 'react';

export interface PageShellProps {
  title: string;
  subtitle?: string;
  icon?: React.ReactNode;
  action?: React.ReactNode;
  children: React.ReactNode;
}

export function PageShell({
  title,
  subtitle,
  icon,
  action,
  children,
}: PageShellProps) {
  return (
    <div className="space-y-5">
      <div className="flex items-start gap-4">
        <div className="flex-1 min-w-0">
          {icon && (
            <div className="mb-1.5 text-primary">
              {icon}
            </div>
          )}
          <h1 className="text-xl font-bold tracking-tight text-foreground">{title}</h1>
          {subtitle && (
            <p className="text-sm text-muted-foreground mt-0.5">{subtitle}</p>
          )}
        </div>
        {action && <div className="shrink-0">{action}</div>}
      </div>
      <div className="border border-border/60 rounded-xl bg-card/40 p-4">
        {children}
      </div>
    </div>
  );
}
