import React from 'react';

export interface CardProps {
  className?: string;
  children: React.ReactNode;
}

export interface CardHeaderProps {
  className?: string;
  children: React.ReactNode;
}

export interface CardTitleProps {
  className?: string;
  children: React.ReactNode;
}

export interface CardDescriptionProps {
  className?: string;
  children: React.ReactNode;
}

export interface CardContentProps {
  className?: string;
  children: React.ReactNode;
}

export interface CardFooterProps {
  className?: string;
  children: React.ReactNode;
}

export function Card({ className, children }: CardProps) {
  return (
    <div className={`rounded-xl border border-border/60 bg-card shadow-sm ${className || ''}`}>
      {children}
    </div>
  );
}

export function CardHeader({ className, children }: CardHeaderProps) {
  return (
    <div className={`flex flex-col space-y-1.5 p-5 border-b border-border/40 ${className || ''}`}>
      {children}
    </div>
  );
}

export function CardTitle({ className, children }: CardTitleProps) {
  return (
    <h3 className={`text-sm font-semibold leading-tight text-foreground ${className || ''}`}>
      {children}
    </h3>
  );
}

export function CardDescription({ className, children }: CardDescriptionProps) {
  return (
    <p className={`text-sm text-muted-foreground ${className || ''}`}>{children}</p>
  );
}

export function CardContent({ className, children }: CardContentProps) {
  return <div className={`p-5 ${className || ''}`}>{children}</div>;
}

export function CardFooter({ className, children }: CardFooterProps) {
  return (
    <div className={`flex items-center justify-between p-5 border-t border-border/40 ${className || ''}`}>
      {children}
    </div>
  );
}
