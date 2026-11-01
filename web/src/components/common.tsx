// Small building blocks without data of their own: they render what they are given.

import { QueryErrorResetBoundary } from "@tanstack/react-query";
import { Component, Suspense, memo, type ReactNode } from "react";

import { ApiError } from "../api/client";
import type { Severity } from "../api/types";
import { fmtScore } from "../format";

export const SeverityBadge = memo(function SeverityBadge({
  severity,
  score,
}: {
  severity: Severity;
  score?: number | null;
}) {
  return (
    <span className={`badge sev-${severity.toLowerCase()}`}>
      {severity}
      {score !== undefined ? <b>{fmtScore(score)}</b> : null}
    </span>
  );
});

export function Skeleton({ height = 120, label }: { height?: number; label: string }) {
  return <div className="skeleton" style={{ height }} role="status" aria-label={`Loading ${label}`} />;
}

// ------------------------------------------------------------------ error boundary + suspense

interface BoundaryProps {
  label: string;
  onReset: () => void;
  children: ReactNode;
}

interface BoundaryState {
  error: Error | null;
}

/** Catches a failed request (or a failed lazy load) in one section, so the rest of the page keeps working. */
class ErrorBoundary extends Component<BoundaryProps, BoundaryState> {
  override state: BoundaryState = { error: null };

  static getDerivedStateFromError(error: unknown): BoundaryState {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }

  private readonly retry = () => {
    this.props.onReset();
    this.setState({ error: null });
  };

  override render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    const unreachable = !(error instanceof ApiError) || error.status >= 500;
    return (
      <div className="error" role="alert">
        <strong>Could not load {this.props.label}.</strong> {error.message}
        {unreachable ? <span className="muted"> Is `hijackscan serve` running, and MongoDB?</span> : null}{" "}
        <button type="button" onClick={this.retry}>
          Try again
        </button>
      </div>
    );
  }
}

/** One independently loading part of the page: its own loading placeholder and its own error message. */
export function Section({ label, fallback, children }: { label: string; fallback: ReactNode; children: ReactNode }) {
  return (
    <QueryErrorResetBoundary>
      {({ reset }) => (
        <ErrorBoundary label={label} onReset={reset}>
          <Suspense fallback={fallback}>{children}</Suspense>
        </ErrorBoundary>
      )}
    </QueryErrorResetBoundary>
  );
}
