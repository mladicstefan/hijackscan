// "Check my domain": a name searched across every run. Shows where it was scanned and its score in each;
// a click opens the full details in that run.

import { lazy } from "react";

import { setLookup } from "../state/view";
import { Section, Skeleton } from "./common";

const DomainHistory = lazy(() => import("./DomainHistory"));

export function DomainLookup({ name }: { name: string }) {
  return (
    <section className="card lookup" aria-labelledby="lookup-title">
      <header className="card-head">
        <h2 id="lookup-title">
          Check my domain: <span className="mono">{name}</span>
        </h2>
        <button type="button" className="linkish" onClick={() => setLookup(null)}>
          close
        </button>
      </header>
      <Section key={name} label={`the runs of ${name}`} fallback={<Skeleton height={80} label="history" />}>
        <DomainHistory name={name} />
      </Section>
    </section>
  );
}
