// Everything about one run. Loads the list of runs, picks the selected one (or the newest), and lays
// out the sections. Each data-dependent section is its own lazy chunk inside its own Section, so it
// downloads, loads its data and fails independently of the others.

import { useSuspenseQuery } from "@tanstack/react-query";
import { lazy } from "react";

import { runsQuery } from "../api/queries";
import type { View } from "../state/view";
import { RunPicker } from "./RunPicker";
import { Section, Skeleton } from "./common";

const Overview = lazy(() => import("./Overview"));
const Filters = lazy(() => import("./Filters"));
const DomainTable = lazy(() => import("./DomainTable"));
const Providers = lazy(() => import("./Providers"));
const DomainDetail = lazy(() => import("./DomainDetail"));

export default function Workspace({ view }: { view: View }) {
  const { data: runs } = useSuspenseQuery(runsQuery());
  const run = runs.find((r) => r.id === view.run) ?? runs[0];

  if (!run) {
    return (
      <div className="empty">
        <h2>No runs yet</h2>
        <p>
          Load scan results first: <code>uv run hijackscan load data/samples/dev100.txt</code>
        </p>
      </div>
    );
  }

  return (
    <>
      <RunPicker runs={runs} selected={run.id} />

      <Section label="the overview" fallback={<Skeleton height={260} label="overview" />}>
        <Overview runId={run.id} />
      </Section>

      <div className="workspace">
        <aside className="filters-col">
          <Section label="the filters" fallback={<Skeleton height={480} label="filters" />}>
            <Filters runId={run.id} filters={view.filters} />
          </Section>
        </aside>
        <section className="table-col" aria-label="Domains">
          <Section label="the domains" fallback={<Skeleton height={480} label="domains" />}>
            <DomainTable runId={run.id} filters={view.filters} sort={view.sort} page={view.page} />
          </Section>
        </section>
      </div>

      <Section label="the providers" fallback={<Skeleton height={240} label="providers" />}>
        <Providers runId={run.id} />
      </Section>

      {view.domain ? (
        // keyed: a different domain gets a fresh boundary, so one failed detail does not stick
        <Section key={`${run.id}/${view.domain}`} label={view.domain} fallback={null}>
          <DomainDetail runId={run.id} name={view.domain} />
        </Section>
      ) : null}
    </>
  );
}
