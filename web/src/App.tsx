// The page frame: header with "check my domain", then the run workspace. Everything that needs data
// is lazy (its code downloads when first shown) and sits in its own Section.

import { lazy, useState, type FormEvent } from "react";

import { Section, Skeleton } from "./components/common";
import { DomainLookup } from "./components/DomainLookup";
import { setLookup, useView } from "./state/view";

const Workspace = lazy(() => import("./components/Workspace"));

export function App() {
  const view = useView();
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <h1>hijackscan</h1>
          <span className="muted small">certificate theft through BGP hijacks below DNS</span>
        </div>
        <LookupForm key={view.lookup ?? ""} initial={view.lookup} />
      </header>

      {view.lookup ? <DomainLookup name={view.lookup} /> : null}

      <Section label="the runs" fallback={<Skeleton height={400} label="runs" />}>
        <Workspace view={view} />
      </Section>

      <footer className="muted small">
        Scores 0–10 on the CVSS severity scale; model and references in <code>design/formula.md</code>. Data from
        each loaded scan run; nothing on this page is computed in the browser.
      </footer>
    </div>
  );
}

function LookupForm({ initial }: { initial: string | null }) {
  const [text, setText] = useState(initial ?? "");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const name = text.trim().toLowerCase().replace(/\.$/, "");
    setLookup(name || null);
  };
  return (
    <form className="lookup-form" onSubmit={submit} role="search" aria-label="Check my domain">
      <input value={text} onChange={(e) => setText(e.target.value)} placeholder="check my domain, e.g. rnids.rs" spellCheck={false} />
      <button type="submit">Check</button>
    </form>
  );
}
