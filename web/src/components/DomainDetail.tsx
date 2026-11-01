// One domain, everything: what an attacker can do, what to fix first, how the score was calculated,
// the evidence, and the same domain in other runs. Opens as a side panel over the page.
// Escape, the close button or a click on the backdrop closes it (no global listener, so no effect).

import { useSuspenseQuery } from "@tanstack/react-query";
import { Suspense, lazy, type KeyboardEvent } from "react";

import { domainQuery } from "../api/queries";
import type { DomainDetail as Detail, Fix, PathScore } from "../api/types";
import { fmtOwner, fmtScore } from "../format";
import { openDomain } from "../state/view";
import { SeverityBadge, Skeleton } from "./common";

const DomainHistory = lazy(() => import("./DomainHistory"));

const close = () => openDomain(null);
const onKey = (e: KeyboardEvent) => {
  if (e.key === "Escape") close();
};

export default function DomainDetail({ runId, name }: { runId: string; name: string }) {
  const { data: d } = useSuspenseQuery(domainQuery(runId, name));

  return (
    <div className="drawer-backdrop" onClick={close}>
      <aside
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-label={`Details of ${name}`}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={onKey}
      >
        <button type="button" className="drawer-close" onClick={close} autoFocus aria-label="Close details">
          ×
        </button>
        {d ? <Body d={d} /> : <p className="empty">{name} is not in this run.</p>}
        <h3>In every run</h3>
        <Suspense fallback={<Skeleton height={80} label="history" />}>
          <DomainHistory name={name} currentRun={runId} />
        </Suspense>
      </aside>
    </div>
  );
}

function Body({ d }: { d: Detail }) {
  const x = d.details;
  const f = d.facts;
  return (
    <>
      <h2 className="drawer-title">{d.domain}</h2>
      <p>
        <SeverityBadge severity={d.severity} score={d.score} /> <code>{d.label}</code>
      </p>
      <p className="headline">{d.headline}</p>

      {d.fix || d.full_fix ? (
        <table className="fixes-brief">
          <tbody>
            {d.fix ? <FixLine title="Fix first" f={d.fix} /> : null}
            {d.full_fix ? <FixLine title="To close" f={d.full_fix} /> : null}
          </tbody>
        </table>
      ) : null}

      <h3>Defences</h3>
      <dl className="facts">
        <dt>DNSSEC</dt>
        <dd className={f.dnssec === "secure" ? "good" : "bad"}>{f.dnssec}</dd>
        <dt>CAA</dt>
        <dd className={f.has_caa ? "good" : "bad"}>
          {f.has_caa ? `at ${f.caa_from ?? "?"}: ${f.caa_issue.join(", ") || "no CA allowed"}` : "none: every CA may issue"}
        </dd>
        <dt>accounturi</dt>
        <dd className={f.pinned ? "good" : "bad"}>{f.pinned ? "every allowed CA is pinned to one account" : "not pinned"}</dd>
        <dt>Web route</dt>
        <dd className={f.web_forgeable ? "bad" : "good"}>{f.web_forgeable ? "forgeable" : "not forgeable"}</dd>
        <dt>Nameservers</dt>
        <dd className={f.ns_forgeable_hosts ? "bad" : "good"}>
          {f.ns_forgeable_hosts} of {f.ns_hosts} capturable
        </dd>
        <dt>Hosting</dt>
        <dd>{f.hosting_asns.map((h) => `AS${h.asn} ${h.name ?? ""}`).join(", ") || "–"}</dd>
        <dt>DNS operators</dt>
        <dd>{f.ns_operators.join(", ") || "–"}</dd>
      </dl>

      {x.calculation ? <Calculation c={x.calculation} params={x.params} score={d.score} /> : null}
      {!x.data_quality.complete ? (
        <p className="error">
          Incomplete record, not scored: {x.data_quality.errors.join("; ")}
        </p>
      ) : null}

      {x.paths.length ? (
        <>
          <h3>Every attack path</h3>
          <table className="paths">
            <thead>
              <tr>
                <th>Path</th>
                <th>Target</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {x.paths.map((p) => (
                <PathLine key={`${p.path}/${p.target}`} p={p} />
              ))}
            </tbody>
          </table>
        </>
      ) : null}

      <h3>Findings</h3>
      <ul className="findings">
        {x.findings.map((fi) => (
          <li key={fi.id}>
            <code>{fi.id}</code> {fi.severity ? <SeverityBadge severity={fi.severity} /> : null} {fi.detail}
            {fi.evidence.length ? (
              <ul className="evidence">
                {fi.evidence.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            ) : null}
          </li>
        ))}
      </ul>

      {x.fixes.length ? (
        <>
          <h3>What each fix does</h3>
          <table className="fixes">
            <thead>
              <tr>
                <th>Score after</th>
                <th>Who</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {x.fixes.map((fx: Fix) => (
                <tr key={fx.action}>
                  <td>
                    <SeverityBadge severity={fx.severity_after} score={fx.score_after} />
                  </td>
                  <td className="small">{fmtOwner(fx.owner)}</td>
                  <td>{fx.action}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : null}

      {x.vectors.cvss31 || x.attack_techniques.length || x.references.length ? (
        <details>
          <summary>Vectors, techniques and references</summary>
          {x.vectors.cvss31 ? (
            <p className="small">
              <code>{x.vectors.cvss31}</code> (base {fmtScore(x.vectors.cvss31_base)})
              <br />
              <code>{x.vectors.cvss40}</code>
            </p>
          ) : null}
          <ul className="small">
            {x.attack_techniques.map((t) => (
              <li key={t.id}>
                <code>{t.id}</code> {t.name}
              </li>
            ))}
          </ul>
          <ol className="small refs">
            {x.references.map((r) => (
              <li key={r.n} value={r.n}>
                <a href={r.url} target="_blank" rel="noreferrer">
                  {r.title}
                </a>
              </li>
            ))}
          </ol>
        </details>
      ) : null}
    </>
  );
}

function FixLine({ title, f }: { title: string; f: { action: string; owner: string; score_after: number | null; severity_after: Fix["severity_after"] } }) {
  return (
    <tr>
      <th>{title}</th>
      <td>
        <span className="owner">{fmtOwner(f.owner)}</span> {f.action}
      </td>
      <td>
        <SeverityBadge severity={f.severity_after} score={f.score_after} />
      </td>
    </tr>
  );
}

function Calculation({ c, params, score }: { c: PathScore; params: Record<string, number>; score: number | null }) {
  const r = params.remote_perspectives;
  const fails = params.allowed_non_corroborations;
  return (
    <>
      <h3>How the score was calculated</h3>
      <div className="calc">
        <div>
          driving path <b>{c.path}</b> → {c.target}
        </div>
        <div>
          p = {c.p.toFixed(2)} <span className="muted">({c.p_note})</span>
        </div>
        <div>
          P per attempt = {c.p_attempt.toFixed(3)}{" "}
          <span className="muted">
            (primary and at least {r !== undefined && fails !== undefined ? r - fails : "?"} of {r ?? "?"} CA perspectives fooled)
          </span>
        </div>
        <div>
          likelihood L = {c.likelihood.toFixed(3)} <span className="muted">(at least one success in {params.attempts ?? "?"} attempts)</span>
        </div>
        <div>
          complexity K = {c.complexity.toFixed(3)} {c.h_reasons.length ? <span className="muted">({c.h_reasons.join("; ")})</span> : null}
        </div>
        <div>
          score = 10 × K × L = <b>{fmtScore(score)}</b>
        </div>
      </div>
    </>
  );
}

function PathLine({ p }: { p: PathScore }) {
  return (
    <tr>
      <td>
        <code>{p.path}</code>
      </td>
      <td className="small">
        {p.target}
        <div className="muted">{p.p_note}</div>
      </td>
      <td>
        {p.open ? <SeverityBadge severity={p.severity} score={p.score} /> : <span className="good small">blocked: {p.blocked_by.join("; ")}</span>}
      </td>
    </tr>
  );
}
