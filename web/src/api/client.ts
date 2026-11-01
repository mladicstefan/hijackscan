// Typed calls to the hijackscan API. Every function takes an AbortSignal so React Query can cancel
// requests whose answer is no longer needed (for example after the filters changed again).

import type {
  DomainDetail,
  DomainQuery,
  DomainRow,
  Facets,
  FilterSet,
  HistoryRow,
  Page,
  RunReport,
  RunSummary,
} from "./types";

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

type Params = Record<string, string | number | null | undefined>;

async function getJson<T>(path: string, params: Params, signal: AbortSignal): Promise<T> {
  const url = new URL(path, window.location.origin);
  for (const [key, value] of Object.entries(params)) {
    if (value !== null && value !== undefined && value !== "") url.searchParams.set(key, String(value));
  }
  const res = await fetch(url, { signal, headers: { Accept: "application/json" } });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = (await res.json()) as { detail?: unknown };
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      // the error body is not JSON: keep the status text
    }
    throw new ApiError(res.status, detail);
  }
  return (await res.json()) as T;
}

/** The filter part of a request, in the API's parameter names (comma lists for multi-value filters). */
function filterParams(f: FilterSet): Params {
  return {
    severity: f.severity.join(","),
    label: f.label.join(","),
    finding: f.finding.join(","),
    asn: f.asn,
    operator: f.operator,
    q: f.q,
    min_score: f.minScore,
  };
}

const run = (id: string) => `/api/runs/${encodeURIComponent(id)}`;

export const api = {
  runs: (signal: AbortSignal) => getJson<RunSummary[]>("/api/runs", {}, signal),

  run: (id: string, signal: AbortSignal) => getJson<RunReport>(run(id), {}, signal),

  domains: (id: string, q: DomainQuery, signal: AbortSignal) =>
    getJson<Page<DomainRow>>(
      `${run(id)}/domains`,
      { ...filterParams(q), sort: q.sort, page: q.page, per_page: q.perPage },
      signal,
    ),

  facets: (id: string, f: FilterSet, signal: AbortSignal) => getJson<Facets>(`${run(id)}/facets`, filterParams(f), signal),

  /** One domain in one run; null when the run does not contain it (a stale link). */
  domain: async (id: string, name: string, signal: AbortSignal): Promise<DomainDetail | null> => {
    try {
      return await getJson<DomainDetail>(`${run(id)}/domains/${encodeURIComponent(name)}`, {}, signal);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null;
      throw e;
    }
  },

  /** One domain in every run, newest first; empty when it was never scanned. */
  history: async (name: string, signal: AbortSignal): Promise<HistoryRow[]> => {
    try {
      return await getJson<HistoryRow[]>(`/api/domains/${encodeURIComponent(name)}`, {}, signal);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return [];
      throw e;
    }
  },
};
