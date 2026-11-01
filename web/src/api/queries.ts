// Every piece of server data the page uses, as a React Query definition: a cache key, how to fetch it,
// and how long it stays fresh. Components call useSuspenseQuery(xxxQuery(...)) and never fetch by hand.
//
// A run is a snapshot: once loaded, its report and its domains never change. Everything scoped to a run
// is therefore cached for good (staleTime: Infinity) and never fetched twice. Only the list of runs and a
// domain's history can grow (a new `hijackscan load`), so they are refreshed after a short while.

import { QueryClient, queryOptions } from "@tanstack/react-query";

import { ApiError, api } from "./client";
import type { DomainQuery, FilterSet } from "./types";

const GROWS = 30_000; // ms: the list of runs and a domain's history may gain a new run

export const keys = {
  runs: ["runs"] as const,
  run: (id: string) => ["run", id] as const,
  domains: (id: string, q: DomainQuery) => ["run", id, "domains", q] as const,
  facets: (id: string, f: FilterSet) => ["run", id, "facets", f] as const,
  domain: (id: string, name: string) => ["run", id, "domain", name] as const,
  history: (name: string) => ["history", name] as const,
};

export const runsQuery = () =>
  queryOptions({ queryKey: keys.runs, queryFn: ({ signal }) => api.runs(signal), staleTime: GROWS });

export const runQuery = (id: string) =>
  queryOptions({ queryKey: keys.run(id), queryFn: ({ signal }) => api.run(id, signal), staleTime: Infinity });

export const domainsQuery = (id: string, q: DomainQuery) =>
  queryOptions({
    queryKey: keys.domains(id, q),
    queryFn: ({ signal }) => api.domains(id, q, signal),
    staleTime: Infinity,
  });

export const facetsQuery = (id: string, f: FilterSet) =>
  queryOptions({
    queryKey: keys.facets(id, f),
    queryFn: ({ signal }) => api.facets(id, f, signal),
    staleTime: Infinity,
  });

export const domainQuery = (id: string, name: string) =>
  queryOptions({
    queryKey: keys.domain(id, name),
    queryFn: ({ signal }) => api.domain(id, name, signal),
    staleTime: Infinity,
  });

export const historyQuery = (name: string) =>
  queryOptions({ queryKey: keys.history(name), queryFn: ({ signal }) => api.history(name, signal), staleTime: GROWS });

export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // A 4xx answer will not change on retry; a network blip or a 5xx might.
        retry: (failures, error) => !(error instanceof ApiError && error.status < 500) && failures < 2,
        refetchOnWindowFocus: false,
        gcTime: 10 * 60_000, // keep unused results 10 minutes, so going back to a filter is instant
      },
    },
  });
}
