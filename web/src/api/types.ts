// The shapes the API returns (src/hijackscan/api.py, store.py). Field names match the JSON exactly.

export const SEVERITIES = ["Critical", "High", "Medium", "Low", "None", "Unknown"] as const;
export type Severity = (typeof SEVERITIES)[number];
export type SeverityCounts = Record<Severity, number>;

/** Severity counts plus score statistics, shared by runs, providers and what-if rows. */
export interface Stats {
  severity: SeverityCounts;
  scored: number;
  mean_score: number | null;
  median_score: number | null;
  high_or_critical: number;
}

// ------------------------------------------------------------------ runs

export interface Population {
  apex: string | null;
  soa_serial: string | null;
  seed: number | null;
  delegations: number;
  ds: number;
  ds_share: number | null;
  sample_ds: number | null;
  sample_ds_share: number | null;
  ns_operators: { operator: string; delegations: number; ds: number }[];
}

export interface RunScope {
  domains: number;
  tld: string | null;
  resolver: string | null;
  routing_source: string | null;
  rpki_source: string | null;
  rpki_date: string | null;
  population: Population | null;
}

/** One row of GET /api/runs. */
export interface RunSummary {
  id: string;
  name: string;
  source: string;
  loaded_at: string;
  git_commit: string | null;
  scope: RunScope;
  summary: Stats;
  missing: string[];
}

export interface ModelParams {
  remote_perspectives: number;
  allowed_non_corroborations: number;
  attempts: number;
  contest_share: number;
  impact: number;
  complexity_step: number;
}

export interface OperatorRow extends Stats {
  operator: string;
  domains: number;
  signed: number;
  zone_delegations: number | null;
  zone_ds: number | null;
}

export interface HostingRow extends Stats {
  asn: string;
  name: string | null;
  domains: number;
  web_forgeable: number;
}

export interface WhatIf extends Stats {
  scenario: string;
  overrides: Record<string, unknown>;
  reads_as: string;
}

/** GET /api/runs/{id}: the aggregate report of one run. No domain names. */
export interface RunReport extends RunSummary {
  schema_version: number;
  generated_at: string;
  model: { formula: string; score: string; scale: Record<Severity, string>; params: ModelParams | null };
  severity: Record<Severity, { band: string; domains: number; share: number | null }>;
  labels: Record<string, { domains: number; meaning: string }>;
  findings: Record<string, number>;
  defences: {
    dnssec_secure: number;
    dnssec_bogus: number;
    dnssec_unsigned: number;
    caa: number;
    caa_accounturi: number;
  };
  fixes: { first_fix: Record<string, number>; to_close: Record<string, number> };
  by_ns_operator: OperatorRow[];
  by_hosting_as: HostingRow[];
  what_if: WhatIf[];
}

// ------------------------------------------------------------------ domains

export interface FixBrief {
  action: string;
  owner: string;
  score_after: number | null;
  severity_after: Severity;
}

export interface DomainFacts {
  dnssec: "unsigned" | "secure" | "bogus";
  has_caa: boolean;
  pinned: boolean;
  caa_from: string | null;
  caa_issue: string[];
  web_forgeable: boolean;
  ns_forgeable: boolean;
  ns_forgeable_hosts: number;
  ns_hosts: number;
  hosting_asns: { asn: string; name: string | null }[];
  ns_operators: string[];
}

/** One row of the domains table: the summary, without details. */
export interface DomainRow {
  schema_version: number;
  domain: string;
  score: number | null;
  severity: Severity;
  label: string;
  headline: string;
  fix: FixBrief | null;
  full_fix: FixBrief | null;
  tld: string;
  fetched_at: string | null;
  finding_ids: string[];
  facts: DomainFacts;
}

export interface PathScore {
  path: "web" | "ns" | "contest";
  target: string;
  open: boolean;
  blocked_by: string[];
  p: number;
  p_note: string;
  h: number;
  h_reasons: string[];
  p_attempt: number;
  likelihood: number;
  complexity: number;
  score: number;
  severity: Severity;
  evidence: string[];
}

export interface Finding {
  id: string;
  kind: "exposure" | "missing-defence" | "hygiene" | "data";
  severity: Severity | null;
  detail: string;
  evidence: string[];
  refs: number[];
}

export interface Fix extends FixBrief {
  refs: number[];
}

export interface DomainDetails {
  calculation: PathScore | null;
  paths: PathScore[];
  findings: Finding[];
  fixes: Fix[];
  vectors: { cvss31: string | null; cvss31_base: number | null; cvss40: string | null };
  attack_techniques: { id: string; name: string }[];
  params: Record<string, number>;
  data_quality: { complete: boolean; errors: string[] };
  references: { n: number; title: string; url: string }[];
}

/** GET /api/runs/{id}/domains/{domain}: one domain with every detail. */
export interface DomainDetail extends DomainRow {
  run_id: string;
  details: DomainDetails;
}

/** One row of GET /api/domains/{domain}: the domain in one run. */
export interface HistoryRow extends DomainRow {
  run_id: string;
  run_name: string | null;
  loaded_at: string;
}

export interface Page<T> {
  total: number;
  page: number;
  per_page: number;
  items: T[];
}

export interface FacetValue {
  value: string;
  domains: number;
  name?: string | null;
}

export interface Facets {
  severity: FacetValue[];
  label: FacetValue[];
  finding: FacetValue[];
  asn: FacetValue[];
  operator: FacetValue[];
}

// ------------------------------------------------------------------ what the page asks for

/** The filters of the domains table. Arrays are empty when the filter is off. */
export interface FilterSet {
  severity: readonly Severity[];
  label: readonly string[];
  finding: readonly string[];
  asn: string | null;
  operator: string | null;
  q: string | null;
  minScore: number | null;
}

export type SortKey = "score" | "domain";

export interface DomainQuery extends FilterSet {
  sort: SortKey;
  page: number;
  perPage: number;
}
