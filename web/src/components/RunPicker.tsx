// Choose which run the page shows. Gets the runs from Workspace: no data of its own, so not lazy.

import { memo } from "react";

import type { RunSummary } from "../api/types";
import { fmtDate } from "../format";
import { setRun } from "../state/view";

export const RunPicker = memo(function RunPicker({ runs, selected }: { runs: RunSummary[]; selected: string }) {
  return (
    <label className="run-picker">
      <span>Run</span>
      <select value={selected} onChange={(e) => setRun(e.target.value)}>
        {runs.map((r) => (
          <option key={r.id} value={r.id}>
            {r.name} · .{r.scope.tld ?? "?"} · {r.scope.domains} domains · {fmtDate(r.loaded_at)}
          </option>
        ))}
      </select>
    </label>
  );
});
