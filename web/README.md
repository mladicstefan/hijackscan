# hijackscan web page

React + TypeScript page over the hijackscan API: runs, overview, filterable domains, providers, domain details,
"check my domain". It only reads; data gets in with `hijackscan load`.

## Run it

Needs Node.js 20.19 or newer, MongoDB (`docker compose up -d` in the project root) and at least one loaded run.

```bash
cd web
npm install                       # once, and after package.json changes

# while developing: live reload on http://127.0.0.1:5173 (the API must run too)
uv run hijackscan serve           # in another terminal, from the project root
npm run dev

# for the demo: one server for page and API on http://127.0.0.1:8000
npm run build                     # writes web/dist/; restart `hijackscan serve` after the first build
```

`npm run check` runs the type checker and ESLint; both must pass with no warnings.

## How it is built

| Rule | How |
|---|---|
| Data is never fetched by hand | Every request is a React Query definition in `src/api/queries.ts`, read with `useSuspenseQuery` |
| Every data-dependent component is lazy | `React.lazy` + its own `Section` (error boundary + `Suspense`): it downloads, loads and fails on its own |
| No effect without a dependency array | Enforced by ESLint (`no-restricted-syntax` in `eslint.config.js`); the page has no `useEffect` at all |
| State lives in the URL | `src/state/view.ts`, read with `useSyncExternalStore`: every view can be bookmarked or shared |
| Runs never change | Run-scoped data is cached for good (`staleTime: Infinity`) and never fetched twice |
| No placeholder flash on filter changes | `useDeferredValue`: the old rows stay (dimmed) until the new page is there |
| Rows re-render only when their data changes | memoised rows get the cached objects, which keep their identity |

| File | What |
|---|---|
| `src/api/types.ts` | The JSON the API returns, as TypeScript types |
| `src/api/client.ts` | Typed `fetch` calls, cancellable |
| `src/api/queries.ts` | Cache keys, freshness, retries |
| `src/state/view.ts` | Run, filters, page, open domain: read from and written to the URL hash |
| `src/components/Workspace.tsx` | Picks the run, lays out the lazy sections |
| `src/components/Overview.tsx`, `Providers.tsx`, `Filters.tsx`, `DomainTable.tsx`, `DomainDetail.tsx`, `DomainHistory.tsx` | One section each |
