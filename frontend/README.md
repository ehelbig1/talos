# Talos Frontend (React + TypeScript)

This is the **IDE‑style** UI for the Talos automation platform. It follows the architecture
described in the design document:

* **React + TypeScript** – type‑safe UI, matches the Rust backend.
* **Vite** – fast dev server with HMR.
* **Tailwind CSS** – utility‑first styling; shadcn/ui components are built on top of it.
* **React Flow** – displays the workflow DAG with drag‑and‑drop support.
* **Zustand** – a tiny, slice‑based state manager that holds the visual graph (nodes/edges) and synchronises it with the backend.
* **TanStack Query (v5)** – typed GraphQL hooks generated from the backend schema via
  `graphql-codegen`. The UI subscribes to execution updates over a GraphQL subscription.

## Project structure

```
frontend/
├─ src/
│  ├─ components/            # UI components (Workspace, TalosNode, Toolbox…)
│  │  ├─ ui/                 # shadcn/ui primitive wrappers (Button, Badge, …)
│  │  └─ …
│  ├─ generated/             # Auto‑generated GraphQL hooks (run codegen to fill)
│  ├─ store/                 # Zustand store (`workflowStore`)
│  ├─ lib/                   # Utility helpers (className merger)
│  ├─ App.tsx                # Root React component
│  └─ main.tsx               # ReactDOM bootstrap
├─ index.html                # Entry point for Vite
├─ vite.config.ts            # Vite config with @ alias and dev proxy
├─ tailwind.config.ts       # Tailwind configuration
├─ postcss.config.js        # PostCSS plugins for Tailwind
├─ codegen.yml               # GraphQL Codegen configuration
└─ package.json              # npm scripts & dependencies
```

## Development workflow

1. **Start the back‑end** – make sure the Talos controller is running on
   `http://localhost:8000` (the GraphQL endpoint).
2. **Install dependencies**:
   ```bash
   cd frontend
   npm install   # or `pnpm i` / `yarn`
   ```
3. **Generate GraphQL Types & Hooks**:
   ```bash
   npm run codegen
   ```
   This reads the schema from the running controller and produces
   `src/generated/graphql.ts` containing strongly‑typed query and subscription hooks.
4. **Run the dev server**:
   ```bash
   npm run dev
   ```
   Vite will proxy `/graphql` requests to the back‑end, so the UI can talk to the
   controller without CORS headaches.

## Build for production

```bash
npm run build
```
The output will be placed in `dist/` and can be served by any static‑file server
or embedded into the Talos binary via `include_bytes!` if you wish.

## Security notes

* **CSP** – since we never eval arbitrary code in the browser, a strict
  Content‑Security‑Policy (`script-src 'self'`) can be applied.
* **Auth** – the back‑end should set an HttpOnly session cookie on login; the UI
  does **not** store JWTs in `localStorage`.
* **Input sanitisation** – the inspector allows raw JSON editing. Validation is
  performed server‑side before a node is executed.

---

Happy hacking! 🎨🚀

