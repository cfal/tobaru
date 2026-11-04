# Tobaru documentation

This Starlight project is the source for <https://tobaru-rs.github.io/>. Content
lives alongside Tobaru; the [publication repository](https://github.com/tobaru-rs/tobaru-rs.github.io)
selects an exact source commit, runs `npm ci` and `npm run check`, and deploys
`docs/dist/`. Development publication follows successful `docs.yml` push CI on
master, with a pinned-commit override in the publication repository.

## Local development

Use Node 24 (see `.node-version`):

```sh
cd docs
npm ci
npm run check
npm run dev
```

`npm run check` builds the site and checks internal links, anchors, header source
metadata, required assets, repository entry-point links, and every example's
copy-button payload against its YAML source. It does not fetch external URLs or
validate a running Tobaru process. Validate changed runnable configurations with
the matching binary's `tobaru --dry-run` and test their runtime behavior separately.

`npm run preview` serves `docs/dist/`, including the built search index. Both
servers bind to `0.0.0.0` for VM access; use a trusted network. Override with
`npm exec -- astro dev --host 127.0.0.1` for loopback-only development.

`TOBARU_DOCS_REF` is a full lowercase commit SHA; invalid explicit values fail the
build. Otherwise the local Git revision is used. Source links describe that
commit, not uncommitted edits. When Git metadata is unavailable, source links are
omitted. `TOBARU_DOCS_LABEL` defaults to **dev**, meaning unreleased. Do not infer
release status from `Cargo.toml`.

Only development docs are currently published at `/`. Version archives and a
selector require pinned release builds, base-aware links, isolated search indexes,
and one combined Pages artifact. Do not label current docs as an earlier release.

## Authoring

- Update the relevant `src/content/docs/` page in the same change as configuration,
  defaults, or runtime behavior. Verify against the parser and validator, not old prose.
- Keep `README.md` and the former root reference files as entry points, not parallel
  references. Shared settings belong in `config/`, TLS in `tls/`, HTTP in `http/`,
  and deployment guidance in `operations/`.
- Use ordinary Markdown except where imports or components require MDX. Mark
  schema sketches and partial fragments as illustrative, not runnable configurations.
- Keep complete configurations in `../examples/*.yml` or `*.yaml`; the catalog
  and copyable `/examples/filename/` pages are generated directly from those files.
  Import the same raw source for tutorials instead of copying YAML into Markdown.
- Document requiredness, accepted values, defaults, explicit `null`, units, and
  constraints. Use placeholder addresses and credentials, never real secrets.
- Keep dependency versions exact and commit `package-lock.json`. Generated schema
  machinery is unnecessary here; the Rust configuration pipeline is authoritative.
