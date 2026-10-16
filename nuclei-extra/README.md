# Our own nuclei templates

Templates in this directory ship in the daily bundle under
`nuclei-templates/custom/`, next to the pinned public set, and run in the web
add-on of every `full` scan exactly like those. They are reviewed through pull
requests, signed into the bundle by the daily workflow and named by their `id`
in findings and in a site's exclusions (`nuclei:<id>`).

The build (`cp-api bundle build --nuclei-extra nuclei-extra`) applies the rules
of the pinned set, but where it would silently drop one of upstream's templates
it stops on one of ours and says why. A template here must:

- have an `id` and speak HTTP to the target only: an `http` section, no `tcp`,
  `dns`, `javascript`, `code`, `headless` or other protocol section, no
  `self-contained: true`, no fuzzer;
- carry none of the excluded tags (`dos`, `fuzz`, `intrusive`); the appliance
  also refuses those at run time;
- have an `id` that no other template here and none of the pinned set has
  (prefix ours, for example `acme-cve-2026-0001`);
- name helper files (payload lists) that sit below this directory, as regular
  files, at a path the pinned set does not use: nuclei looks below the root of
  the template tree first;
- load with the nuclei version the appliance image carries (the pin in
  `ci/build-engine.sh`), which `-validate` checks.

A job runs templates at or above its minimum severity, `medium` unless the
job's `web.min_severity` says otherwise, and never those tagged
`default-login` unless it carries that module. A template rated `info` or
`low` therefore runs only in a job that lowers the bar.

Layout is free below this directory; `README.md` and anything that is not
`*.yaml` or `*.yml` is ignored. A helper named `helpers/x.txt` from a template
in `acme/` is found at `nuclei-extra/helpers/x.txt` on the build host and at
`nuclei-templates/custom/helpers/x.txt` on the appliance.

Checks: CI builds a bundle from this directory alone with the image's nuclei on
every push, which catches everything except an id or helper path that collides
with the pinned set. For that, dispatch the bundle workflow on the branch with
`dry_run=true`: it builds the whole bundle and publishes nothing. Locally:

```sh
ci/build-engine.sh --only nuclei --out engine-bin
make dev-bundle TEMPLATES=path/to/nuclei-templates EXTRA=nuclei-extra NUCLEI=engine-bin/nuclei
```
