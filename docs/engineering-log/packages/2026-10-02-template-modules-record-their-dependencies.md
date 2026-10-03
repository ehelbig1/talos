# A module built from a template records the crates it was compiled with (2026-10-02)

**Seen.** Recompiling the installed copy of `google-health-daily` with
`hot_update_module` failed with `unresolved import chrono`. The install had
compiled it WITH the template's declared `dependencies` and stored none, so
the hot-update cascade (explicit → the row's own `dependencies`) found nothing
and the caller had to restate the map.

**Population.** Three paths compile a module from a template and store it:
`install_module_from_catalog` (`install_catalog_module_to_modules`),
`compile_template` and GraphQL `createModuleFromTemplate`. All three compiled
with the template's crates (check 68 leg (d) keeps the compile side honest)
and stored `dependencies` as NULL. Four catalog templates declare crates
(`briefing-html-generator`, `create-calendar-event`,
`google-calendar-list-events`, `google-health-daily`). On the reference
deployment no installed module currently uses a crate without having it
stored: the one affected copy was repaired by hand during the live check.

**Fix.** The catalog install takes the template's `dependencies` and writes
them; a reinstall REPLACES them (`dependencies = EXCLUDED.dependencies`),
because a reinstall replaces the source they belong to. `compile_template` and
`createModuleFromTemplate` store `template.dependencies`.

**Not changed, and why.** `restore_pinned_modules` and the replay service
build in-memory module values from a template's precompiled bytes to execute
them; nothing is stored, so `dependencies: None` there is not a defect.

**Tests.** `catalog_install_audit_tests::an_install_records_the_crates_it_was_compiled_with`
(installs, a reinstall with a different map, a reinstall with none) reads the
value back through `get_wasm_module_dependencies`, the read the hot-update
cascade uses; storing NULL fails it. A textual pin in
`inherited_grants_pins` holds the two template-compile sites and the install
call to the template's value.

**Stated limit.** The pin is textual. No test drives `hot_update_module`
end to end on an installed catalog copy (that needs the compile toolchain).
