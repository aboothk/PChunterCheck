This MVP does not ship separate JSON Schema files. `pchunter_platform.models`
(Pydantic v2 models) is the single source of truth for `CaseVersion`,
`Event`, `RunManifest`, `AttemptResult`, `Finding`, and `GateVerdict`.

The full platform design describes a dedicated
`schemas/` contract layer as a later-stage goal once multiple independent
adapters/consumers need a language-neutral contract (e.g. exporting JSON
Schema via `Model.model_json_schema()`). For S0-S3 of this MVP, keeping
the schema co-located with the validating code avoids drift between "the
schema" and "what the code actually checks."
