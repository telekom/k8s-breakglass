# Template rendering security

Debug templates are administrator-authored code running with controller credentials.
Admission parses templates and checks output actions without executing them.
Runtime and admission remove `env` and `expandenv`. Sprig still includes expensive
and DNS-capable functions: template authors must be trusted, and controller resource
limits remain necessary. The 1 MiB writer limit bounds serialized output only,
not intermediate allocations, CPU, DNS, or other effects during evaluation.

Requester values are preserved byte-for-byte before rendering. Emit a complete
string scalar with `value: {{ .vars.value | yamlQuote }}`. Do not surround that
action with literal quotes or concatenate it with scalar fragments. `yamlQuote`
and `yamlSafe` always emit quoted strings; `yamlSafe` additionally performs its
explicit legacy character replacement. Numeric strings and YAML boolean words
remain strings. Use explicit numeric conversion or boolean comparisons for typed
manifest fields, for example `enabled: {{ eq .vars.choice "yes" }}`.

The shared parse-tree check rejects raw dynamic output, including variables,
rebound dot in range/with, named template bodies, annotation values, and pipelines
that transform serialized output. Put transformations before the final serializer:
`{{ .vars.payload | b64dec | yamlQuote }}`. Unknown aliases conservatively require
serialization even when their original source was trusted. Direct Kubernetes
identifier fields, literal output, and known numeric/boolean functions are allowed.
`toYaml` is not a scalar serializer for unknown data; use `yamlQuote` for strings.
A conservative scalar-context pass also rejects serializers inside literal quotes
or scalar fragments, including contexts introduced by branches, aliases, or named
template calls. Loops must preserve their scalar context across iterations.
Recursive calls, break/continue, and excessively ambiguous contexts are rejected.
This is not a complete YAML validator or a hostile-template sandbox: administrator
literal text, allowed function evaluation, and the resource structure remain trusted.
Template output validation failures retain the `template output validation failed` context and the underlying diagnostic.

This changes compatibility for templates using raw interpolation, `env`,
`expandenv`, or string fragments around quoting helpers. Update templates before
upgrade. Existing stored templates are checked again at runtime. Admission does
not promise that a template will execute or produce a valid workload.

Auxiliary resource defaults are keyed by category. Required categories take
precedence over defaults and binding disables. API responses omit a select or
multiSelect default if any selected value is inaccessible to the requester.

For list-valued variables represented as JSON text, decode and range over the
list, then serialize each item (`{{ range .vars.args | fromJson }}` followed by
`- {{ . | yamlQuote }}`). Serialize quantity suffixes together with their value,
for example `{{ printf "%sGi" .vars.size | yamlQuote }}`. Auxiliary renderer
callers retain the empty/nil byte-template no-op behavior; the general renderer
still rejects an empty template string.
