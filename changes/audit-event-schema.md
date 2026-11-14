---
section: Behaviour changes
---

- Audit events carry `schemaVersion: "v1"` and conform to the published JSON
  Schema `api/audit/v1/audit-event.schema.json` (docs/audit-event-schema.md).
  Batched Kafka writes now carry the same `actor` and `correlation-id` headers
  as single writes, and every record has a `schema-version` header (TCAAS-1625).
