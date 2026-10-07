# LogAsis Architecture

## Investigation pipeline

```text
Uploaded log
    |
    v
Parser / normalized event records
    |
    v
Persistent LogDataset (EventIndex + QueryEngine + AggregationEngine)
    |
    +--> Dashboard / Events / Timeline / IP / Authentication
    |
    v
Evidence identity + read-only investigation tools
    |
    +--> search events (indexed)
    +--> entity context (indexed)
    +--> timeline (indexed)
    +--> correlation (indexed)
    +--> overview (cached)
    |
    v
Live AI provider
    |
    v
Claim-level grounding and citation validation
    |
    v
Human-readable analyst report
```

## Index lifecycle

```
UPLOAD -> PARSE ONCE -> NORMALIZE ONCE -> BUILD INDEX ONCE -> READY
                                                                    |
                                                                    +--> FILTER
                                                                    +--> SEARCH
                                                                    +--> AGGREGATION
                                                                    +--> AI QUERY
                                                                    +--> TIMELINE
                                                                    +--> CORRELATION
                                                                    +--> DASHBOARD
```

The index is built once and reused for all operations. Filtering is a VIEW operation that does NOT rebuild indexes or rerun analysis.

## Evidence boundary

LogAsis preserves populated source fields, including vendor-specific JSON
fields, and assigns stable evidence identifiers. Retrieval and evidence
identity are deterministic and auditable.

The AI provider decides what evidence to investigate, what records to
correlate, and how to interpret the evidence. The provider is not allowed to
turn unsupported claims into verified forensic facts.

## Grounding

Provider claims are checked against immutable evidence references before they
are presented. When the log supports only an observation or an inference,
LogAsis keeps the language appropriately qualified.

For example, execution of a downloaded file does not automatically prove that
the file established attacker access. The UI should distinguish observed
facts from analyst interpretation.

## Retrieval

The retrieval layer supports exact identifiers such as IP addresses, ports,
process names, paths, event IDs, and CVEs while also supporting natural
language matching. Logical grouping can use correlation/session/request
identifiers or bounded time windows to provide surrounding context.

The main analyst path remains provider-directed; retrieval is evidence
infrastructure rather than a hidden forensic answer engine.

## Large logs

The current desktop application parses uploaded logs into pandas-backed
records. Evidence sent to a provider is bounded rather than blindly sending
the complete log.

For substantially larger datasets, a future scalability step is streaming
ingestion plus an embedded on-disk index while preserving the same evidence-ID
and grounding contract.
