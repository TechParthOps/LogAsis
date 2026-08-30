# Dynamic Event Filters

The Events filter is driven by the currently loaded log and does not require
manual value entry.

## Workflow

1. Upload a log.
2. Open **Events**.
3. Select a populated field such as **Source IP**, **Destination IP**,
   **Username**, **Process**, **PID**, **Port**, or a vendor-specific field.
4. LogAsis automatically populates the available values from that field.
5. Select a value.
6. Matching event records are displayed with their complete available columns.
7. Use **Clear** to restore the complete event set.

Values are matched exactly, so similar identifiers are not accidentally mixed.

## Dynamic fields

The selector is rebuilt from populated fields in the current parsed dataset.
Source-specific JSON fields are included when they contain values.

## Scope

The Events filter is a presentation filter. It does not change the evidence
universe used by Dashboard, Timeline, Investigation, Evidence, Cases, or the
AI Analyst.

The AI Analyst continues to investigate the complete uploaded log rather than
the currently visible UI subset.
