# Interface assumptions and verification obligations

| Assumption | Current evidence | Failure risk | Required check/owner |
| --- | --- | --- | --- |
| `/health.build_sha` is the runtime version authority | Read-only W1 inspection documented in target integration | Evaluating wrong build | Fetch before campaign and persist; controller/operator |
| Target aliases resolve to exact allowed origins | Checked-in profile and gate rules | SSRF or cross-environment execution | Parse exact origin, disable/witness redirects; gate tests |
| Normal OpenEMR login/session remains available | Existing target UI baseline | Stale/foreign session | Fresh ephemeral context and card/patient checks; runner |
| Numeric PID is dynamic and never model/user controlled | Target authorization design | Cross-patient access | Resolve from exact synthetic pubpid/card; runner/gate |
| CSRF is patient scoped and must be reacquired after navigation | W1 source/baseline docs | Stale or wrong-context request | Read card immediately before action; runner |
| Stage rejection is actual cleanup | Target endpoint contract | Persistent contaminated state | Verify returned stage status; stop on uncertainty |
| Ingestion confirmation stays prohibited | Target profile | Persistent chart mutation | Gate negative test and no runner implementation |
| Target response contract remains stable | W1 source and UI baseline | Missing/misread evidence | Contract smoke on exact build; platform engineer |
| Model usage fields match provider billing semantics | SDK and adapter normalization | Budget drift | Reconcile sampled calls; FinOps/operator |
| Langfuse redaction/hiding is effective | Adapter configuration/tests | Sensitive telemetry exposure | Live synthetic canary/redaction verification; security owner |
| Queue claim/heartbeat is safe under concurrent PostgreSQL workers | Repository logic | Duplicate execution | Multi-worker integration and kill/recovery test |
| Reports directory is writable and private | Configuration only | Export failure or disclosure | Deployment filesystem/access/retention check |
| Dashboard/API reads are safe to expose | **Contradicted by route inspection** | Information disclosure | Add authentication before public deployment |
| Gate authorization reaches runner unchanged | **Not satisfied; types disconnected** | Gate bypass | Authorized envelope and end-to-end negative tests |

Assumptions are not controls. Every row that can affect authorization, evidence, cleanup, or cost must be verified for the exact deployment revision and target build.
