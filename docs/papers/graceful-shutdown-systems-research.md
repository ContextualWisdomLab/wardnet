# Graceful shutdown systems research

This note grounds the process-lifecycle decision implemented by `src/main.rs` and exercised by the shipped-binary SIGTERM/SIGINT cases in `tests/binary.rs`. It is supporting research for `docs/architecture.md#process-lifecycle`; it does not create a second shutdown authority or extend Wardnet into transport/load-balancer ownership outside its existing gateway boundary.

## Decision relevance

Wardnet is a connection-serving gateway. Once it has announced readiness, an ordinary operator or supervisor termination should enter the server's existing graceful-shutdown future rather than abruptly taking the process through the operating system's default signal disposition. This preserves the opportunity for the serving stack to stop accepting work and complete its existing bounded connection/process cleanup path. The current change composes Unix SIGTERM and SIGINT into the same lifecycle authority; it does not implement connection migration, transparent replay, or a new failover subsystem.

Araujo, Saino, Buytenhek, and Landa (2018) report an operational edge load-balancing design in which individual components can be removed from service without breaking existing connections, explicitly tying graceful failover to maintenance availability. Wardnet does not copy Faild's transport-affinity algorithm. The relevant systems principle is narrower: planned component removal should avoid turning an administrative lifecycle event into avoidable connection loss when the serving process already exposes a graceful termination path. That principle supports routing both normal Unix termination inputs through Wardnet's one existing Axum graceful-shutdown future rather than leaving SIGINT at the default abrupt disposition.

Olteanu, Agache, Voinescu, and Raiciu (2018) similarly treat backend churn, including scale-in, as an availability event and design Beamer so those membership changes need not drop established connections. Wardnet again does not adopt Beamer's stateless load-balancing mechanism. The paper is relevant because it separates membership/lifecycle change from unnecessary connection failure in a production load-balancing context, which is the buyer-visible availability property protected by the binary-level signal acceptance.

Candea and Fox (2003) provide the important counter-position: software intentionally engineered as crash-only can make abrupt termination the single stop path and rely on fast recovery. Wardnet does not currently establish the crash-only preconditions described there, and its server API already has an explicit graceful-shutdown future. Treating default SIGINT termination as if Wardnet were crash-only would therefore be an unsupported architectural assumption. The selected design keeps one graceful path instead of adding a second lifecycle subsystem, while leaving any future crash-only/recovery architecture to separate evidence and an explicit decision.

The executable acceptance remains intentionally process-level. A helper-only test could prove construction of signal futures while missing handler-registration order at startup. `tests/binary.rs` instead launches the shipped binary, waits for readiness, delivers SIGTERM or SIGINT, and requires a clean process exit. That acceptance tests the operational invariant at the boundary where an orchestrator, supervisor, or interactive operator actually controls Wardnet.

## References

Araujo, J. T., Saino, L., Buytenhek, L., & Landa, R. (2018). Balancing on the edge: Transport affinity without network state. In *15th USENIX Symposium on Networked Systems Design and Implementation (NSDI 18)* (pp. 111–124). USENIX Association. https://www.usenix.org/conference/nsdi18/presentation/araujo

Candea, G., & Fox, A. (2003). Crash-only software. In *9th Workshop on Hot Topics in Operating Systems (HotOS IX)*. USENIX Association. https://www.usenix.org/conference/hotos-ix/crash-only-software

Olteanu, V., Agache, A., Voinescu, A., & Raiciu, C. (2018). Stateless datacenter load-balancing with Beamer. In *15th USENIX Symposium on Networked Systems Design and Implementation (NSDI 18)* (pp. 125–139). USENIX Association. https://www.usenix.org/conference/nsdi18/presentation/olteanu

## Redistribution boundary

USENIX provides public conference pages and downloadable papers for all three references. This repository records citations, links, and change-specific summaries only. No third-party PDF is vendored here because public download access alone does not establish a redistribution license for committing the document into this repository. If an authoritative permissive redistribution license is later verified for a cited paper, the PDF can be added without changing the lifecycle decision.
