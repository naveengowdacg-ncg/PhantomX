from concurrent.futures import ThreadPoolExecutor, as_completed

class WorkflowEngine:
    """Adaptive, profile-driven assessment workflow."""
    PROFILES = {
        "passive": ["recon"],
        "standard": ["recon", "web"],
        "full": ["recon", "web", "vuln"],
    }

    def __init__(self, registry, executor, normalizer, risk_engine, logger, max_workers=4):
        self.registry = registry
        self.executor = executor
        self.normalizer = normalizer
        self.risk_engine = risk_engine
        self.logger = logger
        self.max_workers = max_workers

    def tools_for_profile(self, profile):
        categories = self.PROFILES[profile]
        return [t for t in self.registry.list() if t.get("enabled", True) and t.get("category") in categories]

    def run(self, session):
        # Stage 1: run selected tools. Stage 2: normalize/score. Stage 3: adapt based on findings.
        selected = self.tools_for_profile(session.profile)
        self.logger.info("Workflow start: profile=%s target=%s tools=%s", session.profile, session.target, [t["name"] for t in selected])
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.executor.run, t, session.target): t for t in selected}
            for future in as_completed(futures):
                result = self.normalizer.parse(future.result())
                result.findings = self.risk_engine.score_all(result.findings)
                session.results.append(result)
                self.logger.info("Tool %s finished with %s findings", result.tool, len(result.findings))

        # Adaptive stage: if network results expose HTTP/HTTPS, ensure web tools are considered even in passive profile.
        if session.profile == "passive":
            return session
        open_web = any(
            any(f.metadata.get("port") in {80, 443, 8080, 8443} for f in r.findings)
            for r in session.results
        )
        if open_web:
            session.notes.append("Web service detected; web assessment stage is relevant.")
        return session
