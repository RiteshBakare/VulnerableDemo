# Safe SecureFix AI Testing Workflow

1. Generate the project from this SDD.
2. Run only on `127.0.0.1` with synthetic data and a disposable database.
3. Import `fixtures/securefix-vuln-lab.sarif` into SecureFix AI.
4. Confirm eight findings and preserved severities.
5. Create a plan and patch proposal for one finding.
6. Inspect the diff and validate it without applying it to the working tree.
7. Review evidence, human verdict behavior, and audit history.
8. Confirm findings are not automatically closed.
9. Reset only the disposable demo database when finished.

The SARIF fixture is synthetic and hand-authored. It tests SecureFix AI's import workflow; it does not prove a static analyzer detects all eight findings.
