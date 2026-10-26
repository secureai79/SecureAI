"""AI Safety Checkup - offline CLI, policy-as-code and CI integration.

Runs the same static analysis as the hosted product (``app.scanner.pipeline``) on a local
checkout. No database, no server and no network access are needed, so customers can run it
in their own CI and their source code never leaves their infrastructure.
"""
__version__ = "0.1.0"