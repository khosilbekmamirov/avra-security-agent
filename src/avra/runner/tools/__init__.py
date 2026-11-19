"""Per-tool executors for the Tool Runner (ADR 0003, decision 6).

Each module here builds the argument list for exactly one tool from that
tool's validated request. Executors never run anything themselves and
never choose the program to run — the registry fixes the executable, and
the Runner core applies scope checks, timeouts and output caps.
"""
