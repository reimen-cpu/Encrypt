"""
protocol — Envelope and Canonical Serialization
================================================
Defines the wire format (Payload v3.0) for all encrypted tokens and
provides deterministic serialization for signed payloads.

Modules:
    canonical.py — Stable, order-deterministic JSON bytes for DSA signing
    envelope.py  — Build and parse v3.0 token payloads
"""
