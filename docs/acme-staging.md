# Archived Deferred Certificate-Automation Notes

This document is archive-only. It records that earlier design work considered
external ACME and Let's Encrypt staging, but it is not an operational runbook,
release requirement, or supported certificate workflow.

The active single-node product supports manual certificates and private PKI
only. Do not issue, renew, stage, configure, validate, or collect evidence for
external certificate automation unless the user explicitly reopens that scope.

When that happens, create a new approved development plan before restoring any
implementation, environment configuration, helper command, external-domain
procedure, or release evidence requirement. The new plan must re-evaluate the
then-current security model, API contract, private-key handling, runtime
boundaries, and operator documentation.

For current installation and recovery guidance, use the manual-certificate and
private-PKI sections of [the install guide](install.md),
[deployment guide](deployment.md), and [troubleshooting guide](troubleshooting.md).
