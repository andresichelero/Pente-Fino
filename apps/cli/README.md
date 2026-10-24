# PenteFino Management CLI (`pentefino`)

Management CLI interface for the PenteFino bug bounty attack surface management and traffic control platform.

## Features
- **Program Management**: Create, list, and manage bug bounty programs (`pentefino program`).
- **Scope Control**: Add and import explicit allow/deny rules, inspect scope, and evaluate targets with fail-closed precedence (`pentefino scope`).
- **Authorization Governance**: Register cryptographically hashed legal authorization snapshots (`pentefino auth`).
- **Asset Inventory**: Inspect targets, observe scope status, and trace discovery (`pentefino asset`).
- **Execution Dispatch**: Trigger scanner workflows and check worker execution status (`pentefino run`).
- **Finding Inspection**: Query vulnerability findings with severity filters, Rich terminal output, or machine-readable JSON (`pentefino finding`).

## Installation
```bash
pip install -e .
```

## Quick Start
```bash
pentefino program create --slug example-bounty --name "Example Bounty"
pentefino scope add --program example-bounty --allow "*.example.com" --deny "internal.example.com"
pentefino program list --json
```
