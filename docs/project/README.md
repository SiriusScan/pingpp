---
title: "Prime Radiant Project Overview"
description: "Overview of the Prime Radiant vulnerability data unification platform."
template: "TEMPLATE.documentation-standard"
version: "0.1.0"
last_updated: "2026-01-14"
author: "Project Team"
tags: ["overview", "project", "introduction"]
categories: ["project"]
difficulty: "beginner"
prerequisites: []
related_docs:
  - "CONTRIBUTING.md"
  - "GLOSSARY.md"
  - "../architecture/README.md"
dependencies: []
llm_context: "high"
search_keywords: ["prime radiant", "overview", "project", "introduction"]
---

# Prime Radiant Project Overview

## What is Prime Radiant?

Prime Radiant is a system for **unifying, normalizing, and exposing cybersecurity vulnerability data** from multiple sources through a strict, contract-driven API.

### The Problem

Organizations receive vulnerability data from many sources:
- Internal scanners (Sirius Scan)
- Commercial tools (Nessus, Qualys)
- Public databases (NVD, CVE)
- Vendor advisories

Each source uses different formats, severity scales, and identifiers. This makes it difficult to:
- Get a unified view of vulnerabilities
- Prioritize remediation efforts
- Track vulnerabilities across sources
- Automate security workflows

### The Solution

Prime Radiant provides:

1. **Unified Data Model**: A canonical vulnerability format that normalizes data from all sources
2. **Ingestion API**: Accept vulnerability data from any source
3. **Query API**: Retrieve normalized vulnerability data
4. **Source Correlation**: Link the same vulnerability across different sources
5. **Severity Normalization**: Consistent scoring across all data sources

## System Architecture

```
┌─────────────────────────────────────────────────────┐
│                   DATA SOURCES                       │
│   Sirius  │  Nessus  │  NVD/CVE  │  Vendor         │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│               INGESTION LAYER                        │
│   Ingestion API  →  Normalizer Lambdas              │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│               CANONICAL DATA                         │
│   Unified Vulnerability Model  →  Storage           │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│                 QUERY LAYER                          │
│   Query API  →  Search, Filter, Retrieve            │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│                  CONSUMERS                           │
│   Security Tools  │  Dashboards  │  Reports         │
└─────────────────────────────────────────────────────┘
```

## Project Structure

```
prime-radiant/
├── docs/                      # Documentation
│   ├── ai/                    # AI-specific docs
│   ├── architecture/          # System architecture
│   ├── developers/            # Developer guides
│   │   ├── quick-start/       # Getting started
│   │   ├── guides/            # How-to guides
│   │   └── best-practices/    # Coding standards
│   └── project/               # Project docs (this directory)
├── specs/                     # Specifications
│   ├── openapi/               # API specifications
│   └── schemas/               # JSON Schemas
├── lambdas/                   # Lambda functions
├── packages/                  # Shared Go packages
└── projects/                  # Project management
```

## Key Concepts

### Canonical Vulnerability

A normalized representation of a vulnerability with:
- Unique Prime Radiant ID (e.g., `PR-2026-000001`)
- Source references from multiple systems
- Normalized severity (0-10 scale)
- Temporal tracking (first seen, last updated)

See [Canonical Model](../architecture/CANONICAL-MODEL.md) for details.

### Source References

Each vulnerability tracks all original sources:
```json
{
  "sources": [
    {"source_type": "sirius", "source_id": "SIRIUS-2026-001"},
    {"source_type": "cve", "source_id": "CVE-2026-12345"}
  ]
}
```

### Lambda-Based Architecture

Each processing function is an isolated AWS Lambda:
- **Normalizers**: Transform source data to canonical format
- **Query Handlers**: Execute API queries
- **Ingestion Handlers**: Accept incoming data

## Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.21+ |
| Runtime | AWS Lambda |
| API Spec | OpenAPI 3.1 |
| Schema | JSON Schema Draft-07 |
| Build | Make |

## Getting Started

### For New Developers

1. [Development Setup](../developers/quick-start/development-setup.md) - Set up your environment
2. [First Lambda](../developers/quick-start/first-lambda.md) - Build your first Lambda
3. [Understanding the Schema](../developers/quick-start/understanding-the-schema.md) - Learn the data model

### For API Consumers

1. [API Integration Guide](../developers/guides/api-integration.md) - Use the APIs
2. [Ingestion API Spec](../../specs/openapi/ingest/v1.yaml) - API documentation
3. [Query API Spec](../../specs/openapi/query/v1.yaml) - API documentation

### For Contributors

1. [Contributing Guide](CONTRIBUTING.md) - How to contribute
2. [Lambda Conventions](../developers/guides/lambda-conventions.md) - Lambda standards
3. [Best Practices](../developers/best-practices/README.md) - Coding standards

## Project Status

### Current Phase: Project 0 - Foundation

Project 0 establishes the foundational structure:
- ✅ Repository structure
- ✅ Documentation standards
- ✅ Canonical vulnerability schema v0
- ✅ OpenAPI specifications
- ✅ Lambda conventions

### Future Phases

- **Project 1**: Sirius Scan ingestion
- **Project 2**: Nessus ingestion
- **Project 3**: Query implementation
- **Project 4**: Storage implementation

## Documentation Index

### Architecture
- [Architecture Overview](../architecture/README.md)
- [Canonical Model](../architecture/CANONICAL-MODEL.md)
- [API Design](../architecture/API-DESIGN.md)

### Developer Guides
- [Quick Start](../developers/quick-start/README.md)
- [Lambda Conventions](../developers/guides/lambda-conventions.md)
- [API Integration](../developers/guides/api-integration.md)
- [Testing](../developers/guides/testing-lambdas.md)

### Best Practices
- [Overview](../developers/best-practices/README.md)
- [Go Patterns](../developers/best-practices/go-patterns.md)
- [Error Handling](../developers/best-practices/error-handling.md)
- [Logging](../developers/best-practices/logging.md)

### Reference
- [Glossary](GLOSSARY.md)
- [Contributing](CONTRIBUTING.md)

## Contact

For questions about Prime Radiant:
- Check the documentation first
- Review the [Glossary](GLOSSARY.md) for terminology
- See [Contributing](CONTRIBUTING.md) to report issues

---

_Prime Radiant: Unifying vulnerability data for better security outcomes._
