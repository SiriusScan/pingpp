---
title: "Glossary"
description: "Definitions of terms used in the Prime Radiant project."
template: "TEMPLATE.reference"
version: "0.1.0"
last_updated: "2026-01-14"
author: "Project Team"
tags: ["glossary", "definitions", "terminology", "reference"]
categories: ["project", "reference"]
difficulty: "beginner"
prerequisites: []
related_docs:
  - "README.md"
  - "../architecture/CANONICAL-MODEL.md"
dependencies: []
llm_context: "high"
search_keywords: ["glossary", "terms", "definitions", "vocabulary"]
---

# Glossary

## A

### API (Application Programming Interface)
A set of defined rules and protocols for building and interacting with software. Prime Radiant exposes Ingestion and Query APIs.

### Affected Product
A software, hardware, or system that is vulnerable to a security issue. Tracked in the canonical model with vendor, product name, version, and CPE.

## B

### Batch Ingestion
The process of submitting multiple vulnerability records in a single API request. More efficient than individual requests for large datasets.

## C

### Canonical ID
The unique identifier assigned by Prime Radiant to each normalized vulnerability. Format: `PR-YYYY-NNNNNN` (e.g., `PR-2026-000001`).

### Canonical Model
The standardized, vendor-agnostic data structure used to represent vulnerabilities in Prime Radiant. Defined in JSON Schema.

### CPE (Common Platform Enumeration)
A standardized naming scheme for software, hardware, and operating systems. Example: `cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*`

### CVE (Common Vulnerabilities and Exposures)
A publicly disclosed cybersecurity vulnerability identifier. Example: `CVE-2026-12345`

### CVSS (Common Vulnerability Scoring System)
A standardized framework for rating the severity of security vulnerabilities. Scores range from 0.0 to 10.0.

## D

### Deduplication
The process of identifying and merging duplicate vulnerability records from different sources into a single canonical entry.

## E

### EPSS (Exploit Prediction Scoring System)
A model that predicts the probability that a vulnerability will be exploited in the wild. Scores range from 0 to 1.

## F

### First Seen
The timestamp when a vulnerability was first observed by any source in the Prime Radiant system.

## G

### Go
The programming language used for Prime Radiant Lambda functions. Also known as Golang.

## H

### Handler
The main function in a Lambda that processes incoming requests. Entry point for Lambda execution.

## I

### Ingestion
The process of accepting vulnerability data from external sources and normalizing it into the canonical format.

### Ingestion API
The Prime Radiant API that accepts vulnerability data for processing. Endpoints: `POST /v1/vulnerabilities`, `POST /v1/vulnerabilities/batch`.

## J

### JSON Schema
A vocabulary for annotating and validating JSON documents. Used to define the canonical vulnerability model.

## L

### Lambda (AWS Lambda)
A serverless compute service that runs code in response to events. Prime Radiant uses Lambda functions for processing.

### Last Updated
The timestamp when a canonical vulnerability record was last modified.

## M

### Metadata
Additional fields in the canonical model for extensibility. Can contain arbitrary key-value pairs.

## N

### Nessus
A proprietary vulnerability scanner by Tenable. One of the supported data sources for Prime Radiant.

### Normalization
The process of converting source-specific vulnerability data into the canonical Prime Radiant format.

### Normalizer
A Lambda function that transforms data from a specific source format to the canonical model.

### Normalized Score
A severity score (0.0-10.0) calculated by Prime Radiant to provide consistent severity across all sources.

### Normalized Level
A categorical severity (none, low, medium, high, critical) derived from the normalized score.

### NVD (National Vulnerability Database)
The U.S. government repository of vulnerability management data. A source of CVE data.

## O

### OpenAPI
A specification for describing REST APIs. Prime Radiant uses OpenAPI 3.1 for API documentation.

## P

### Prime Radiant
The vulnerability data unification platform. The name references the planning device from Isaac Asimov's Foundation series.

### Priority
The relative importance of addressing a vulnerability. In task management: high, medium, low.

## Q

### Query API
The Prime Radiant API for retrieving normalized vulnerability data. Endpoints: `GET /v1/vulnerabilities`, `GET /v1/vulnerabilities/{id}`, `GET /v1/vulnerabilities/search`.

## R

### Raw Data
The original, unmodified data from a source system, preserved in the source reference for debugging and auditing.

## S

### Schema Version
An integer field in the canonical model indicating which version of the schema was used. Enables data migrations.

### Severity
A measure of how critical a vulnerability is. Normalized to a 0-10 scale in Prime Radiant.

### Sirius Scan
An internal vulnerability scanning platform. One of the primary data sources for Prime Radiant.

### slog
Go's structured logging package (log/slog). Used for all logging in Prime Radiant.

### Source Reference
A record linking a canonical vulnerability to its original data source. Includes source ID, type, URL, and raw data.

### Source Type
The category of data source. Values: sirius, nessus, nvd, cve, vendor, manual, other.

### Structured Logging
Logging with key-value pairs instead of unstructured text. Enables easier parsing and querying.

## T

### Task
A unit of work in the project management system. Has status, priority, and dependencies.

### Temporal Data
Time-related fields tracking when a vulnerability was observed and updated.

## V

### Vendor Advisory
A security notice published by a software vendor about vulnerabilities in their products.

### Vulnerability
A weakness in software or hardware that can be exploited to compromise security.

## W

### Wrapping (Error)
The Go pattern of adding context to errors using `fmt.Errorf` with `%w`.

---

## Quick Reference

| Term | Definition |
|------|------------|
| Canonical ID | Prime Radiant vulnerability identifier (PR-YYYY-NNNNNN) |
| Canonical Model | Normalized vulnerability data structure |
| CVE | Common Vulnerabilities and Exposures identifier |
| CVSS | Common Vulnerability Scoring System (0-10) |
| Ingestion | Process of accepting and normalizing source data |
| Lambda | AWS serverless function |
| Normalization | Converting source data to canonical format |
| Source Reference | Link to original vulnerability data |

---

_Terms are listed alphabetically. For detailed explanations, see linked documentation._
