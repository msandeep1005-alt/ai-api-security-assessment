# AI-Assisted API Security Assessment

An AI-assisted API security assessment framework developed for the **OWASP crAPI API**.

The project combines OpenAPI-driven endpoint discovery, LLM-assisted security analysis and test generation, automated security-test execution, deterministic validation, evidence collection, finding management, and HTML/JSON reporting.

---

## Overview

The objective of this implementation is to demonstrate an end-to-end API security assessment workflow where AI assists with security reasoning and test generation, while **runtime evidence and deterministic validation are used for final vulnerability classification**.

The assessment pipeline covers:

- OpenAPI specification analysis
- API endpoint discovery
- AI-assisted endpoint security analysis
- AI-generated security test plans
- Automated security test execution
- BOLA testing
- Authentication testing
- Rate-limit testing
- Excessive data exposure testing
- Deterministic validation
- Evidence collection
- Finding generation
- JSON and HTML reporting

The implementation was tested against the locally deployed **OWASP crAPI** target.

---

## Assessment Architecture

```text
                    OpenAPI Specification
                             |
                             v
                    Endpoint Discovery
                             |
                             v
                  AI Security Analysis
                             |
                             v
                  AI Test Generation
                             |
                             v
                  Security Test Plan
                             |
                             v
                   Test Dispatcher
                             |
            +----------------+----------------+
            |                |                |
            v                v                v
          BOLA       Authentication     Information
                                           Disclosure
            |                |                |
            +----------------+----------------+
                             |
                             v
                      Rate Limiting
                             |
                             v
                 HTTP Test Execution
                             |
                             v
                Deterministic Validation
                             |
                             v
                    Evidence Collection
                             |
                             v
                     Finding Manager
                             |
                             v
                  JSON / HTML Reporting
