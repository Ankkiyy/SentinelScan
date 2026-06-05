Mermaid Diagram for SentinelScan Architecture

flowchart TD
    A[User Enters Target URL] --> B[Target Validator]
    B --> C[Crawler]
    C --> D[Security Header Scanner]
    C --> E[SSL/TLS Checker]
    C --> F[Technology Detector]
    C --> G[Form Analyzer]
    D --> H[Risk Engine]
    E --> H
    F --> H
    G --> H
    H --> I[Findings Database]
    I --> J[Report Generator]
    J --> K[PDF/HTML Report]