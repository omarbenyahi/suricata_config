# Suricata Feature Extraction System

## Architecture


## Components

### 1. Statistical Feature Extractor
- **Input**: Suricata JSON (eve.json)
- **Process**: Statistical analysis
- **Output**: Statistical Feature Vector (numeric metrics)
- **Features**: 30+ numerical features including ports, protocols, bytes, packets, ratios

### 2. Semantic Feature Extractor (LESFE)
- **Input**: Suricata JSON
- **AI Model**: DeepSeek LLM (optional)
- **Output**: Semantic Feature Vector (contextual representation)
- **Features**: Threat classification, contextual analysis, textual features

## Installation

### Prerequisites

### Setup

## Usage

### Start Statistical Extractor

### Start Semantic Extractor (without LLM)

### Start Semantic Extractor (with DeepSeek LLM)

## Output Files

### statistical_features.json

### semantic_features.json

## Features Extracted

### Statistical Features (30+)
- Alert metadata (ID, timestamp, severity)
- Protocol features (TCP, UDP, ICMP)
- Port analysis (well-known, registered, dynamic)
- Flow statistics (packets, bytes, ratios)
- Application protocol indicators

### Semantic Features (40+)
- Signature text analysis
- Threat classification (malware, exploit, scan, DoS, botnet)
- Category semantics
- Application layer context (HTTP, DNS, TLS)
- LLM-based threat analysis (when enabled)
- IP context (private/public)

## DeepSeek API Setup

1. Visit: https://platform.deepseek.com/
2. Create account and generate API key
3. Export key: `export DEEPSEEK_API_KEY='sk-...'`

## Integration with Feature Fusion Layer

Both extractors run independently and output to JSON files that can be consumed by the Feature Fusion Layer for Anomaly Detection and PPO processing.

## Notes

- Both extractors work in **real-time** monitoring mode
- Features are appended incrementally to JSON files
- Virtual environment recommended for dependency isolation
- LLM usage is optional for semantic extraction
