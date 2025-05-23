# Threat Analysis Agents

**Experimental project to validate the capabilities of LLM & Agent and help for understanding the working principles of Agents.**


## Features

- Routes security analysis requests to appropriate specialized agents
- Supports analysis of:
  - Domain names (DNS, reputation, etc.)
  - IP addresses (reputation, geolocation, etc.)
  - Malware samples (file hashes, behaviors, etc.)
  - Vulnerabilities (CVE lookups, patch info, etc.)

## Configuration

Create a `.env` file based on `.env.example` with your:
- Volcano Engine API credentials
- Langfuse observability keys (optional)

## Install
```bash
poetry install
```

## Usage

To use the Threat Analysis Agents, you can run it in two ways:

### 1. Command Line Interface (CLI)
Run the following command to analyze a security query directly from the shell:
```bash
poetry run python main.py "your security query here"
```

### 2. Web Interface
Launch a simple Gradio-based web chatbot for interactive analysis:
```bash
poetry run python chatbot.py
```
![screenshot](https://github.com/kenshinx/threat-analysis-agents/blob/master/threat_analyze_agent_screenshoot.png)

Example queries:
- "Analyze the domain example.com"
- "Check IP reputation for 1.1.1.1"
- "Analyze this malware sample SHA256: abc123..."
- "Look up CVE-2023-1234 details"

## Agent Architecture

- **Triage Agent**: Routes requests to appropriate specialized agents
- **Domain Agent**: Handles domain name analysis
- **IP Agent**: Handles IP address analysis
- **Sample Agent**: Handles malware sample analysis
- **Vulnerability Agent**: Handles CVE/vulnerability analysis

## Dependencies

- Python 3.10+
- Volcano Engine API access
- Optional: Langfuse for observability
- openai-agents-python, after evaluating a dozen agent frameworks,  ultimately selected openai-agents-python due to simple, lightweight and powerful enough
