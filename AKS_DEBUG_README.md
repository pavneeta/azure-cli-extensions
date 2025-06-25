# Azure CLI AKS Debug Commands

This document describes the `az aks debug` commands that integrate HolmesGPT AI-powered Kubernetes debugging into the Azure CLI AKS extension.

## Overview

The `az aks debug` command group provides AI-powered debugging capabilities for Azure Kubernetes Service (AKS) clusters using HolmesGPT. These commands help diagnose issues, analyze cluster state, and provide intelligent recommendations for troubleshooting.

## Prerequisites

### 1. Install Azure CLI AKS Preview Extension

```bash
# Install the aks-preview extension
az extension add --name aks-preview

# Or upgrade if already installed
az extension update --name aks-preview
```

### 2. Install HolmesGPT

```bash
# Install HolmesGPT CLI
pipx install holmesgpt
```

### 3. Configure OpenAI API Key

HolmesGPT requires an OpenAI API key for AI-powered analysis:

```bash
# Set the OpenAI API key as an environment variable
export OPENAI_API_KEY="your-openai-api-key-here"

# On Windows PowerShell:
$env:OPENAI_API_KEY="your-openai-api-key-here"
```

### 4. Kubernetes Access

Ensure you have access to your AKS cluster:

```bash
# Get AKS credentials
az aks get-credentials --resource-group myResourceGroup --name myAKSCluster

# Verify access
kubectl get nodes
```

## Commands

### `az aks debug ask`

Interactive AI-powered debugging that answers specific questions about your cluster.

#### Basic Usage

```bash
# Ask a question about your cluster (uses current kubectl context)
az aks debug ask --question "Why are my pods failing?"

# Ask about a specific cluster
az aks debug ask --resource-group myRG --name myCluster --question "Why is my deployment not scaling?"
```

#### Advanced Usage with Context Filtering

```bash
# Focus on specific namespace
az aks debug ask --question "What's wrong with my nginx deployment?" \
  --context-namespace default \
  --context-include-events \
  --context-include-logs

# Analyze specific resource types
az aks debug ask --question "Why are my services not accessible?" \
  --context-type service \
  --context-include-events

# Time-based analysis
az aks debug ask --question "What happened in the last hour?" \
  --context-hours 1 \
  --context-include-events \
  --context-include-logs
```

### `az aks debug investigate`

Automated cluster investigation that provides comprehensive analysis without requiring a specific question.

#### Basic Usage

```bash
# Investigate cluster issues (uses current kubectl context)
az aks debug investigate

# Investigate specific cluster
az aks debug investigate --resource-group myRG --name myCluster
```

#### Advanced Usage

```bash
# Investigate specific resource types
az aks debug investigate --context-type pod --holmes-verbose

# Focus on specific namespace
az aks debug investigate --context-namespace kube-system \
  --context-include-events \
  --context-include-logs

# Investigate with labels
az aks debug investigate --context-labels "app=nginx" \
  --context-include-monitoring
```

## Available Parameters

### Cluster Specification (Optional)
- `--resource-group` / `-g`: Azure resource group name
- `--name` / `-n`: AKS cluster name

*Note: If not specified, commands use the current kubectl context*

### Context Options
- `--context`: Kubernetes context to use
- `--context-namespace`: Limit analysis to specific namespace
- `--context-labels`: Filter resources by labels (e.g., "app=nginx")
- `--context-since`: Analyze resources since specific time
- `--context-hours`: Analyze resources from last N hours
- `--context-type`: Focus on specific resource type (pod, service, deployment, etc.)
- `--context-filter`: Additional filters for resource selection

### Context Includes
- `--context-include-events`: Include Kubernetes events
- `--context-include-logs`: Include pod logs
- `--context-include-monitoring`: Include monitoring data
- `--context-include-traces`: Include tracing data

### AI Model Configuration
- `--history`: Conversation history file path
- `--model`: AI model to use (default: gpt-4)
- `--max-tokens`: Maximum tokens for AI response
- `--temperature`: AI response creativity (0.0-2.0)
- `--top-p`: AI response focus (0.0-1.0)
- `--backend`: AI backend to use
- `--engine`: AI engine specification
- `--lang`: Response language

### Output and Behavior
- `--output`: Output format (json, table, tsv, yaml)
- `--no-cache`: Disable caching
- `--refresh-cache`: Refresh cache before analysis
- `--config`: Configuration file path
- `--holmes-verbose`: Enable verbose HolmesGPT output
- `--explain`: Provide detailed explanations

## Example Use Cases

### 1. Pod Startup Issues

```bash
# Investigate why pods aren't starting
az aks debug ask --question "Why are my pods stuck in pending state?" \
  --context-type pod \
  --context-include-events \
  --context-include-logs
```

### 2. Service Connectivity Problems

```bash
# Debug service connectivity
az aks debug ask --question "Why can't I reach my service?" \
  --context-type service \
  --context-include-events \
  --context-namespace default
```

### 3. Resource Constraints

```bash
# Analyze resource usage
az aks debug ask --question "Is my cluster running out of resources?" \
  --context-include-monitoring \
  --holmes-verbose
```

### 4. Deployment Issues

```bash
# Investigate deployment problems
az aks debug investigate --context-type deployment \
  --context-include-events \
  --context-include-logs
```

### 5. Node Problems

```bash
# Check node health
az aks debug ask --question "Are there any node issues?" \
  --context-type node \
  --context-include-events
```

## Output Formats

### Default Output
Human-readable text with AI analysis and recommendations.

### JSON Output
Structured output for programmatic use:

```bash
az aks debug ask --question "What's wrong?" --output json
```

### Integration with Azure CLI
The commands integrate seamlessly with Azure CLI patterns:

```bash
# Use with Azure CLI output formatting
az aks debug investigate --output table

# Combine with other Azure CLI commands
az aks debug ask --question "Why are pods failing?" \
  --resource-group $(az group list --query "[0].name" -o tsv) \
  --name $(az aks list --query "[0].name" -o tsv)
```

## Troubleshooting

### Common Issues

1. **HolmesGPT not found**
   ```bash
   pip install holmesgpt
   ```

2. **OpenAI API key not set**
   ```bash
   export OPENAI_API_KEY="your-key-here"
   ```

3. **Kubernetes access denied**
   ```bash
   az aks get-credentials --resource-group myRG --name myCluster
   ```

4. **No current context**
   ```bash
   kubectl config use-context your-cluster-context
   ```

### Verbose Output
Use `--holmes-verbose` for detailed HolmesGPT output:

```bash
az aks debug ask --question "Debug issue" --holmes-verbose
```

## Best Practices

1. **Be Specific**: Ask specific questions for better AI analysis
2. **Use Context Filters**: Narrow down analysis scope with filters
3. **Include Relevant Data**: Use `--context-include-*` flags for comprehensive analysis
4. **Time-bound Analysis**: Use `--context-hours` for recent issues
5. **Combine with kubectl**: Use alongside kubectl commands for verification

## Examples by Scenario

### Application Not Starting
```bash
az aks debug ask --question "Why is my application not starting?" \
  --context-namespace myapp \
  --context-include-events \
  --context-include-logs \
  --context-type pod
```

### High Resource Usage
```bash
az aks debug ask --question "Why is my cluster using too much memory?" \
  --context-include-monitoring \
  --holmes-verbose
```

### Network Issues
```bash
az aks debug ask --question "Why can't my pods communicate?" \
  --context-include-events \
  --context-type service,pod \
  --context-namespace default
```

### Cluster-wide Investigation
```bash
az aks debug investigate \
  --context-include-events \
  --context-include-logs \
  --context-include-monitoring
```

## Support

For issues related to:
- **Azure CLI**: Check [Azure CLI documentation](https://docs.microsoft.com/en-us/cli/azure/)
- **HolmesGPT**: Visit [HolmesGPT documentation](https://github.com/robusta-dev/holmesgpt)
- **AKS**: Refer to [AKS documentation](https://docs.microsoft.com/en-us/azure/aks/)

## Contributing

This integration is part of the Azure CLI AKS preview extension. Contributions and feedback are welcome through the appropriate Azure CLI channels.
