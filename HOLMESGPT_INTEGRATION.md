# HolmesGPT Integration with Azure CLI AKS Extension

## Overview
Successfully integrated HolmesGPT's CLI functionality as new commands within the Azure CLI's aks-preview extension.

## Completed Implementation

### 1. Commands Added
- `az aks debug ask` - Interactive debugging with HolmesGPT AI
- `az aks debug investigate` - Automated cluster investigation

### 2. Files Modified

#### commands.py
- Added new command group: `aks debug`
- Registered two commands: `ask` and `investigate`
- Both commands route to custom functions in `custom.py`

#### _params.py
- Added comprehensive parameter definitions for both commands
- All original HolmesGPT CLI flags are preserved and mapped:
  - Context options (namespace, labels, since, hours, type, filter)
  - Context includes (events, logs, monitoring, traces)
  - Model configuration (model, max-tokens, temperature, top-p)
  - Backend options (backend, engine, language)
  - Output and behavior (output format, caching, config, verbose, explain)

#### custom.py
- Implemented `aks_debug_ask()` function
- Implemented `aks_debug_investigate()` function
- Both functions use subprocess to call HolmesGPT CLI with all user-supplied flags
- Proper error handling for missing HolmesGPT installation
- Support for JSON output parsing
- Logging integration with Azure CLI standards

### 3. Key Features

#### Optional Cluster Parameters
- `--resource-group` and `--name` (cluster name) are optional
- If not provided, commands use the current kubectl context
- This allows for flexible usage with any Kubernetes cluster

#### Flag Preservation
All original HolmesGPT CLI flags are available:
```bash
# Context flags
--context, --context-namespace, --context-labels, --context-since, --context-hours
--context-type, --context-filter
--context-include-events, --context-include-logs, --context-include-monitoring, --context-include-traces

# Model configuration
--history, --model, --max-tokens, --temperature, --top-p, --backend, --engine, --lang

# Output and behavior
--output, --no-cache, --refresh-cache, --config, --holmes-verbose, --explain
```

#### Usage Examples
```bash
# Basic usage - uses current kubectl context
az aks debug ask --question "Why are my pods failing?"

# With explicit cluster specification
az aks debug ask --resource-group myRG --name myCluster --question "Why are my pods failing?"

# With context filtering (uses current kubectl context)
az aks debug ask --question "What's wrong with my nginx deployment?" \
  --context-namespace default \
  --context-include-events \
  --context-include-logs

# Investigate mode with explicit cluster
az aks debug investigate --resource-group myRG --name myCluster \
  --context-type pod \
  --holmes-verbose

# Investigate mode using current kubectl context  
az aks debug investigate --context-type pod --holmes-verbose
```

#### Error Handling
- Checks for HolmesGPT CLI availability
- Provides clear installation instructions if missing
- Handles subprocess execution errors
- Supports both text and JSON output formats

### 4. Integration Benefits
- Native Azure CLI experience with `az aks debug` commands
- Full preservation of HolmesGPT functionality
- Consistent with Azure CLI patterns and conventions
- Proper error handling and logging
- Support for Azure CLI output formats

### 5. Prerequisites
Users need to install HolmesGPT separately:
```bash
pip install holmesgpt
```

The Azure CLI extension will provide clear error messages if HolmesGPT is not available.

## File Structure
```
src/aks-preview/azext_aks_preview/
├── commands.py        # Command registration
├── _params.py         # Parameter definitions  
└── custom.py          # Implementation functions
```

## Testing
Once the extension is built and installed, users can test with:
```bash
az aks debug ask --help
az aks debug investigate --help
```

Both commands will show all available parameters inherited from HolmesGPT CLI.
