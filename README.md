# Malware Strace Scanner

A simple C# CLI tool that runs `strace` on a target executable and looks for suspicious behavior such as:

- reading sensitive files like `/etc/passwd` or `/etc/shadow`
- connecting to external IP addresses
- accessing terminal, shell config, or bash history files
- attempting to replace or modify critical system binaries or cron jobs
- traversing browser profile directories for sensitive data
- copying executable payloads to system directories for persistence
- creating and exfiltrating data via temporary files

## Features

- Automatically kills strace after 10 seconds to ensure analysis completes
- Extracts PID and process name from strace output
- Reports malware categories: `spyware`, `rootkit`, `reverse shell`, etc.
- Provides detailed behavioral evidence from strace syscalls
- Runs strace with sudo for complete syscall visibility
- Handles large strace outputs by deduplicating and limiting lines

## Requirements

- .NET 10 SDK
- `strace` installed and available in `PATH`
- `sudo` configured for passwordless execution (recommended for complete syscall tracing)
- Linux environment

## Build

```bash
cd ../Mal-Analysis-Assign-3
dotnet build
```

## Run

```bash
dotnet run -- /path/to/executable
```

The tool prints the process name, detected PID (if available), categories of suspicious behavior, diagnostic flags, and a detailed summary of the strace evidence.
