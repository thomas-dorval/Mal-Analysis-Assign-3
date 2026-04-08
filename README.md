# Malware Strace Scanner

A simple C# CLI tool that runs `strace` on a target executable and looks for suspicious behavior such as:

- reading sensitive files like `/etc/passwd` or `/etc/shadow`
- connecting to external IP addresses
- attempting to replace or modify critical system binaries

## Requirements

- .NET 10 SDK
- `strace` installed and available in `PATH`
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

The tool prints the process name, detected PID (if available), categories of suspicious behavior, and a brief summary of the strace evidence.
