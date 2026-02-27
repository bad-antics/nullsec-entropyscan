# NullSec EntropyScan

Erlang file entropy analyzer demonstrating the actor model and fault-tolerant design.

## Features

- **Actor Model** - Message passing concurrency
- **Pattern Matching** - Binary parsing patterns
- **Fault Tolerance** - Supervision ready
- **Hot Code Reload** - Update without restart
- **Shannon Entropy** - Information theory metrics

## Classifications

| Level | Entropy | Description |
|-------|---------|-------------|
| Plaintext | < 4.0 | ASCII text, source code |
| Native | 4.0 - 6.5 | Compiled binaries |
| Compressed | 6.5 - 7.5 | Packed/compressed |
| Encrypted | > 7.5 | Encrypted data |

## Build

```bash
# Compile
erlc entropy.erl

# Run with escript
escript entropy.erl file.exe

# Interactive shell
erl -noshell -s entropy main file.exe -s init stop
```

## Usage

```bash
# Analyze file
./entropyscan malware.exe

# Custom block size
./entropyscan -b 512 suspicious.bin

# Show per-block entropy
./entropyscan --blocks packed.exe

# JSON output
./entropyscan -j file.bin > result.json

# Multiple files
./entropyscan *.exe
```

## API

```erlang
% Calculate entropy
entropy:calculate_entropy(Binary).

% Analyze file
entropy:analyze_file("suspicious.exe").

% Start server
Pid = entropy:start_server().

% Async analysis
entropy:analyze_async("file.exe").
```

## Use Cases

- **Malware Analysis** - Detect packing/encryption
- **Forensics** - Find encrypted sections
- **Incident Response** - Triage suspicious files
- **Reverse Engineering** - Identify data sections

## Author

bad-antics | [Twitter](https://x.com/AnonAntics)

## License

MIT
