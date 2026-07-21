# Installation

Source installation is the preferred method. Install Git and Go 1.26, then run:

```bash
git clone https://github.com/Bavlik/CredScope.git
cd CredScope
go run ./cmd/credscope version
go run ./cmd/credscope scan /path/to/repository
```

Build locally with `go build -o credscope ./cmd/credscope`, or on Windows with `go build -o credscope.exe ./cmd/credscope`.

GitHub Release binaries are optional conveniences. Verify checksums. Official v0.1.0 Windows binaries are unsigned; building from source avoids relying on an unsigned executable without requiring users to disable security controls.

CredScope is Apache-2.0 licensed. No payment or commercial license is required.
