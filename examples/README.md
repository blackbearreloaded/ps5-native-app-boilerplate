# Elevated-capability proof applications

These four small applications present the capabilities enabled by the proposed
caller-only kstuff interface. Each title shows one plain-language PASS or FAIL
notification and writes a detailed receipt under `/data` for independent
verification.

| Title | Proof | Safe boundary | Receipt |
| --- | --- | --- | --- |
| Capability Proof: Data Access | Credential inspection, system-file read, and a complete `/data` file lifecycle | Inspects only its own authority and removes temporary files | `/data/self-elevation-validation.txt` |
| Capability Proof: Process Memory | Platform `mdbg` read, write, verify, and restore | Targets only the supplied test helper and independently confirms restoration | `/data/g2-process-memory-result.txt` |
| Capability Proof: System Access | procfs mount/read/unmount, privileged-device open/close, and raw-socket availability | Removes the mount, sends no device command, and transmits no packet | `/data/g3-g5-system-capabilities-result.txt` |
| Capability Proof: Debugging | Platform `ptrace` attach, read, write, verify, restore, and detach | Targets only the supplied test helper | `/data/g6-ptrace-result.txt` |

Build the complete presentation set from the repository root:

```sh
make capability-examples
```

The process-memory and debugging proofs share
`process-memory/helper/g2-process-helper.elf`. Start a fresh helper through
elfldr immediately before either proof. See
[`docs/CAPABILITY_SUITE.md`](../docs/CAPABILITY_SUITE.md) for the exact console
order, request ABI, hardware results, and limitations.

The apps intentionally keep their on-screen output short. Their receipt files
contain PIDs, raw syscall results, stage codes, before/after values, and cleanup
status for detailed review.
