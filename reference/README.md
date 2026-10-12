# Exact kernel reference

`vmlinux.btf` is the intact raw BTF blob embedded in the target boot kernel.
`bpftool btf dump file reference/vmlinux.btf format raw` parses it directly.

`kernel.config` is the target kernel's embedded IKCONFIG content.

`target.json` records the target gates, kernel symbols, and structure offsets
used by the native exploit. The exploit source keeps the values as compile-time
constants and validates the complete device identity before it uses them.
