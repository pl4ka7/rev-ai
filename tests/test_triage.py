from pathlib import Path

from reverse_eng_anything.core.triage import classify_from_gdb_backtrace

SIGSEGV_WRITE_BT = """\
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401234 in vuln_copy (dst=0x0, src=0x7fffffffe000 "AAAA...") at vuln.c:42
42          memcpy(dst, src, len);
#0  0x0000000000401234 in vuln_copy ()
#1  0x0000000000401300 in main ()
write of size 128 at address 0x0
rsp            0x7fffffffdf20
"""


def test_classifies_signal_and_fault_type():
    result = classify_from_gdb_backtrace(Path("crash-001"), SIGSEGV_WRITE_BT)

    assert result.signal == "SIGSEGV"
    assert result.fault_type == "write"
    assert result.region_guess == "stack"
    assert result.severity_hint == "review-soon"


def test_unknown_backtrace_stays_unknown():
    result = classify_from_gdb_backtrace(Path("crash-002"), "")

    assert result.signal == "unknown"
    assert result.fault_type == "unknown"
    assert result.severity_hint == "needs-review"


def test_triage_never_produces_exploit_fields():
    # Guardrail test: the classification object must never grow exploit-
    # primitive fields (ROP chains, offsets-to-RIP, payloads, shellcode).
    result = classify_from_gdb_backtrace(Path("crash-003"), SIGSEGV_WRITE_BT)
    forbidden = {"rop_chain", "payload", "shellcode", "gadgets", "offset_to_rip"}
    assert forbidden.isdisjoint(result.__dict__.keys())
