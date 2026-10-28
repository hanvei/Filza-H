#ifndef sandbox_escape_h
#define sandbox_escape_h

#include <stdint.h>

// Escape sandbox by rewriting sandbox extension data in kernel memory.
// Walk: proc_ro -> ucred -> cr_label -> sandbox -> ext_set -> ext_table -> ext -> data
int sandbox_escape(uint64_t self_proc);

// Elevate to uid=0 by swapping our p_ucred pointer with launchd's.
// Fixes UNIX DAC (owner/mode) checks so chmod/chown/writes to root-owned
int sandbox_elevate_to_root(uint64_t self_proc);

// Elevate to uid=0 by rewriting our own ucred's posix_cred in place.
// Safest form (no pointer swap, no reference-count damage); required so that
// a directory locked to 0555 stays writable for us, like LockIPCC does.
int sbx_elevate_self_uid0(uint64_t self_proc);

// Dump label / sandbox / ext_set / header / extension memory to the log.
// Diagnostics only: reads kernel memory, never writes.
void sbx_dump_state(uint64_t self_proc, const char *tag);

#endif
