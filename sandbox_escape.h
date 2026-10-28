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

// Transplant launchd's MAC label slots into our own label:
//   out_prev[0] receives our old AMFI slot, out_prev[1] our old sandbox object.
// l_perpolicy[0] is the AMFI slot (entitlements), l_perpolicy[1] the sandbox.
// Needed because Carrier Bundles returns EPERM while being 0755 owned by uid
// 501 - the refusal sits in the MAC layer, above DAC and above the extension
// table. Call this from the save path only, never at startup.
// adopt_sandbox != 0 also replaces the sandbox object (removes profile rules).
// Returns 0 when the AMFI slot was written.
int sbx_adopt_launchd_privileges(uint64_t self_proc, int adopt_sandbox,
                                 uint64_t out_prev[2]);

// Restore the slots captured by sbx_adopt_launchd_privileges().
void sbx_restore_label_slots(uint64_t self_proc, const uint64_t prev[2]);

#endif
