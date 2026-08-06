#pragma once

#include <filesystem>

namespace fs = std::filesystem;

/* Locks down %ProgramData%\obs-studio-hook, the directory the graphics hook is
 * injected into other processes from. Releases up to 1.21 left it writable by
 * BUILTIN\Users, so it may be owned by a standard user and full of files that
 * user planted. Requires elevation; reports only through the log.
 *
 * Permissions come first and never depend on app_dir. Republishing the hook out
 * of the copy underneath it is a best-effort tail, skipped rather than failed
 * when the payload is missing or sits somewhere a standard user could rewrite.
 * It is still worth attempting, because only an elevated writer can fill the
 * hardened directory and the app usually is not one.
 *
 * Fails closed: a directory this cannot leave holding a full set of trusted
 * hooks ends with the vulkan implicit layer unregistered rather than pointing
 * at it.
 *
 * Returns whether the directory came out under administrator-only control.
 * False means it is still whatever it was, quite possibly a standard user's,
 * and is worth reporting. True with the vulkan layer unregistered is not a
 * failure: the directory is ours, only the hook payload was short.
 *
 * Six things in the implementation look like over-caution and are not:
 *
 *   - An untrusted directory is replaced, not repaired. Rewriting a DACL does
 *     not revoke handles opened before the change, so ERROR_ALREADY_EXISTS
 *     after a quarantine means somebody won the name back and their directory
 *     must not be adopted.
 *   - The quarantine name is random, and tried once. MoveFileExW will not
 *     replace a directory, so any name a standard user can predict is one they
 *     can occupy in advance to decline the repair on our behalf - a fixed set
 *     of them only sets the price at one mkdir each. Retrying is pointless at
 *     this width: a collision is not a failure mode, and everything else that
 *     fails the rename is a property of the source rather than the name. A
 *     handle held open without FILE_SHARE_DELETE fails it under every name
 *     there is, so the error is logged and reported instead of papered over.
 *   - Ownership and ACLs are reset only on a file we just wrote. Doing it to
 *     one we merely found relabels it as administrator-installed, which is
 *     exactly what the app reads to decide what to inject into other
 *     processes. A file we cannot vouch for is deleted instead.
 *   - Trust is sampled before hardening. Afterwards the descriptor propagates
 *     to the children, so everything looks administrator-installed - including
 *     the version resource the newest-wins arbitration reads.
 *   - The ancestor write mask is deliberately weaker than the object one. Every
 *     drive root grants create-file to Authenticated Users, so the strict mask
 *     would reject every path on the machine.
 *   - In the descriptor, PAI is what blocks %ProgramData%'s CREATOR OWNER
 *     entry, and AC / S-1-15-2-2 are what let an AppContainer capture target
 *     load the hook. Dropping either fails silently.
 *
 * TODO: none of this verifies signatures. Permissions establish who could have
 * written a file, not what is in it. The open question is which publisher to
 * accept, since the hooks are signed as "OBS Project, LLC" rather than as us.
 *
 * The same rules live in obs-studio's shared/obs-hook-config/hook-dir-security.h
 * and are kept in step by hand, since the two repositories share no header. */
bool repair_hook_directory(const fs::path &app_dir);
