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
 * Returns how the directory came out. Failed means the directory itself is
 * still whatever it was, quite possibly a standard user's, and is the only one
 * that unregisters the layer. Secured with the layer unregistered is not a
 * failure: the directory is ours, only the hook payload was short.
 *
 * AncestorUntrusted changes nothing and is reported only so we can see how
 * often it happens. The directory is ours, but something above it - %ProgramData%
 * or the drive root - is not. Nothing here acts on that. No elevated writer can
 * repair a drive root, it says nothing about who wrote the hooks, and a standard
 * user who can rename a parent of %ProgramData% can equally rename a parent of
 * %ProgramFiles% and replace the application the user launches. Withdrawing the
 * layer over it would take vulkan capture away from every OBS derived
 * application on the machine, permanently, and deny that user nothing.
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
 *   - Trust is sampled before hardening, and every later decision reads the
 *     sample rather than the disk. Afterwards the descriptor propagates to the
 *     children, so a file that was writable only through an inherited ACE
 *     reads as administrator-installed - which would both spare it from the
 *     deletion it had earned and lend its version resource to the newest-wins
 *     arbitration.
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
enum class HookRepair {
	Secured,
	AncestorUntrusted,
	Failed,
};

HookRepair repair_hook_directory(const fs::path &app_dir);

/* Raises the handled error the outcome deserves, if any. Separate categories:
 * an untrusted ancestor is an environment we cannot repair, and grouping it
 * with a failed repair would bury the one we can. */
void report_hook_repair(HookRepair result);
