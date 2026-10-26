#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

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
 * That division is also where the two halves split. The securing half needs
 * nothing from the update, so it can run before the download, at the one moment
 * the user is stopped in front of a window and a process holding the directory
 * open is still something they can be asked about. The publishing half needs
 * the new files and runs after them.
 *
 * Fails closed: a directory this cannot leave holding a full set of trusted
 * hooks ends with the vulkan implicit layer unregistered rather than pointing
 * at it.
 *
 * Returns how the directory came out. Failed means the directory itself is
 * still whatever it was, quite possibly a standard user's. Secured means it is
 * ours, whether or not the hooks in it turned out to be a full trusted set.
 *
 * The layer is unregistered whenever the directory is not ours or the hooks in
 * it are not a full trusted set. ContainmentFailed means that removal could not
 * be verified; otherwise Secured and AncestorUntrusted can each come back with
 * the layer registered or not, and the log says which.
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
 *     there is, so that one comes back as Blocked for the caller to ask about
 *     rather than being retried here.
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
	QuarantineBlocked,
	QuarantineAccessDenied,
	ContainmentFailed,
	Failed,
};

/* How the securing half came out. Blocked means replacement was refused with
 * access denied, a sharing violation, or a lock violation. A process may be
 * holding it open, but access denied alone does not prove that. */
enum class HookSecure {
	Secured,
	Blocked,
	Failed,
};

/* The object and the path to it are answered separately, because only the
 * object is acted on: it is the one that says who wrote what is there, and the
 * one an elevated writer can repair. An untrusted ancestor is reported and
 * nothing else - see above.
 *
 * Deliberately no bool that folds the two back together. One of those is what
 * had the repair quarantining a sound directory over a drive root. */
struct TrustReport {
	bool object = false;
	bool ancestors = false;
	std::wstring object_why;
	fs::path ancestor; /* the component ancestor_why describes */
	std::wstring ancestor_why;
};

/* Walks every directory from `path`'s parent to the drive root, refusing a
 * reparse point or a write grant to anyone outside SYSTEM/Administrators/
 * TrustedInstaller at any of them. Exported because --hook-dir needs the same
 * guarantee before an elevated process ever acts on the argument's path
 * string - see cli-parser.cc. */
TrustReport chain_trust(const fs::path &path);

constexpr size_t kHookPairCount = 2;

/* What the securing half learned, for the publishing half to read back. The
 * trust sample has to cross with it: hardening the directory propagates to the
 * children, so afterwards a file that was writable only through an inherited
 * ACE reads as administrator-installed. */
struct HookRepairState {
	fs::path dir;
	std::array<bool, kHookPairCount> pair_was_trusted{};
	/* Preserved for the final report: ERROR_ACCESS_DENIED is not proof of a
	 * holder, and registry cleanup is a separate security postcondition. */
	std::uint32_t quarantine_error = 0;
	bool vulkan_cleanup_failed = false;
	bool attempted = false;
	HookSecure outcome = HookSecure::Failed;
};

/* %ProgramData%\obs-studio-hook, empty if the known folder cannot be resolved.
 * Every entry point below takes the directory rather than resolving it, so the
 * tests can drive the same code against a scratch tree - see --hook-dir. */
fs::path programdata_hook_dir();

HookSecure secure_hook_directory(const fs::path &hook_dir, HookRepairState &state);

/* Secures first if the caller has not, and again if that came back Blocked or
 * if the directory has changed hands since - whoever held it may have exited
 * while the files downloaded, and a sample taken minutes ago is not something
 * to publish on. */
HookRepair publish_hook_payload(const fs::path &app_dir, const fs::path &hook_dir, HookRepairState &state);

/* Both halves back to back, for callers with no window to ask through. */
HookRepair repair_hook_directory(const fs::path &app_dir, const fs::path &hook_dir);

/* The files the securing half has to be able to rename out from under, for a
 * caller that wants to ask the Restart Manager who is holding one. Only the
 * names we own: enumerating the directory would follow whatever junctions a
 * standard user left in it. An empty result does not rule out a directory
 * handle, an unknown child, or an ACL refusal. */
std::vector<fs::path> hook_dir_files(const fs::path &hook_dir);

/* Raises the handled error the outcome deserves, if any. Separate categories:
 * an untrusted ancestor is an environment we cannot repair, access denied does
 * not claim a holder the Restart Manager may not find, sharing violations are
 * definite blockers, and a failure to withdraw the Vulkan layer is the one
 * containment failure that must not be buried under the repair failure. */
void report_hook_repair(HookRepair result);
