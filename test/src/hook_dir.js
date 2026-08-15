/* Sets up a graphics hook directory for the updater to repair, and checks what
 * it left behind.
 *
 * The updater is pointed at it with --hook-dir, so a test never touches the
 * real %ProgramData%\obs-studio-hook that this machine's OBS-derived apps
 * inject from. It still lives under %ProgramData%, because the trust check
 * walks every ancestor to the drive root: a directory under the repo or under
 * %TEMP% is reached through a user-owned one, and every run would come back
 * AncestorUntrusted no matter what the repair did.
 *
 * Needs an elevated terminal, for the same reason the repair does. Without one
 * the setup is skipped and the test says so rather than quietly passing.
 */

const fs = require('fs');
const fse = require('fs-extra');
const path = require('path');
const cp = require('child_process');

const scratch_root = path.join(process.env.ProgramData || 'C:\\ProgramData', 'slobs-hook-tests', 'e2e');

let holder_process = null;

exports.hook_dir = path.join(scratch_root, 'obs-studio-hook');

function elevated() {
  try {
    cp.execSync('net session', { stdio: 'ignore' });
    return true;
  } catch (e) {
    return false;
  }
}

function run(command) {
  try {
    cp.execSync(command, { stdio: 'ignore' });
    return true;
  } catch (e) {
    console.log('Failed: ' + command);
    return false;
  }
}

/* The 1.21-era shape: owned by whoever is logged in, writable by every
 * standard user, which is what makes the repair replace it rather than fix it
 * in place. */
function make_untrusted(dir) {
  return run(`takeown /f "${dir}" /d Y`) && run(`icacls "${dir}" /grant *S-1-5-32-545:(OI)(CI)F`);
}

/* A running image is open without FILE_SHARE_DELETE for as long as it lives,
 * which is exactly what a hooked game does to graphics-hook64.dll and exactly
 * what stops the directory being renamed out from under it. The blocker the
 * pack already uses is copied under the hook's name so the Restart Manager
 * probe, which only asks about the four names we own, can find it. */
function start_holder(testinfo) {
  const blocker = path.join(__dirname, '..', 'resources', 'file_self_blocker_v1.exe');
  const held = path.join(exports.hook_dir, 'graphics-hook64.dll');

  fse.copySync(blocker, held);

  holder_process = cp.spawn(held, ['-t 60'], {
    cwd: exports.hook_dir,
    detached: true,
    shell: true,
  });

  if (testinfo.more_log_output)
    console.log('Hook directory holder pid = ' + holder_process.pid);
}

exports.prepare = function (testinfo) {
  if (!testinfo.hookDirTest)
    return true;

  if (!elevated()) {
    console.log('=== Test ' + testinfo.number + ' skipped: --hook-dir tests need an elevated terminal');
    return false;
  }

  exports.cleanup(testinfo);
  fse.mkdirpSync(exports.hook_dir);

  if (!make_untrusted(exports.hook_dir))
    return false;

  if (testinfo.hookDirBlocked)
    start_holder(testinfo);

  return true;
};

exports.cleanup = function (testinfo) {
  if (holder_process) {
    try {
      cp.execSync(`taskkill /pid ${holder_process.pid} /t /f`, { stdio: 'ignore' });
    } catch (e) {}
    holder_process = null;
  }

  /* The image stays mapped for a moment after the process goes, and a
   * blocked repair may have staged a .new for the next reboot - deleting it
   * cancels that pending rename. */
  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      fse.removeSync(scratch_root);
      return;
    } catch (e) {
      cp.execSync('ping -n 1 -w 200 127.0.0.1 > nul', { shell: true });
    }
  }

  console.log('Could not remove ' + scratch_root);
};

function reported_category(testinfo) {
  const report_path = path.join(testinfo.reporterDir, 'crash_report.json');

  if (!fs.existsSync(report_path))
    return '';

  /* prepare_crash_report puts the category in exception.values[0].type; the
   * attached log carries the same words, so read the field rather than
   * searching the body */
  try {
    const report = JSON.parse(fs.readFileSync(report_path, 'utf8'));
    const values = report.exception && report.exception.values;

    return (values && values.length && values[0].type) || '';
  } catch (e) {
    console.log('Could not read the crash report: ' + e);
    return '';
  }
}

exports.check = function (testinfo) {
  if (!testinfo.hookDirTest)
    return true;

  let ok = true;

  if (testinfo.expectedHookReport !== undefined) {
    const category = reported_category(testinfo);

    if (category !== testinfo.expectedHookReport) {
      console.log(`Hook report was "${category}", expected "${testinfo.expectedHookReport}"`);
      ok = false;
    }
  }

  if (testinfo.expectedHookDirSecured !== undefined) {
    let acl = '';
    try {
      acl = cp.execSync(`icacls "${exports.hook_dir}"`).toString();
    } catch (e) {}

    /* the grant the repair exists to remove */
    const still_loose = acl.indexOf('BUILTIN\\Users:(OI)(CI)(F)') !== -1;

    if (still_loose === testinfo.expectedHookDirSecured) {
      console.log('Hook directory permissions not as expected:\n' + acl);
      ok = false;
    }
  }

  return ok;
};
