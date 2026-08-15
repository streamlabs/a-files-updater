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

/* A real synchronous sleep: ping to loopback replies immediately, so -w never
 * has anything to wait out. */
function sleep_ms(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/* Windows denies write access to a mapped image, so the open failing is the
 * signal that the holder is up and the directory can no longer be renamed. */
function image_is_mapped(file) {
  let fd;
  try {
    fd = fs.openSync(file, 'r+');
  } catch (e) {
    return true;
  }
  fs.closeSync(fd);
  return false;
}

/* A running image is open without FILE_SHARE_DELETE for as long as it lives,
 * which is exactly what a hooked game does to graphics-hook64.dll and exactly
 * what stops the directory being renamed out from under it. The blocker the
 * pack already uses is copied under the hook's name so the Restart Manager
 * probe, which only asks about the four names we own, can find it.
 *
 * Launched without a shell: cmd dispatches on the extension and will not run
 * a .dll, and even where it would, spawn returns once cmd starts rather than
 * once the image is mapped - the updater would then race the holder and the
 * blocked case would quietly test the successful one instead. */
function start_holder(testinfo) {
  const blocker = path.join(__dirname, '..', 'resources', 'file_self_blocker_v1.exe');
  const held = path.join(exports.hook_dir, 'graphics-hook64.dll');

  fse.copySync(blocker, held);

  holder_process = cp.spawn(held, ['-t', '60'], {
    cwd: exports.hook_dir,
    detached: true,
    shell: false,
    stdio: 'ignore',
  });

  holder_process.on('error', (e) => console.log('Hook directory holder failed to start: ' + e.message));

  for (let attempt = 0; attempt < 50; attempt++) {
    if (image_is_mapped(held)) {
      if (testinfo.more_log_output)
        console.log('Hook directory holder pid = ' + holder_process.pid);
      return true;
    }
    sleep_ms(100);
  }

  console.log('Hook directory holder never took hold of ' + held);
  return false;
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

  if (testinfo.hookDirBlocked && !start_holder(testinfo))
    return false;

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
      sleep_ms(200);
    }
  }

  console.log('Could not remove ' + scratch_root);
};

/* Three outcomes, deliberately distinct: no report was sent at all, one was
 * sent and names a category, or one was sent and could not be read. Folding
 * the third into the first would let a malformed report pass as silence.
 *
 * The emulator answers the POST before it finishes writing the file, so both
 * "is it there" and "is it complete" are waited for rather than sampled once. */
function reported_category(testinfo, expect_report) {
  const report_path = path.join(testinfo.reporterDir, 'crash_report.json');
  const deadline = Date.now() + (expect_report ? 5000 : 1000);
  let last_error = null;

  do {
    if (fs.existsSync(report_path)) {
      try {
        /* prepare_crash_report puts the category in
         * exception.values[0].type; the attached log carries the same
         * words, so read the field rather than searching the body */
        const report = JSON.parse(fs.readFileSync(report_path, 'utf8'));
        const values = report.exception && report.exception.values;

        return (values && values.length && values[0].type) || '<report without a category>';
      } catch (e) {
        last_error = e;
      }
    } else if (!expect_report) {
      /* nothing to wait for, but give a late write a moment to appear */
    }

    sleep_ms(200);
  } while (Date.now() < deadline);

  if (last_error) {
    console.log('Crash report at ' + report_path + ' could not be read: ' + last_error.message);
    return '<unreadable report>';
  }

  return '';
}

exports.check = function (testinfo) {
  if (!testinfo.hookDirTest)
    return true;

  let ok = true;

  if (testinfo.expectedHookReport !== undefined) {
    const category = reported_category(testinfo, testinfo.expectedHookReport !== '');

    if (category !== testinfo.expectedHookReport) {
      const wanted = testinfo.expectedHookReport === '' ? 'no report' : `"${testinfo.expectedHookReport}"`;
      console.log(`Hook report was "${category}", expected ${wanted}`);
      ok = false;
    }
  }

  if (testinfo.expectedHookDirSecured !== undefined) {
    let acl = null;
    try {
      acl = cp.execSync(`icacls "${exports.hook_dir}"`).toString();
    } catch (e) {}

    if (acl === null) {
      console.log('Could not read the ACL of ' + exports.hook_dir);
      ok = false;
    } else {
      /* the grant the repair exists to remove */
      const still_loose = acl.indexOf('BUILTIN\\Users:(OI)(CI)(F)') !== -1;

      if (still_loose === testinfo.expectedHookDirSecured) {
        console.log('Hook directory permissions not as expected:\n' + acl);
        ok = false;
      }
    }
  }

  return ok;
};
