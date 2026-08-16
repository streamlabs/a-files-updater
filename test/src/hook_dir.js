/* Sets up a graphics hook directory for the updater to repair, and checks what
 * it left behind.
 *
 * The updater is pointed at it with --hook-dir, so a test never touches the
 * real %ProgramData%\obs-studio-hook that this machine's OBS-derived apps
 * inject from. It still lives under %ProgramData%, because the trust check
 * walks every ancestor to the drive root: a directory under the repo or under
 * %TEMP% is reached through a user-owned one, and --hook-dir would refuse the
 * argument outright rather than letting the updater run against it.
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
    cp.execFileSync('net.exe', ['session'], { stdio: 'ignore' });
    return true;
  } catch (e) {
    return false;
  }
}

function run(file, args) {
  try {
    cp.execFileSync(file, args, { stdio: 'ignore' });
    return true;
  } catch (e) {
    console.log('Failed: ' + file + ' ' + args.join(' '));
    return false;
  }
}

/* The 1.21-era shape: owned by whoever is logged in, writable by every
 * standard user, which is what makes the repair replace it rather than fix it
 * in place. */
function make_untrusted(dir) {
  return run('takeown.exe', ['/f', dir]) && run('icacls.exe', [dir, '/grant', '*S-1-5-32-545:(OI)(CI)F']);
}

/* mkdirpSync leaves every directory it creates owned by whoever is running
 * this elevated terminal, not BUILTIN\Administrators, and --hook-dir now
 * refuses an override reached through anything but Administrators. Retaken
 * and locked down the same way the shared hook directory itself is, so the
 * chain the parser demands is the chain this tree actually has. */
function harden_ancestor(dir) {
  return (
    run('takeown.exe', ['/f', dir, '/a']) &&
    run('icacls.exe', [
      dir,
      '/inheritance:r',
      '/grant:r',
      '*S-1-5-18:(OI)(CI)F',
      '*S-1-5-32-544:(OI)(CI)F',
    ])
  );
}

/* A real synchronous sleep: ping to loopback replies immediately, so -w never
 * has anything to wait out. */
function sleep_ms(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/* Windows denies write access to a mapped image, so the open failing says the
 * image is mapped. The loader maps it during startup whether or not the holder
 * survives that, so this is a step towards readiness and not readiness itself. */
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

function still_running(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return false;
  }
}

/* The rename quarantine_hook_dir() performs. Asserted once the holder has
 * settled, never polled: a rename that succeeds while the holder is still
 * starting takes the directory out from under it and the holder exits, so
 * polling this destroys the thing it is measuring. */
function quarantine_is_refused() {
  const aside = exports.hook_dir + '.holdprobe';

  try {
    fs.renameSync(exports.hook_dir, aside);
  } catch (e) {
    return true;
  }

  /* prepare() is called outside any try in run_test.js, so a throw here would
   * take the whole suite down rather than fail the one test */
  try {
    fs.renameSync(aside, exports.hook_dir);
  } catch (e) {
    console.log('Could not put ' + aside + ' back: ' + e.message);
  }

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
 * blocked case would quietly test the successful one instead.
 *
 * stdin has to be a pipe this process holds open. The blocker exits on stdin
 * EOF, so 'ignore' hands it NUL and it is gone inside half a second - the
 * pack's other blockers survive only because the default stdio gives them a
 * pipe. That exit is invisible to the image probe, which the loader has
 * already satisfied by then, so readiness is not settled until the holder is
 * confirmed alive and the rename confirmed refused. */
function start_holder(testinfo) {
  const blocker = path.join(__dirname, '..', 'resources', 'file_self_blocker_v1.exe');
  const held = path.join(exports.hook_dir, 'graphics-hook64.dll');

  fse.copySync(blocker, held);

  holder_process = cp.spawn(held, ['-t', '60'], {
    cwd: exports.hook_dir,
    detached: true,
    shell: false,
    stdio: ['pipe', 'ignore', 'ignore'],
  });

  holder_process.on('error', (e) => console.log('Hook directory holder failed to start: ' + e.message));
  /* the pipe breaks when cleanup kills the holder, and an unhandled error on
   * a stdio stream would take the suite down with it */
  holder_process.stdin.on('error', () => {});

  for (let attempt = 0; attempt < 50; attempt++) {
    if (image_is_mapped(held))
      break;
    sleep_ms(100);
  }

  sleep_ms(750);

  if (!still_running(holder_process.pid)) {
    console.log('Hook directory holder exited during startup, so ' + held + ' is not held');
    return false;
  }

  if (!quarantine_is_refused()) {
    console.log('Hook directory holder never took hold of ' + held);
    return false;
  }

  if (testinfo.more_log_output)
    console.log('Hook directory holder pid = ' + holder_process.pid);

  return true;
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

  if (!harden_ancestor(path.dirname(scratch_root)) || !harden_ancestor(scratch_root))
    return false;

  if (!make_untrusted(exports.hook_dir))
    return false;

  if (testinfo.hookDirBlocked && !start_holder(testinfo))
    return false;

  return true;
};

exports.cleanup = function (testinfo) {
  if (holder_process) {
    try {
      cp.execFileSync('taskkill.exe', ['/pid', String(holder_process.pid), '/t', '/f'], {
        stdio: 'ignore',
      });
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

function delay_ms(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/* Three outcomes, deliberately distinct: no report was sent at all, one was
 * sent and names a category, or one was sent and could not be read. Folding
 * the third into the first would let a malformed report pass as silence.
 *
 * The emulator answers the POST before it finishes writing the file, so both
 * "is it there" and "is it complete" are waited for rather than sampled once.
 * That write happens on this same process's event loop, in
 * error_receive_server.js, so the wait has to yield to it rather than block
 * it - a blocking sleep here would starve the very write it is waiting on. */
async function reported_category(testinfo, expect_report) {
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

    await delay_ms(200);
  } while (Date.now() < deadline);

  if (last_error) {
    console.log('Crash report at ' + report_path + ' could not be read: ' + last_error.message);
    return '<unreadable report>';
  }

  return '';
}

exports.check = async function (testinfo) {
  if (!testinfo.hookDirTest)
    return true;

  let ok = true;

  if (testinfo.expectedHookReport !== undefined) {
    const category = await reported_category(testinfo, testinfo.expectedHookReport !== '');

    if (category !== testinfo.expectedHookReport) {
      const wanted = testinfo.expectedHookReport === '' ? 'no report' : `"${testinfo.expectedHookReport}"`;
      console.log(`Hook report was "${category}", expected ${wanted}`);
      ok = false;
    }
  }

  if (testinfo.expectedHookDirSecured !== undefined) {
    let acl = null;
    try {
      acl = cp.execFileSync('icacls.exe', [exports.hook_dir]).toString();
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
