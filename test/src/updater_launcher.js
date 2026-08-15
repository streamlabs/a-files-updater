const cp = require('child_process');
const path = require('path');
const fs = require('fs');

const hook_dir = require('./hook_dir.js');

exports.start_updater = async function (testinfo) {
  const updaterPath = path.join(testinfo.updaterDir, testinfo.updaterName)
  const updaterWorkPath = path.join(testinfo.updaterWorkDir, testinfo.updaterName)
  const updaterPathE = updaterPath.replace(/\\/g, '\\\\') + "test";
  
  let updateDirE;
  if (testinfo.systemFolder) {
    updateDirE = "A:\\";
  } else {
    updateDirE = testinfo.initialDir.replace(/\\/g, '\\\\'); 
  }

  updateJsonFile = path.join(testinfo.serverDir, "update.json"); 
  const updaterArgs = [
    '--base-url', `"${testinfo.serverUrl}"`,
    '--version', `"${testinfo.versionName}"`,
    '--exec', `"${updaterPathE}"`,
    '--cwd', `"${updateDirE}"`,
    '--interactive', `"${testinfo.runAsInteractive}"`,
    '--app-dir', `"${updateDirE}"`,
    '--force-temp',
    '--details', `"${updateJsonFile}"`
  ];

  if (testinfo.pidWaiting) {
    testinfo.pidWaitingList.forEach((pid) => {
      updaterArgs.push('-p');
      updaterArgs.push(pid);
    });
  }

  // keep the repair off the machine's real hook directory
  if (testinfo.hookDirTest) {
    updaterArgs.push('--hook-dir');
    updaterArgs.push(`"${hook_dir.hook_dir.replace(/\\/g, '\\\\')}"`);
  }

  if (testinfo.hookPrompt !== undefined) {
    updaterArgs.push('--hook-prompt');
    updaterArgs.push(`"${testinfo.hookPrompt}"`);
  }

  if (testinfo.more_log_output)
    console.log(`SPAWN: args :\n${updaterArgs}`);

  if (testinfo.wrong_arguments)
    updaterArgs.splice(0, updaterArgs.length);

  if (!fs.existsSync(testinfo.updaterWorkDir)){
    fs.mkdirSync(testinfo.updaterWorkDir);
  }
  
  fs.copyFileSync(updaterPath, updaterWorkPath);

  const app_spawned = cp.spawn(`${updaterWorkPath}`, updaterArgs, {
    cwd: testinfo.updaterWorkDir,
    detached: false,
    shell: true,
    windowsVerbatimArguments: true
  });

  app_spawned.stdout.on('data', (data) => {
    //  console.log(`SPAWN: stdout:\n${data}`);
  });

  //make promises for app exit , error
  const primiseExit = new Promise(resolve => {
    app_spawned.on('exit', resolve);
  });

  const primiseError = new Promise(resolve => {
    app_spawned.on('error', resolve);
  });

  var promise = await Promise.race([primiseError, primiseExit]);

  if (testinfo.more_log_output)
    console.log(`SPAWN: promise: ${promise}`);

  app_spawned.unref();

  if (`${promise}` == "0") {
    return true;
  } else {
    return false;
  }
}
