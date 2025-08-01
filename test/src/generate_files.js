const fs = require('fs');
const fse = require('fs-extra')
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const kill = require('tree-kill');

const hugefilecontent = "asdfasdf23rdsf34rsdfasdfasdf23rdsf34rsdfasdfasdf23rdsf34rsdfasdfasdf23rdsf34rsdf"
const morefilesmax = 128;
const filecontentlines = 100;
const hugefileincrese = 20;

const selfblockingfile_server = "file_self_blocker_v1.exe";
const selfblockingfile_init = "file_self_blocker_v6.exe";
const selfblockingfile_name = "file_self_blocker";


let self_blocking_process=[];

async function generate_file(filedir, filename, filecontentextended = "", emptyfile = false, hugefile = false) {
  return new Promise((resolve, reject) => {
    const filepath = path.join(filedir, filename)
    fse.outputFileSync(filepath, '');

    var stream = fs.createWriteStream(filepath);
    if (!emptyfile) {
      var i;
      var lines = filecontentlines;
      filecontentextended = filecontentextended + filename;
      if (hugefile) {
        filecontentextended = hugefilecontent + filecontentextended;
        lines = filecontentlines * hugefileincrese;
      }
      stream.write(filename + `\n`);
      stream.write(filecontentextended + `\n`);
      stream.write(`\n`);

      var cipher = crypto.createCipheriv('aes-256-ctr', 'b2df428b9929d3ace7c598bbf4e496b2', 'dkfirosnfkdyrifj')

      for (i = 0; i < lines; i++) {
        var crypted = cipher.update(filecontentextended + i, 'utf8', 'hex')
        stream.write(i + ` ${crypted}` + `\n`);
      }
    }

    stream.end();
    stream.on("finish", () => { resolve(true); });
    stream.on("error", reject);

  });
}

function generate_file_sync(filedir, filename, filecontentextended = "", emptyfile = false, hugefile = false) {
  const filepath = path.join(filedir, filename)
  fse.outputFileSync(filepath, '');

  var stream = fs.openSync(filepath);
  if (!emptyfile) {
    var i;
    var lines = filecontentlines;
    filecontentextended = filecontentextended + filename;
    if (hugefile) {
      filecontentextended = hugefilecontent;
      lines = filecontentlines * hugefileincrese;
    }
    stream.write(filename + `\n`);
    stream.write(filecontentextended + `\n`);
    stream.write(`\n`);

    var cipher = crypto.createCipheriv('aes-256-ctr', 'b2df428b9929d3ace7c598bbf4e496b2', 'dkfirosnfkdyrifj')

    for (i = 0; i < lines; i++) {
      var crypted = cipher.update(filecontentextended + i, 'utf8', 'hex')
      stream.writeSync(i + ` ${crypted}` + `\n`);
    }
  }

  stream.end();
}

function filewalker(dir, done) {
  let results = [];

  fs.readdir(dir, function (err, list) {
    if (err) return done(err);

    var pending = list.length;

    if (!pending) return done(null, results);

    list.forEach(function (file) {
      file = path.resolve(dir, file);

      fs.stat(file, function (err, stat) {
        // If directory, execute a recursive call
        if (stat && stat.isDirectory()) {

          filewalker(file, function (err, res) {
            results = results.concat(res);
            if (!--pending) done(null, results);
          });
        } else {
          results.push(file);

          if (!--pending) done(null, results);
        }
      });
    });
  });
};

function generate_manifest(testinfo) {
  return new Promise((resolve, reject) => {
    const filepath = path.join(testinfo.serverDir, testinfo.versionName + ".sha256")
    fse.outputFileSync(filepath, '');

    filewalker(testinfo.serverDir, function (err, data) {
      if (err) {
        throw err;
      }

      var stream = fs.createWriteStream(filepath);

      for (var foundfile of data) {
        if (filepath == foundfile) {
          continue;
        } else {
          const hash = crypto.createHash('sha256');
          const input = fs.readFileSync(foundfile)

          hash.update(input);
          var update_subdirpath = path.join(testinfo.serverDir, testinfo.versionName)
          stream.write(`${hash.digest('hex')}` + " " + foundfile.substring(update_subdirpath.length + 1) + "\n");

          const gzip = zlib.createGzip();
          const inp = fs.createReadStream(foundfile);
          const out = fs.createWriteStream(foundfile + ".gz");

          inp.pipe(gzip).pipe(out);

        }
      }
      if (testinfo.manifestWrongFile) {

        stream.write(`e980fe14384b38340fad866a92f2cbe4aeef268fac3368274bcb0b8e2cd32702` + " \\missing_file5.1\n");
      }
      stream.end();
      stream.on("finish", () => { resolve(true); }); // not sure why you want to pass a boolean
      stream.on("error", reject); // don't forget this!

      //console.log(data);
    });

  });
}

async function put_file_blocking(testinfo, use_blocking_program, update_subdirpath, need_to_launch, blocker_number) {
  if (testinfo.selfBlockingFile || testinfo.selfLockingFile) {
    let pathInResources = path.join(__dirname, "..", "resources", use_blocking_program);
    const blocker_name = selfblockingfile_name+blocker_number+".exe";
    let pathInTest = path.join(update_subdirpath, blocker_name);
    fse.copySync(pathInResources, pathInTest);

    let arg1 = "";
    let arg2 = "-t 24";

    if (testinfo.selfLockingFile) {
      arg1 = "-l";
    }

    if (testinfo.pidWaiting) {
      arg2 = "-t 2";
    }
    let blocker_to_launch = blocker_number;

    while (need_to_launch && blocker_to_launch > 0) {
      let new_blocking_process = require('child_process').spawn(blocker_name, [
        arg1, arg2
      ], {
          cwd: update_subdirpath,
          detached: true,
          shell: true
        });
      new_blocking_process.stdout.on('data', function(data) {
        console.log(data.toString());
      });
      new_blocking_process.stderr.on('data', function(data) {
        console.log(data.toString());
      });
      new_blocking_process.on('close', exitCode => {
        console.log('Blocker process closed pid:', new_blocking_process.pid);
      });
      if(testinfo.more_log_output)
        console.log("Blocker process pid = " + new_blocking_process.pid + " " + pathInTest);

      self_blocking_process.push(new_blocking_process);
      if (testinfo.pidWaiting) {
        testinfo.pidWaitingList.push(new_blocking_process.pid);
      }
      blocker_to_launch = blocker_to_launch -1;
    }
  }
}

async function generate_server_dir(testinfo) {
  const update_subdirpath = path.join(testinfo.serverDir, testinfo.versionName)

  for(const file of testinfo.files) {
    let filecontentextended = "some file content";
    let fileempty = false;

    if(file.testing == "same") {

    } else if(file.testing == "same empty") {
      fileempty = true;
    } else if(file.testing == "changed content") {
      filecontentextended = "new content"
    } else if(file.testing == "made empty") {
      fileempty = true;
    } else if(file.testing == "from empty") {
      fileempty = false;
    } else if(file.testing == "created") {

    } else if(file.testing == "created empty") {
      fileempty = true;
    } else if(file.testing == "deleted") {
      continue;
    } else if(file.testing == "deleted empty") {
      continue;
    } else if(file.testing == "deleted exception") {
      continue;
    } else if(file.testing == "skip exception") {
      continue;
    } 

    await generate_file(update_subdirpath, file.name, filecontentextended, fileempty, file.hugefile);
  }

  if (testinfo.morebigfiles) {
    let file_index;
    for (file_index = 0; file_index < morefilesmax; file_index++) {
      let file_name = "dir_bigs\\file" + file_index + ".txt";
      await generate_file(update_subdirpath, file_name, "", false, true)
    }
  } else {
    let file_index;
    for (file_index = 0; file_index < 16; file_index++) {
      let file_name = "dir_some\\file" + file_index + ".txt";
      await generate_file(update_subdirpath, file_name, "", false, true)
    }
  }

  for(i = 0; i< testinfo.selfBlockersCount; i++)
  {
    await put_file_blocking(testinfo, selfblockingfile_server, update_subdirpath, false, i);
  }

  if (testinfo.manifestGenerated) {
    await generate_manifest(testinfo)
  }
  
  if( testinfo.version_details == "good") {
    const jsonfile = path.join(testinfo.serverDir, "update.json");
    fse.outputFileSync(jsonfile, "");
    const jsoncontent = {
      version: testinfo.versionName,
      seed: "1111111121111111",
      rollout: { default: 100 },
      restricted: false,
      fallbackVersion: testinfo.fallbackVersion,
      details:
        "Release Notes:\n- Preview build for early testing.\n- Introduces experimental feature flags.\n- Improves core‑engine performance under load.\n- Fixes assorted stability and memory‑leak issues found in 1.18.x.\n- Updates documentation and localization assets.\nBuild date: 2025‑05‑13.",
    };
    fse.writeJsonSync(jsonfile, jsoncontent, { spaces: 2 });
  } else if (testinfo.version_details == "empty") {
    const jsonfile = path.join(testinfo.serverDir, "update.json");
    fse.outputFileSync(jsonfile, "");
  } else if (testinfo.version_details == "nofile") {
  }

  if(testinfo.more_log_output)
    console.log("Finish generate_server_dir");
}

async function generate_initial_dir(testinfo, update_subdirpath = "") {
  if (update_subdirpath == "") {
    update_subdirpath = testinfo.initialDir
  }
  
  for(const file of testinfo.files) {
    let filecontentextended = "some file content";
    let fileempty = false;

    if(file.testing == "same") {

    } else if(file.testing == "same empty") {
      fileempty = true;
    } else if(file.testing == "changed content") {
      filecontentextended = "old content"
    } else if(file.testing == "made empty") {
      fileempty = false;
    } else if(file.testing == "from empty") {
      fileempty = true;
    } else if(file.testing == "created") {
      continue;
    } else if(file.testing == "created empty") {
      continue;
    } else if(file.testing == "deleted") {
      
    } else if(file.testing == "deleted empty") {
      fileempty = true;
    } else if(file.testing == "deleted exception") {

    } else if(file.testing == "skip exception") {

    }

    await generate_file(update_subdirpath, file.name, filecontentextended, fileempty, file.hugefile);
  }

  if (false) {
    let file_index;
    for (file_index = 0; file_index < 16; file_index++) {
      let file_name = "dir_other\\file" + file_index + ".txt";
      await generate_file(update_subdirpath, file_name, "", false, true)
    }
  }
  
  for(i = 0; i< testinfo.selfBlockersCount; i++)
  {
    await put_file_blocking(testinfo, selfblockingfile_init, update_subdirpath, update_subdirpath === testinfo.initialDir, i);
  }
  
  if(testinfo.more_log_output)
    console.log("Finish generate_initial_dir");
}

async function generate_result_dir(testinfo, update_subdirpath) {

  for(const file of testinfo.files) {
    let filecontentextended = "some file content";
    let fileempty = false;

    if(file.testing == "same") {

    } else if(file.testing == "same empty") {
      fileempty = true;
    } else if(file.testing == "changed content") {
      filecontentextended = "new content"
    } else if(file.testing == "made empty") {
      fileempty = true;
    } else if(file.testing == "from empty") {
      fileempty = false;
    } else if(file.testing == "created") {

    } else if(file.testing == "created empty") {
      fileempty = true;
    } else if(file.testing == "deleted") {
      continue;
    } else if(file.testing == "deleted empty") {
      continue;
    } else if(file.testing == "deleted exception") {

    } else if(file.testing == "skip exception") {
      continue;
    }

    await generate_file(update_subdirpath, file.name, filecontentextended, fileempty, file.hugefile);
  }

  if (testinfo.morebigfiles) {
    let file_index;
    for (file_index = 0; file_index < morefilesmax; file_index++) {
      let file_name = "dir_bigs\\file" + file_index + ".txt";
      await generate_file(update_subdirpath, file_name, "", false, true)
    }
  } else {
    let file_index;
    for (file_index = 0; file_index < 16; file_index++) {
      let file_name = "dir_some\\file" + file_index + ".txt";
      await generate_file(update_subdirpath, file_name, "", false, true)
    }
  }
  
  for(i = 0; i< testinfo.selfBlockersCount; i++)
  {
    await put_file_blocking(testinfo, selfblockingfile_server, update_subdirpath, false, i);
  }
  
  if(testinfo.more_log_output)
    console.log("Finish generate_result_dir");
}

clean_test_dir = function (dirpath) {
  try {
    fse.removeSync(dirpath);
  }
  catch (error) {
    console.log("Failed to clean_dir for " + dirpath+ " , error: "+error);  
    return;
  }
  
}

exports.clean_after_test = function (testinfo, force) {
  self_blocking_process.forEach(function(item){
    console.log("Close file blocking process");
    //kill.treeKillSync(self_blocking_process.pid);
    kill(item.pid);
    //process.kill(-self_blocking_process.pid);
  });
  self_blocking_process = [];

  if (testinfo.not_keep_files || force) {
    clean_test_dir(testinfo.serverDir);
    clean_test_dir(testinfo.initialDir);
    clean_test_dir(testinfo.resultDir);
    clean_test_dir(testinfo.reporterDir);
    if(testinfo.more_log_output)
      console.log("Finish all clean_dir runs");
  }
}

exports.generate_test_files = async function (testinfo) {
  exports.clean_after_test(testinfo, true);

  await generate_server_dir(testinfo);
  await generate_initial_dir(testinfo);

  if (testinfo.expectedResult == "filesupdated")
    await generate_result_dir(testinfo, testinfo.resultDir);
  if (testinfo.expectedResult == "filesnotchanged")
    await generate_initial_dir(testinfo, testinfo.resultDir);
  if (testinfo.expectedResult == "filescorrupted")
    await generate_initial_dir(testinfo, testinfo.resultDir);

}

exports.check_results = function (testinfo) {
  var dircompare = require('dir-compare');
  var format = require('util').format;
  const fs = require('fs');
  const path = require('path');

  var options = { compareSize: true, compareContent: true };
  var path1 = testinfo.initialDir;
  var path2 = testinfo.resultDir;

  var states = { 'equal': '==', 'left': '->', 'right': '<-', 'distinct': '<>' };

  var res = dircompare.compareSync(path1, path2, options);

  if(testinfo.more_log_output)
    console.log(format('Compare dirs: equal=%s, distinct=%s, left=%s, right=%s, differences=%s, same=%s',
      res.equal, res.distinct, res.left, res.right, res.differences, res.same));

  let file_distinct = res.distinct;
  let file_left = 0;
  let file_right = 0;

  res.diffSet.forEach(function (entry) {
    if (entry.state === 'left' && entry.type1 === 'file') {
      file_left++;
    } else if (entry.state === 'right' && entry.type2 === 'file') {
      file_right++;
    }
  });

  let ret = file_distinct !== 0 || file_left !== 0 || file_right !== 0;

  if (ret) {
    res.diffSet.forEach(function (entry) {
      var state = states[entry.state];
      var name1 = entry.name1 ? entry.name1 : '';
      var name2 = entry.name2 ? entry.name2 : '';
      console.log(format('%s(%s)%s%s(%s)', name1, entry.type1, state, name2, entry.type2));
    });
  }

  if (ret) {
    const report_path = path.join(testinfo.reporterDir, "crash_report.json")
    const have_report = fs.existsSync(report_path);

    if ((testinfo.expectedCrashReport && have_report)
      || (!testinfo.expectedCrashReport && !have_report)) {
      ret = true;
    } else {
      ret = false;
    }
  }

  return !ret;

}