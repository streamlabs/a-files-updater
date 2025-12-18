const path = require('path');
const os = require('os');
let test_counter = 1;

exports.gettestinfo = function (testname) {
  let newinfo = {
    testName: "",
    serverDir: "",
    initialDir: "",
    resultDir: "",
    updaterDir: "",
    updaterWorkDir: "",
    reporterDir: "",
    appPathExtra: "Program Files Streamlabs Desktop",
    versionName: "0.11.9-preview.1",
    updaterName: "slobs-updater.exe",

    serverUrl: "https://localhost/",

    files: [],

    //posible errors to test
    serverStarted: true,
    manifestGenerated: true,
    manifestWrongFile: false,
    blockFileFromUpdating: false,

    selfBlockingFile: false,
    selfLockingFile: false,
    selfBlockersCount: 1,

    pidWaiting: false,
    pidWaitingList: [],

    morebigfiles: false,

    let_404: false,
    let_drop: false,
    let_wrong_header: false,
    let_5sec: false,
    let_15sec: false,
    max_trouble: 20,
    expected_chance_for_trouble: 90,
    let_block_manifest: false,
    let_block_one_file: false,
    block_file_number: 10,
    wrong_arguments: false,
    systemFolder: false,
    customFolder: false,
    corruptBackuped: false,
    version_details: "good", // empty, nofile
    //sentry emulator
    reporterHost: "localhost",
    reporterPort: 80,

    //how to run updater 
    skipUpdaterLaunch: false,
    runAsInteractive: '0',

    //test results 
    expectedResult: "filesupdated", // "filesnotchanged", "", "filescorrupted"
    expectedCrashReport: false,

    register_unnecesary_request: false,

    not_keep_files: false,
    more_log_output: false
  }
  newinfo.number = test_counter;
  test_counter = test_counter + 1;

  newinfo.testName = newinfo.number + testname;

  const testfilesDir = path.join(__dirname, "..", "testfiles", "" + newinfo.number);
  newinfo.serverDir = path.join(testfilesDir, "server")
  newinfo.initialDir = path.join(testfilesDir, "i件Яnitial" + newinfo.appPathExtra)
  newinfo.resultDir = path.join(testfilesDir, "result")
  newinfo.reporterDir = path.join(testfilesDir, "crash_reports")

  newinfo.updaterDir = path.join(__dirname, "..", "..", "build", "distribute","a-file-updater")
  newinfo.updaterWorkDir = path.join(testfilesDir, "updaİeł")

  newinfo.files = [
    { name: "filech1.jpeg", hugefile: false, testing: "changed content" },
    { name: "filech2.jpeg", hugefile: false, testing: "changed content" },
    { name: "filea.exe", hugefile: false, testing: "deleted empty" },
    { name: "file1.exe", hugefile: false, testing: "deleted" },
    { name: "file2.txt", hugefile: false, testing: "deleted" },
    { name: "file2.jpeg", hugefile: false, testing: "same" },
    { name: "annual report 2023.docx", hugefile: false, testing: "created" },
    { name: "budget_plan(Q3&Q4).xlsx", hugefile: false, testing: "created" },
    { name: "team_meeting_01_10_2023.mp4", hugefile: true, testing: "created" },
    { name: "product_launch@2024.png", hugefile: false, testing: "created" },
    { name: "dir/ccache-clang++.sh", hugefile: false, testing: "created" },
    { name: "user-guide_v2.0#updated.pdf", hugefile: false, testing: "created" },
    { name: "file3.jpeg", hugefile: false, testing: "same" },
    { name: "Uninstall Streamlabs OBS.exe", hugefile: false, testing: "deleted exception" },
    { name: "Uninstall Streamlabs Desktop.exe", hugefile: false, testing: "deleted exception" },
    { name: "installername", hugefile: false, testing: "deleted exception" },
    { name: "dir/resources/app.asar.unpacked/node_modules/plugin.dll", hugefile: false, testing: "skip exception" },
    { name: "руский файл.jpeg", hugefile: false, testing: "same" },
    { name: "文件名.jpeg", hugefile: false, testing: "same" },
    { name: "рузский файл.jpeg", hugefile: false, testing: "changed content" },
    { name: "文件名-2.jpeg", hugefile: false, testing: "changed content" },
    { name: "file 2.svn", hugefile: false, testing: "same empty" },
    { name: "resources/app.asar", hugefile: true, testing: "changed content" },
    { name: "test2.txt", hugefile: false, testing: "changed content" },
    { name: "dir/file3.zip", hugefile: false, testing: "deleted" },
    { name: "file4.log.txt", hugefile: false, testing: "created" },
    { name: "file5.1", hugefile: false, testing: "created" },
    { name: "file 1.txt", hugefile: false, testing: "created" },
    { name: "dir/file6.ept", hugefile: false, testing: "created empty" },
  ];

  console.log("Test created: " + newinfo.testName);
  return newinfo;
}