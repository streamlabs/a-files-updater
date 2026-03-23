const run_test = require('./run_test.js');
const test_config = require('./test_config.js');

async function run_tests() {
    let testinfo
    //good 
    testinfo = test_config.gettestinfo(" // just test env for use with debuggers ");
    testinfo.more_log_output = true;
    //testinfo.morebigfiles = true;
    //testinfo.selfLockingFile = true;
    //testinfo.selfVirtualCamBlocking = true;
    //testinfo.selfBlockersCount = 2;
    testinfo.skipUpdaterLaunch = true;
    //testinfo.manifestGenerated = true;
    //testinfo.let_15sec = true;
    //testinfo.serverStarted = false;
    testinfo.expectedResult = "filesnotchanged"
    //testinfo.selfBlockingFile = true;
    await run_test.test_update(testinfo)
}

(async () => {
    await run_tests();
})();