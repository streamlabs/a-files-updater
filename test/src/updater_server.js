var http = require('http');
var https = require('https');
var httpProxy = require('http-proxy');
var finalhandler = require('finalhandler');
var serveStatic = require('serve-static');
const fs = require('fs'); 
const path = require('path');

var server;
var proxy;
var proxyServer;

var ssl_options = {
  key: fs.readFileSync('valid-ssl-key.pem', 'utf8'),
  cert: fs.readFileSync('valid-ssl-cert.pem', 'utf8')
};

var files_served = 0;
var file_to_block;
var have_trouble = 0;
var files_corrupted = false;

exports.start_https_update_server = function (testinfo) {
  files_served = 0;
  file_to_block = "";
  have_trouble = 0;

  proxy = httpProxy.createProxyServer();

  proxy.on('error', function (err, req, res) 
  { 
    //console.log("just proxy error");
  });

  proxyServer = https.createServer(ssl_options, function (req, res) {
    let test_timeout = 100 + Math.floor(Math.random() * Math.floor(500));
    let chanse_for_trouble = Math.floor(Math.random() * Math.floor(100));
    //console.log( req.socket.localAddress );
    let do_block = (chanse_for_trouble > testinfo.expected_chance_for_trouble && have_trouble < testinfo.max_trouble ) ;

    if((testinfo.let_block_one_file && (testinfo.block_file_number == files_served) ) && ! file_to_block)
    {
      file_to_block = req.url;
    }
    if(testinfo.let_block_one_file && ( file_to_block === req.url ))
    {
      do_block = true;
    }
    
    if( do_block && req.url == "//0.11.9-preview.1.sha256")
    {
      do_block = false;
    }

    if( testinfo.let_block_manifest && req.url == "//0.11.9-preview.1.sha256")
    {
      do_block = true;
      if(!testinfo.let_block_one_file )
      {
        testinfo.let_block_manifest = false;
      }
    }

    if(files_served == 10 && testinfo.corruptBackuped && !files_corrupted) {
      files_corrupted = true;
      console.log("10 files served and corruptBackuped is true. Will try to corrupt backuped file and remove one downloaded");
      let file_to_corrupt = path.join(testinfo.initialDir, testinfo.files[0].name);
      console.log("Will corrupt file " + file_to_corrupt);

      fs.writeFileSync(file_to_corrupt, "corrupted");

      let file_to_abort_update = path.join(testinfo.initialDir, testinfo.files[1].name);
      console.log("Will remove file " + file_to_abort_update);
      fs.unlinkSync(file_to_abort_update);
    }

    //check if file requested is from files that not changed and not have to be downloaded 
    let decoded_url = decodeURI(req.url);
    let requested_file = decoded_url.substring("//0.11.9-preview.1/".length, req.url.length-3);

    for(const update_file of testinfo.files) {
      if( update_file.name == requested_file) {
        let file_ok_to_update = true;
        if(update_file.testing == "same") {
          file_ok_to_update = false;
        } else if(update_file.testing == "same empty") {
          file_ok_to_update = false;
        } else if(update_file.testing == "changed content") {
          
        } else if(update_file.testing == "made empty") {
          
        } else if(update_file.testing == "from empty") {
          
        } else if(update_file.testing == "created") {
    
        } else if(update_file.testing == "created empty") {
        } else if(update_file.testing == "deleted") {
          file_ok_to_update = false;
        } else if(update_file.testing == "deleted empty") {
          file_ok_to_update = false;
        } else if(update_file.testing == "deleted exception") {
          file_ok_to_update = false;
        } else if(update_file.testing == "skip exception") {
          file_ok_to_update = false;
        }
    
        if(!file_ok_to_update)
        {
          console.log("Warning: Found requested file in testinfo.files as not changed - " + req.url);
          testinfo.register_unnecesary_request = true;
        }
      }
    }

    if( do_block )
    {
      have_trouble = have_trouble + 1;
      if(testinfo.let_404)
      {
        console.log("Will 404 this request " + req.url);
        res.writeHead(404, {'Content-Type': 'text/html'});
        res.write('Hello World!');  
        res.end();
        return;
      } else if(testinfo.let_drop)
      {
        console.log("Will drop this request " + req.url);
        res.end();
        return;
      } else if(testinfo.let_wrong_header)
      {
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.write('Hello World!');  
        console.log("Will send wrong content this request " + req.url);
        res.end();
        return;
      } else if(testinfo.let_5sec)
      {
        test_timeout = 5*1000;
        console.log("Will make this request delayed for "+test_timeout + "ms, " + req.url);
      } else if(testinfo.let_15sec)
      {
        test_timeout = 15*1000;
        console.log("Will make this request delayed for "+test_timeout + "ms, " + req.url);
      }
    } else {
      if(testinfo.more_log_output)
        console.log("Will make this request delayed for "+test_timeout + "ms, " + req.url);
    }
    
    files_served = files_served + 1;

    setTimeout(function () {
      proxy.web(req, res, {
        target: 'http://localhost:8443',
      });
    }, test_timeout);    // This simulates an operation that takes XXXms to execute
  });

  proxyServer.listen(443);

  var serve = serveStatic(testinfo.serverDir);
  server = http.createServer(function (req, res) {
    var done = finalhandler(req, res);
    serve(req, res, done);
  });

  server.listen(8443);
  
  if(testinfo.more_log_output) 
    console.log('Update server emulator listening at https://' + 'localhost' + ':' + '443');
}

exports.stop_https_update_server = function () {
  proxy.close();
  proxyServer.close();
  server.close()
}
