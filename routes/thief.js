var dateTime = require('node-datetime');
var express = require('express')
const fs = require('fs');
const axios = require('axios')
var router = express.Router()
router.use(express.json())

/* GET users listing. */
router.get('/', function (req, res, next) {
  res.send('You\'ve come to the thief detection API')
});

router.post('/check', function (req, res, next) {
  data = req.body;
  console.log(data);

  var tar_commands, curl_commands;
  tar_commands = data.tar;
  curl_commands = data.curl;

  // check for compressed files
  console.log("iter\ttar compressed_file\tcurl_compressed_file");
  for (let i = 0; i < tar_commands.hits.length; i++) {
    process_name = tar_commands.hits[i]._source.process.name;
    process_title = tar_commands.hits[i]._source.process.title;
    host_name = tar_commands.hits[i]._source.host.name;
    host_ipv4 = tar_commands.hits[i]._source.host.ip[0];
    host_ipv6 = tar_commands.hits[i]._source.host.ip[1];
    host_os = tar_commands.hits[i]._source.host.os.name;

    // print if there are any compressed files
    var compressed_file_pattern = /(\/)+[a-zA-Z0-9\-_\/ ]*(.tar.gz)/;
    tar_compressed_file = tar_process_title.match(compressed_file_pattern)[0];
    
    for (let j = 0; j < curl_commands.hits; j++) {
      curl_process_name = curl_commands.hits[i]._source.process.name;
      curl_process_title = curl_commands.hits[i]._source.process.title;
      curl_host_name = curl_commands.hits[i]._source.host.name;
      curl_host_ipv4 = curl_commands.hits[i]._source.host.ip[0];
      curl_host_ipv6 = curl_commands.hits[i]._source.host.ip[1];
      curl_host_os = curl_commands.hits[i]._source.host.os.name;

      // search for any compressed files
      var curl_compressed_file = curl_process_title.match(compressed_file_pattern);
      console.log(i + "\t" + tar_compressed_file + "\t" + curl_compressed_file);
    }
  }


  res.send('42069');
});

module.exports = router

