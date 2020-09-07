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
  console.log("iter\ttar compressed_file\tcurl_compressed_file\ttar host ip\tcurl host ip\tdestination_url");
  for (let i = 0; i < tar_commands.hits.length; i++) {
    tar_process_name = tar_commands.hits[i]._source.process.name;
    tar_process_title = tar_commands.hits[i]._source.process.title;
    tar_host_name = tar_commands.hits[i]._source.host.name;
    tar_host_ipv4 = tar_commands.hits[i]._source.host.ip[0];
    tar_host_ipv6 = tar_commands.hits[i]._source.host.ip[1];
    tar_host_os = tar_commands.hits[i]._source.host.os.name;

    // print if there are any compressed files
    var compressed_file_pattern = /(\/)+[a-zA-Z0-9\-_\/ ]*(.tar.gz)/;
    var tar_compressed_file = tar_process_title.match(compressed_file_pattern)[0];
    
    for (let j = 0; j < curl_commands.hits.length; j++) {
      curl_process_name = curl_commands.hits[j]._source.process.name;
      curl_process_title = curl_commands.hits[j]._source.process.title;
      curl_host_name = curl_commands.hits[j]._source.host.name;
      curl_host_ipv4 = curl_commands.hits[j]._source.host.ip[0];
      curl_host_ipv6 = curl_commands.hits[j]._source.host.ip[1];
      curl_host_os = curl_commands.hits[j]._source.host.os.name;

      // search for any compressed files
      var curl_compressed_file = curl_process_title.match(compressed_file_pattern)[0];
      // console.log(i + "\t" + tar_compressed_file + "\t" + curl_compressed_file + "\t" + tar_host_ipv4 + "\t" + curl_host_ipv4);

      if (tar_host_ipv4 == curl_host_ipv4) {
        // extract the destination url
        var url_pattern = /(http|https):\/\/(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])(:[0-9]+)?$/
        var destination_url = curl_process_title.match(url_pattern);
        console.log(i + "\t" + tar_compressed_file + "\t" + curl_compressed_file + "\t" + tar_host_ipv4 + "\t" + curl_host_ipv4 + "\t" + destination_url);
      }
    }
  }


  res.send('42069');
});

module.exports = router

