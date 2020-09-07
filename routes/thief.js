var dateTime = require('node-datetime');
var express = require('express')
const fs = require('fs');
const axios = require('axios');
const { report } = require('../app');
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

  // regex patterns
  var directory_pattern = /(\/)+[a-zA-Z0-9-_\/ ]*$/
  var compressed_file_pattern = /(\/)+[a-zA-Z0-9\-_\/ ]*(.tar.gz)/;
  var url_pattern = /(http|https):\/\/(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])(:[0-9]+)?/

  // get datetime 
  var dt = dateTime.create();
  var formatted_date = dt.format('Y-m-d-H-M-S');
  console.log('datetime: ' + formatted_date);

  // check for compressed files
  var reports = 'REPORT GENERATED AT: ' + formatted_date + "\n"
  console.log(reports);
  console.log("iter\ttar compressed_file\tcurl_compressed_file\ttar host ip\tcurl host ip\tdestination_url");
  for (let i = 0; i < tar_commands.hits.length; i++) {
    // parse tar commands
    tar_process_name = tar_commands.hits[i]._source.process.name;
    tar_process_title = tar_commands.hits[i]._source.process.title;
    tar_host_name = tar_commands.hits[i]._source.host.name;
    tar_host_ipv4 = tar_commands.hits[i]._source.host.ip[0];
    tar_host_ipv6 = tar_commands.hits[i]._source.host.ip[1];
    tar_host_os = tar_commands.hits[i]._source.host.os.name;

    // print if there are any compressed files
    var tar_compressed_file = tar_process_title.match(compressed_file_pattern)[0];
    
    for (let j = 0; j < curl_commands.hits.length; j++) {
      // parse curl commands
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
        // initialize singleton report
        var report = '';

        // extract the destination url
        var directory = tar_process_title.match(directory_pattern)[0];
        var destination_url = curl_process_title.match(url_pattern)[0];
        console.log(i + "\t" + tar_compressed_file + "\t" + curl_compressed_file + "\t" + tar_host_ipv4 + "\t" + curl_host_ipv4 + "\t" + destination_url);

        // host name, host ip, host os, possibly created directory, possible exfiltrated file, possible exfiltration utilities, destination url
        report = report +
                 "----------------------------------------------------------------\n"
                 "host name: " + curl_host_name + "\n" +
                 "host IP: " + curl_host_ipv4 + "\n" +
                 "host OS: " + curl_host_os + "\n" +
                 "possible created directory: " + directory + "\n" +
                 "possible exfiltrated file: " + curl_compressed_file + "\n" +
                 "possible exfiltration utilities: " + curl_process_name + "\n" +
                 "destination URL: " + destination_url + "\n"

        // concatenate singleton report to reports string
        reports = reports + report;
      }
    }
  }
  filename = "thief_" + formatted_date
  fs.appendFile("./reports/" + filename + ".txt", reports, (err) => {
    // throws an error, you could also catch it here
    if (err) throw err;
    // success case, the file was saved
    console.log('Report saved!');
  });
  res.send('See report at http://10.150.0.7:3000/reports/'+ filename + '.txt')
});

module.exports = router

