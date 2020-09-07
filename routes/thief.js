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
    for (let i=0; i<tar_commands.hits.length; i++) {
        process_name = tar_commands.hits[i]._source.process.name;
        process_title = tar_commands.hits[i]._source.process.title;
        host_name = tar_commands.hits[i]._source.host.name;
        host_ipv4 = tar_commands.hits[i]._source.host.ip[0];
        host_ipv6 = tar_commands.hits[i]._source.host.ip[1];
        host_os = tar_commands.hits[i]._source.host.os.name;

        // print if there are any compressed files
        var compressed_file_pattern = /(/)+[a-zA-Z0-9\-_/ ]*(.tar.gz)/;
        compressed_file_match = process_title.match(compressed_file_pattern)[0];
        console.log("compressed_file " + i + ": " + compressed_file_match);
    }


    res.send('42069');
});

module.exports = router

