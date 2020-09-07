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
        console.log(tar_commands.hits[i].process.title);
    }


    res.send('42069');
});

module.exports = router

