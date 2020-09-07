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
});

module.exports = router

