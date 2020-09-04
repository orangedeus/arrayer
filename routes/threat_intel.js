var dateTime = require('node-datetime');
var express = require('express')
const fs = require('fs');
const axios = require('axios');
const { RequestHeaderFieldsTooLarge } = require('http-errors');
//const { report } = require('../app');
var router = express.Router()
router.use(express.json())


/* GET users listing. */
router.get('/', function (req, res, next) {
  res.send('You\'ve come to the threat intel api')
})

router.post('/pihole', function (req, res, next) {
  data = req.body;
  console.log(data);
  var reports = '';

  // get datetime 
  var dt = dateTime.create();
  var formatted_date = dt.format('Y-m-d-H-M-S');
  console.log('datetime: ' + formatted_date);
  const sleep = (ms) => {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  // iterate through list of _source
  const loop = async function() {
    reports = reports + 'REPORT GENERATED AT: ' + formatted_date + "\n"
    var report = ''
    console.log("YOOOOOOOOOOOOOOO: " + data.length)
    for (let i = 0; i < data.length; i++) {
      // parse data
      report = ''
      var source_ip = data[i].source.ip
      var dns_question_name = data[i].dns.question.name
      var answers_count = data[i].dns.answers_count

      // report generation
      report = report + 
                   "--------------------------------------------------\n" +
                   "source: " + source_ip + "\n" +
                   "question: " + dns_question_name + "\n" + 
                   "answers_count: " + answers_count + "\n" 
      if (data[i].dns.resolved_ip != undefined) {
        var resolved_ip = data[i].dns.resolved_ip
        report = report + "resolved_ip: " + resolved_ip.toString() + "\n"
      }

      // query threatcrowd API
      var response = await axios.get('https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=' + dns_question_name)

      var vote = ''
      switch(response.data.votes) {
        case -1: 
          vote = 'malicious'
          break;
        case 0:
          vote = 'neutral'
          break;
        case 1:
          vote = 'non-malicious'
          break;
        default:
          console.log('default');
      }

      report = report + 
               "threatcrowd_votes: " + response.data.votes + "\n"

      // aggregate all reports
      console.log(i)
      reports = reports + report
      //await sleep(10)
    }
    return reports;
  };

  loop(data, reports)
  .then(r => {
    fs.appendFile("./reports/" + formatted_date + ".txt", r, (err) => {
      // throws an error, you could also catch it here
      if (err) throw err;
      // success case, the file was saved
      console.log('Report saved!');
    });
    res.send('See report at http://10.150.0.7:3000/reports/'+formatted_date+'.txt')
  })
  .catch(err => {
    res.send(err)
  });
});

router.post('/squid', function (req, res, next) {
  data = req.body;
  console.log(data);
  var reports = '';

  // get datetime 
  var dt = dateTime.create();
  var formatted_date = dt.format('Y-m-d-H-M-S');
  console.log('datetime: ' + formatted_date);
  const sleep = (ms) => {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // iterate through list of _source
  const loop = async function() {
    reports = reports + 'REPORT GENERATED AT: ' + formatted_date + "\n"
    console.log(reports)
    var report = ''
    for (let i = 0; i < data.length; i++) {
      // initialize report
      report = ''

      // parse data
      var source_ip = data[i].source.ip;
      var destination_ip = data[i].destination.ip;
      var destination_domain = data[i].destination.domain;
      var url_domain = data[i].url.domain;
      var url_full = data[i].url.full;
      // optional: encode url to base64
      var b = new Buffer(url_full)
      var url_b64 = (b.toString('base64')).replace(/=/g, '')

      // report generation
      report = report + 
                   "--------------------------------------------------\n" +
                   "source ip: " + source_ip + "\n" +
                   "destination_ip: " + destination_ip + "\n" +
                   "destination_domain: " + destination_domain + "\n" +
                   "url_domain " + url_domain + "\n" + 
                   "url_full: " + url_full + "\n" +
                   "url_b64: " + url_b64 + "\n"

      // query threatcrowd API for domain information
      var response = await axios.get('https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=' + url_domain)
      var vote = (data)
      switch(response.data.votes) {
        case -1: 
          vote = 'malicious'
          break;
        case 0:
          vote = 'neutral'
          break;
        case 1:
          vote = 'non-malicious'
          break;
        default:
          vote = 'no information'
          console.log('default');
      }
      report = report + 
               "domain_threatcrowd_votes: " + vote + "\n"

      // query threatcrowd API for IP information
      var response = await axios.get('https://www.threatcrowd.org/searchApi/v2/domain/report/?ip=' + destination_ip)
      var vote = (data)
      switch(response.data.votes) {
        case -1: 
          vote = 'malicious'
          break;
        case 0:
          vote = 'neutral'
          break;
        case 1:
          vote = 'non-malicious'
          break;
        default:
          vote = 'no information'
          console.log('default');
      }
      report = report + 
               "IP_threatcrowd_votes: " + vote + "\n"


      // aggregate all reports
      console.log("iteration "+i)
      reports = reports + report
      //await sleep(10)
    }
    return reports;
  }

  loop(data, reports)
  .then(r => {
    fs.appendFile("./reports/" + "squid_" + formatted_date + ".txt", r, (err) => {
      // throws an error, you could also catch it here
      if (err) throw err;
      // success case, the file was saved
      console.log('Report saved!');
    });
    res.send('See report at http://10.150.0.7:3000/reports/'+ "squid_" + formatted_date + '.txt')
  })
  .catch(err => {
    res.send(err)
  });
});


module.exports = router
