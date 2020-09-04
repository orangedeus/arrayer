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
          vote = 'no information'
          console.log('default');
      }

      report = report + 
               "threatcrowd_votes: " + vote + "\n"

      // aggregate all reports
      console.log(i)
      reports = reports + report
      //await sleep(10)
    }
    return reports;
  };

  loop(data, reports)
  .then(r => {
    filename = 'pihole_' + formatted_date
    fs.appendFile("./reports/" + filename + ".txt", r, (err) => {
      // throws an error, you could also catch it here
      if (err) throw err;
      // success case, the file was saved
      console.log('Report saved!');
    });
    res.send('See report at http://10.150.0.7:3000/reports/'+ filename + '.txt')
  })
  .catch(err => {
    res.send(err)
  });
});

router.post('/squid', function (req, res, next) {
  data = req.body;
  console.log("iteration "+i)
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
          vote = 'no information'
          console.log('default');
      }
      report = report + 
               "domain_threatcrowd_votes: " + vote + "\n"

      // query threatcrowd API for IP information
      var response = await axios.get('https://www.threatcrowd.org/searchApi/v2/domain/report/?ip=' + destination_ip)
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
          vote = 'no information'
          console.log('default');
      }
      report = report + 
               "IP_threatcrowd_votes: " + vote + "\n"
      
      console.log('VIRUSTOTAL QUERY STARTS HERE SHADJHASNDJHASDJKSAHDKJALSHDJKSALH')

      // virusTotal API get URL information
      var config = {
        method: 'get',
        url: 'https://www.virustotal.com/api/v3/urls/' + url_b64,
        headers: { 'x-apikey': '2770fe15cd6d812d08ee1bfb0c7019d7fccf1e4ce68b0c3c76739e3cc49e5adf' }
      }
      var response = await axios(config);
      stats = reponse.data.data.attributes.last_analysis_stats
      console.log(stats)
      report = report + 
               "virustotal_URL_analysis_stats: \n" +
               "\tharmless: " + stats.harmless + "\n" +
               "\tmalicious: " + stats.malicious + "\n" +
               "\tsuspicious: " + stats.suspicious + "\n" +
               "\ttimeout: " + stats.timeout + "\n" +
               "\tundetected: " + stats.undetected + "\n"

      // // virustotal API get IP information
      // var config = {
      //   method: 'get',
      //   url: 'https://www.virustotal.com/api/v3/ip_addresses/' + destination_ip,
      //   headers: { 'x-apikey': '2770fe15cd6d812d08ee1bfb0c7019d7fccf1e4ce68b0c3c76739e3cc49e5adf' }
      // }
      // var response = await axios(config);

      // stats = reponse.data.data.attributes.last_analysis_stats
      // console.log(stats)
      // report = report + 
      //          "virustotal_IP_analysis_stats: \n" +
      //          "\tharmless: " + stats.harmless + "\n" +
      //          "\tmalicious: " + stats.malicious + "\n" +
      //          "\tsuspicious: " + stats.suspicious + "\n" +
      //          "\ttimeout: " + stats.timeout + "\n" + 
      //          "\tundetected: " + stats.undetected + "\n"

      // // virustotal API get Domain information
      // var config = {
      //   method: 'get',
      //   url: 'https://www.virustotal.com/api/v3/domains/' + url_domain,
      //   headers: { 'x-apikey': '2770fe15cd6d812d08ee1bfb0c7019d7fccf1e4ce68b0c3c76739e3cc49e5adf' }
      // }
      // var response = await axios(config);

      // stats = reponse.data.data.attributes.last_analysis_stats
      // report = report + 
      //          "virustotal_IP_analysis_stats: \n" +
      //          "\tharmless: " + stats.harmless + "\n" +
      //          "\tmalicious: " + stats.malicious + "\n" +
      //          "\tsuspicious: " + stats.suspicious + "\n" +
      //          "\ttimeout: " + stats.timeout + "\n" +
      //          "\tundetected: " + stats.undetected + "\n"


      // aggregate all reports
      
      reports = reports + report
      //await sleep(10)
    }
    return reports;
  }

  loop(data, reports)
  .then(r => {
    filename = "squid_" + formatted_date
    fs.appendFile("./reports/" + filename + ".txt", r, (err) => {
      // throws an error, you could also catch it here
      if (err) throw err;
      // success case, the file was saved
      console.log('Report saved!');
    });
    res.send('See report at http://10.150.0.7:3000/reports/'+ filename + '.txt')
  })
  .catch(err => {
    res.send(err)
  });
});

router.post('/virustotal', function (req, res, next) {
  data = req.body;
  console.log(data);

  var vt_responses = [];

  const loop = async function(data, responses) {
    // parse data
    for (let i=0; i < data.length; i++) {
      var source_ip = data[i].source.ip;
      var destination_ip = data[i].destination.ip;
      var destination_domain = data[i].destination.domain;
      var url_domain = data[i].url.domain;
      var url_full = data[i].url.full;
      // optional: encode url to base64
      var b = new Buffer(url_full)
      var url_b64 = (b.toString('base64')).replace(/=/g, '')

      const config = {
        method: 'get',
        url: 'https://www.virustotal.com/api/v3/urls/' + url_b64,
        headers: { 'x-apikey': '2770fe15cd6d812d08ee1bfb0c7019d7fccf1e4ce68b0c3c76739e3cc49e5adf' }
      }

      var response = await axios(config);
      responses.push(response.data.data.attributes.last_analysis_stats)

      console.log(response.data)
    }
    return responses
  }

  loop(data, vt_responses)
  .then(r => {
    // filename = "squid_" + formatted_date
    // fs.appendFile("./reports/" + filename + ".txt", r, (err) => {
    //   // throws an error, you could also catch it here
    //   if (err) throw err;
    //   // success case, the file was saved
    //   console.log('Report saved!');
    // });
    // res.send('See report at http://10.150.0.7:3000/reports/'+ filename + '.txt')
    console.log(r)
    res.send('Trying out virustotal API')
  })
  .catch(err => {
    res.send(err)
  });
});


module.exports = router
