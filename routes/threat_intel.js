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

router.post('/virustotal', function (req, res, next) {
  data = req.body;
  console.log(data);
  var reports = '';
  // iterate through list of _source
  const loop = async function() {
    for (let i = 0; i < data.length; i++) {
      // get datetime 
      var dt = dateTime.create();
      var formatted_date = dt.format('Y-m-d-H-M-S');
      console.log('datetime: ' + formatted_date);

      // parse data
      var source_ip = data[i].source.ip
      var dns_question_name = data[i].dns.question.name
      var answers_count = data[i].dns.answers_count
      var resolved_ip = data[i].dns.resolved_ip

      // report generation
      var report = "-----------------------------------------------------------\n" +
                   "source: " + source_ip + "\n" +
                   "question: " + dns_question_name + "\n"
                   "resolved_ip: " + resolved_ip.toString() + "\n"

      // query threatcrowd API
      var response = await axios.get('https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=' + dns_question_name)
      report = report 
               "threatcrowd_votes: " + response.data.votes + "\n"

      // aggregate all reports
      reports = reports + report + "\n"
      console.log(reports)

      fs.appendFile("./reports/" + formatted_date + ".txt", report, (err) => {
        // throws an error, you could also catch it here
        if (err) throw err;
        // success case, the file was saved
        console.log('Report saved!');
      });
    }
    return reports;
  };

  loop(data, reports).then(r => {
    // const response = {
    //   message: r
    // }
    // res.type('json').send(response)
    res.send(r)
  });
});
//router.post('/threat_crowd/ip')

module.exports = router
