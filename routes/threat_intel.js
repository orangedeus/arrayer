var dateTime = require('node-datetime');
var express = require('express')
const fs = require('fs');
const axios = require('axios')
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
  var report, vote
  var reports = [];
  var votes = [];
  // iterate through list of _source
  for (let i=0; i < data.length; i++) {
    // get datetime 
    var dt = dateTime.create();
    var formatted_date = dt.format('Y-m-d-H-M-S');
    console.log('datetime: ' + formatted_date);

    // parse data
    var source_ip = data[i].source.ip
    var dns_question_name = data[i].dns.question.name
    var answers_count = data[i].dns.answers_count
    if (data[i].dns.resolved_ip != undefined) {
      var resolved_ip = 
    }

    // TODO: query threatcrowd API
    axios
      .get('https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=' + dns_question_name)
      .then(response => {
        //console.log(response.data);
        console.log(response.data.votes);
        report = "-----------------------------------------------------------\n" +
             "source: " + source_ip + "\n" +
             "question: " + dns_question_name + "\n" +
             "threatcrowd votes: " + response.data.votes + "\n"
        fs.writeFile('.txt', JSON.stringify(json_resp), (err) => {
          // throws an error, you could also catch it here
          if (err) throw err;

          // success case, the file was saved
          console.log('Report saved!');
        });
      })
      .catch(error => {
        console.log(error);
      });
  }

  const response = {
    message: 'See Reports at reports directory'
  }
  res.type('json').send(response)

})

//router.post('/threat_crowd/ip')

module.exports = router
