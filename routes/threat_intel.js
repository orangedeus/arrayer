var dateTime = require('node-datetime');
var express = require('express')
const fs = require('fs');
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

  // iterate through list of _source
  for (let i=0; i < data.length; i++) {
    // get datetime 
    var dt = dateTime.create();
    var formatted_date = dt.format('Y-m-d-H-M-S');
    console.log('datetime: ' + formatted_date);

    // parse data
    var source_ip = data[i]._source.source.ip
    var dns_question_name = data[i].dns.question.name
    var answers_count = data[i].dns.answers_count
    if (answers_count > 0) {
      var resolved_ip = data[i].dns.resolved_ip
    }

    var report = "-------------------------------------\n" +
                 "source: " + source_ip + "\n" +
                 "question: " + dns_question_name + "\n" +
                 "-------------------------------------\n"

    // TODO: query virustotal API
    // create report
    fs.appendFile("./reports/" + formatted_date + ".txt", report, (err) => {
      // throws an error, you could also catch it here
      if (err) throw err;

      // success case, the file was saved
      console.log('Report saved!');
    });
  }

  const response = {
    message: 'See Reports at reports directory'
  }
  res.type('json').send(response)

})

//router.post('/threat_crowd/ip')

module.exports = router
