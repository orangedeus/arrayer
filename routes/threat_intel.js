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
    if (answers_count > 0) {
      var resolved_ip = data[i].dns.resolved_ip
    }

    var report = "-----------------------------------------------------------\n" +
                 "source: " + source_ip + "\n" +
                 "question: " + dns_question_name + "\n" 

    // TODO: query threatcrowd API
    axios
      .get('https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=' + dns_question_name)
      .then(response => {
        //console.log(response.data);
        console.log(response.data.votes);
        report = report + "threatcrowd votes: " + response.data.votes + "\n"

        // write report
        fs.appendFile("./reports/" + formatted_date + ".txt", report, (err) => {
          // throws an error, you could also catch it here
          if (err) throw err;
          console.log(report);
          // success case, the file was saved
          console.log('Report saved!');
        });
        
      })
      .catch(error => {
        console.log(error);
      });


    // create report
    

  }

  const response = {
    message: 'See Reports at reports directory'
  }
  res.type('json').send(response)

})

//router.post('/threat_crowd/ip')

module.exports = router
