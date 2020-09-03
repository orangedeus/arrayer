var dateTime = require('node-datetime');
var express = require('express')
const fs = require('fs');
var router = express.Router()
router.use(express.json())


/* GET users listing. */
router.get('/', function (req, res, next) {
  res.send('You\'ve come to the threat intel api')
})

router.post('/virustotal', function (req, res, next) {
  body = req.body;
  console.log(body);

  // get datetime 
  var dt = dateTime.create();
  var formatted = dt.format('Y-m-d-H-M-S');
  console.log('datetime: ' + formatted_date);
  // query virustotal API
  // create report
  fs.writeFile('reports/test_report.txt', JSON.stringify(body), (err) => {
    // throws an error, you could also catch it here
    if (err) throw err;

    // success case, the file was saved
    console.log('Report saved!');
  });

  const response = {
    message: 'Should be some IP'
  }
  res.type('json').send(response)

})

router.post('/threat_crowd/ip')

module.exports = router