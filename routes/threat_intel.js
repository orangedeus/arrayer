var express = require('express')
var router = express.Router()
router.use(express.json())

/* GET users listing. */
router.get('/', function (req, res, next) {
  res.send('You\'ve come to the threat intel api')
})

router.post('/virustotal/ip', function(req, res, next) {
    body = req.body;
    console.log(body);
    const response = {
        message: 'Should be some IP'
    }
    res.type('json').send(response)

})

module.exports = router