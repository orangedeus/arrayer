
var express = require('express');
var router = express.Router();
router.use(express.json());

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('You\'ve come to the array');
});

router.post('/', function(req, res, next) {
  arr = req.body;
  console.log(arr);
  json_resp = {};
  url_arr = []
  for (i = 0; i < arr.hits.length; i++) {
    url = arr.hits[i]._source.url.full;
    ip = arr.hits[i]._source.destination.ip;
    b = new Buffer(url);
    urlb64 = (b.toString('base64')).replace(/=/g, '');
    url_arr.push({'url': url, 'ip': ip, 'urlb64': urlb64});
  };
  json_resp['array'] = url_arr;
  json_resp['length'] = arr.hits.length;
  res.type('json').send(json_resp);
});

module.exports = router;
