const fs = require('fs');

var express = require('express')
var router = express.Router()
router.use(express.json())

/* GET users listing. */
router.get('/', function (req, res, next) {
  res.send('You\'ve come to the array')
})

router.get('/squid', (req, res, next) => {
  res.send('You\'ve come to the Squid!')
})

router.post('/squid', function (req, res, next) {
  arr = req.body
  console.log(arr)
  json_resp = {}
  url_arr = []
  for (i = 0; i < arr.hits.length; i++) {
    url = arr.hits[i]._source.url.full
    domain = arr.hits[i]._source.url.domain
    destination = arr.hits[i]._source.destination.domain
    ip = arr.hits[i]._source.destination.ip
    source = arr.hits[i]._source.source.ip
    b = new Buffer(url)
    urlb64 = (b.toString('base64')).replace(/=/g, '')
    url_arr.push({ url: url, urlb64: urlb64, url_domain: domain, destination_ip: ip, destination_domain: destination, source_ip: source })
  };
  json_resp.array = url_arr
  json_resp.length = arr.hits.length
  res.type('json').send(json_resp)
})

router.post('/host', function (req, res, next) {
  arr = req.body
  console.log(arr)
  json_resp = {}
  hits_arr = []
  for (i = 0; i < arr.hits.length; i++) {
    ipv4 = arr.hits[i]._source.host.ip[0]
    ipv6 = arr.hits[i]._source.host.ip[1]
    hostname = arr.hits[i]._source.host.hostname
    executable = arr.hits[i]._source.process.executable
    sha1 = arr.hits[i]._source.process.hash.sha1
    hits_arr.push({ hostname: hostname, ipv4: ipv4, ipv6: ipv6, executable: executable, sha1: sha1 })
  };
  json_resp.array = hits_arr
  json_resp.length = arr.hits.length
  res.type('json').send(json_resp)
})

router.post('/virustotal', function (req, res, next) {
  arr = req.body
  console.log(arr)
})

router.post('/pihole', function (req, res, next) {
  arr = req.body
  console.log(arr)
  json_resp = {}
  hits_arr = []
  ri_arr = []
  answer_arr = []
  _source_arr = []
  for (i = 0; i < arr.hits.length; i++) {
    _source = arr.hits[i]._source;
    _source_arr.push(_source);
  };
  json_resp.data = _source_arr
  json_resp.length = _source_arr.length
  res.type('json').send(json_resp)
  // write to a new file named 2pac.txt
  fs.writeFile('test_report.txt', JSON.stringify(json_resp), (err) => {
    // throws an error, you could also catch it here
    if (err) throw err;

    // success case, the file was saved
    console.log('Report saved!');
  });
})

module.exports = router
