var dateTime = require('node-datetime');
var express = require('express')
const fs = require('fs');
const axios = require('axios');
var router = express.Router()
router.use(express.json())

router.get('/', function (req, res, next) {
    res.send('You\'ve come to the thief detection API')
});

router.post('/check', function (req, res, next) {
    data = req.body;
    console.log(data);

    var registered_ip = {};
    for (let i=0; i<data.hits.length; i++) {
        var source_ip = data.hits[i]._source.source.ip;
        if (!registered_ip.hasOwnProperty(source_ip)) {
            registered_ip[source_ip] = 0;
        }
        registered_ip[source_ip] += 1;
    }
    console.log(registered_ip);
    var exceeded = {};
    Object.keys(registered_ip).forEach(async function(key) {
        if (registered_ip[key] > 10) {
            // TODO: query asset inventory
            var asset_query = {
                "query": {
                  "bool": {
                    "must": [
                      {
                        "match": {
                          "ip": key
                        }
                      }
                    ]
                  }
                }
              }
            var response = await axios('http://10.150.0.6:9200/asset_inventory/_search?', {method: "post",data: asset_query});
            console.log(response);
            var asset_info = response.data.hits.hits[0]._source
            console.log('ASSET INFO')
            console.log(asset_info)
            exceeded[key] = asset_info;
        }
    });

    console.log('EXCEEDED')
    console.log(exceeded)

    const loop = async function (exceeded) {
        var dt = dateTime.create();
        var formatted_date = dt.format('Y-m-d-H-M-S');
        var reports = 'REPORT GENERATED AT: ' + formatted_date + "\n"
        
        for (let i=0; i<data.hits.length; i++) {
            // initialize singleton report
            var report = '';

            // parse data
            var source = data.hits[i]._source.source;
            var destination = data.hits[i]._source.destination;
            var dns_question = data.hits[i]._source.dns.question; 
            var dns_answers_count = data.hits[i]._source.dns.answers_count;

            // generate report
            report = report +
                     "source IP: " + exceeded[source.ip].ip + "\n" +
                     "source OS: " + exceeded[source.ip].os + "\n" +
                     "source hostname: " + exceeded[source.ip].hostname + "\n" +
                     "destination IP: " + destination.ip + "\n" + 
                     "question name: " + dns_question.name + "\n" +
                     "question type: " + dns_question.type + "\n" +
                     "answers count" + dns_answers_count + "\n"
            
            // TODO: check DNS answers for base64 encoded URLs
            if (answers_count > 0) {
                base64pattern = /(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})/
                report = report + "answer type\tanswer name\tanswer data\tbase64 decoded\n"
                dns_answers = data.hits[i]._source.dns.answers;
                for (let j=0; j<dns_answers.length; j++) {
                    var match = dns_answers[j].data.match(base64pattern);
                    if (match) {
                        // decode
                        var decoded = Buffer.from(match[0], 'base64').toString();
                        //
                    } else {
                        var decoded = 'not applicable'
                    }

                    // generate report
                    report = report + 
                             dns_answers[j].type + "\t" +
                             dns_answers[j].name + "\t" +
                             dns_answers[j].data + "\t" +
                             decoded + "\n"
                }
            }
            console.log('SINGLE REPORT');
            console.log(report);

            reports = reports + report;
        }
        console.log('COMPLETED REPORTS');
        console.log(reports);
        return reports;
    }

    if (!Object.keys(exceeded).length) {
        res.send("zero machines have exceeded set threshold.");
    } else {
        loop(exceeded)
        .then(r => {
            filename = 'dns_' + formatted_date;
            fs.appendFile("./reports/" + filename + ".txt", reports, (err) => {
                // throws an error, you could also catch it here
                if (err) throw err;
                // success case, the file was saved
                console.log('Report saved!');
            });
            res.send('See report at http://10.150.0.7:3000/reports/' + filename + '.txt')
        })
        .catch(err => {
            console.log(err);
        });
    }




    res.send('Checking for DNS attacks');
})

module.exports = router

