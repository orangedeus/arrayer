var dateTime = require('node-datetime');
var express = require('express')
var urlRegex = require('url-regex');
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
    console.log('===== REGISTERED IP =====');
    console.log(registered_ip);
    // var exceeded = {};
    // Object.keys(registered_ip).forEach(async function(key) {
    //     if (registered_ip[key] > 10) {
    //         // TODO: query asset inventory
    //         var asset_query = {
    //             "query": {
    //               "bool": {
    //                 "must": [
    //                   {
    //                     "match": {
    //                       "ip": key
    //                     }
    //                   }
    //                 ]
    //               }
    //             }
    //           }
    //         var response = await axios('http://10.150.0.6:9200/asset_inventory/_search?', {method: "post",data: asset_query});
    //         console.log(response);
    //         var asset_info = response.data.hits.hits[0]._source
    //         console.log('ASSET INFO')
    //         console.log(asset_info)
    //         exceeded[key] = asset_info;
    //     }
    // });

    // console.log('EXCEEDED')
    // console.log(exceeded)

    var dt = dateTime.create();
    var formatted_date = dt.format('Y-m-d-H-M-S');

    const exceed = async function(registered_ip) {
        var exceeded = {};
        for (const key of Object.keys(registered_ip)) {
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
                var response = await axios('http://10.150.0.6:9200/asset_inventory/_search?', { method: "post", data: asset_query });
                var asset_info = response.data.hits.hits[0]._source
                console.log('===== ASSET INFO =====')
                console.log(asset_info)
                exceeded[key] = asset_info;
            }
        }
        return exceeded
    }

    const loop = async function (exceeded) {
        
        var reports = 'REPORT GENERATED AT: ' + formatted_date + "\n"
        
        for (let i=0; i<data.hits.length; i++) {
            // initialize singleton report
            var report = '';

            // parse data
            var source = data.hits[i]._source.source;
            var destination = data.hits[i]._source.destination;
            var dns_question = data.hits[i]._source.dns.question; 
            var dns_answers_count = data.hits[i]._source.dns.answers_count;
            var tc_response = await axios.get('https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=' + dns_question.name);
            
            var vote = ''
            switch(tc_response.data.votes) {
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
            
            // var vt_config = {
            //     method: 'get',
            //     url: 'https://www.virustotal.com/api/v3/domains/' + dns_question.name,
            //     headers: { 'x-apikey': '2770fe15cd6d812d08ee1bfb0c7019d7fccf1e4ce68b0c3c76739e3cc49e5adf' }
            // }
            // var vt_response = await axios(vt_config);
            // var stats = vt_response.data.data.attributes.last_analysis_stats;
            // generate report
            report = report +
                     "------------------------------------------------------------------------------------------------------\n" + 
                     "===== HOST INFORMATION =====\n" +
                     "source IP: " + exceeded[source.ip].ip + "\n" +
                     "source OS: " + exceeded[source.ip].os + "\n" +
                     "source hostname: " + exceeded[source.ip].host + "\n" +
                     "destination IP: " + destination.ip + "\n" +
                     "===== THREAT INTEL REPORT =====\n" +
                     "domain: " + dns_question.name + "\n" +
                     "threatcrowd votes: " + vote + "\n" +
                    //  "virustotal_domain_analysis_stats: \n" +
                    //  "    harmless: " + stats.harmless + "\n" +
                    //  "    malicious: " + stats.malicious + "\n" +
                    //  "    suspicious: " + stats.suspicious + "\n" +
                    //  "    timeout: " + stats.timeout + "\n" +
                    //  "    undetected: " + stats.undetected + "\n" +
                     "===== DNS TRANSACTION =====\n" +
                     "question name: " + dns_question.name + "\n" +
                     "question type: " + dns_question.type + "\n" +
                     "answers count: " + dns_answers_count + "\n"
            
            // TODO: check DNS answers for base64 encoded URLs
            if (dns_answers_count > 0) {
                report = report + "answers:\n"
                base64pattern = /(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})/
                dns_answers = data.hits[i]._source.dns.answers;
                for (let j=0; j<dns_answers.length; j++) {
                    report = report + (j + 1).toString() + ":\n"
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
                             "\t" + "type: " + dns_answers[j].type + "\n" +
                             "\t" + "name: " + dns_answers[j].name + "\n" +
                             "\t" + "data: " + dns_answers[j].data + "\n" +
                             "\t" + "base64 decoded: " + decoded + "\n"
                }
            }
            console.log('===== SINGLE REPORT =====');
            console.log(report);

            reports = reports + report;
        }
        console.log('===== COMPLETED REPORTS =====');
        console.log(reports);
        return reports;
    }

    exceed(registered_ip)
    .then(exceeded => {
        console.log('===== EXCEEDED =====');
        console.log(exceeded);
        if (!Object.keys(exceeded).length) {
            res.send("zero machines have exceeded set threshold.");
        } else {
            loop(exceeded)
                .then(r => {
                    filename = 'dns_' + formatted_date;
                    fs.appendFile("./reports/" + filename + ".txt", r, (err) => {
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
    })
})

module.exports = router

