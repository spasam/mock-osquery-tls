'use strict';

const assert = require('assert').strict;
const bodyParser = require('body-parser');
const clp = require('clp');
const express = require('express');
const fs = require('fs');
const https = require('https');
const path = require('path');
const pem = require('pem');
const util = require('util');
const { MongoClient, ObjectId } = require('mongodb');

const args = clp(process.argv);
const certs = path.join(__dirname, 'certs');
const createCertificate = util.promisify(pem.createCertificate);

if (args.help) {
  console.info('\nUsage:');
  console.info('\n\tnode', process.argv[1], ' [args...]');
  console.info('\n\t--port <port>    - Port to listen on. Default: 8443');
  console.info('\t--node_key <key> - Shared secret node key. Default: mock-node-key');
  console.info('\t--conf <file>    - Configuration to send to Osquery, basequery, etc. Default: sample.conf');
  console.info('\t--host <name>    - Hostname to use in common name of certificate. Default: localhost');
  console.info('\t--status         - Log status messages to console. Default: false');
  console.info('\t--gen_exit       - Generate certificate/private key if necessary and exit');
  console.info('\t--dr <query>     - Distributed read query to send. Can be repeated for multiple queries. Default: none');
  console.info('\t--delay <ms>     - Delay in milli-seconds between distributed read queries. Default: 12000 ms');
  console.info('\t--skip <count>   - Number of distributed read requests to skip before sending configured queries. Default: 5');
  console.info('\t--mongo <url>    - MongoDB URL. If configured, results will be written to MongoDB instead of console. Default: none');
  console.info('\n\tNOTE:');
  console.info('\t\tMultiple distributed read queries can be specified by repeating "--dr <...>"');
  console.info('\t\t"skip" is the number of distributed read requests to skip before sending one of specified queries');
  console.info('\t\tIf "skip" is 5, one distributed read query is sent every 5 * 12 = 60 seconds\n');
  process.exit(0);
}

let node_key,
  conf = {},
  skip,
  drCount = 0,
  queryIndex = 0,
  drQueries = [],
  mongoDb;

async function init() {
  node_key = args.node_key || 'mock-node-key';
  if (!args.conf) {
    args.conf = 'sample.conf';
  }
  if (fs.existsSync(args.conf)) {
    conf = JSON.parse(fs.readFileSync(args.conf));
  } else {
    console.error('Config file not found:', args.conf);
    process.exit(1);
  }

  skip = args.skip || 5;
  if (skip < 1) {
    skip = 1;
  }

  if (args.dr) {
    if (Array.isArray(args.dr)) {
      drQueries = args.dr;
    } else {
      drQueries.push(dr);
    }
  }

  if (args.mongo) {
    const mongoClient = new MongoClient(args.mongo);
    await mongoClient.connect();
    mongoDb = await mongoClient.db('results');
  }
}

let delay = 12000;
if (args.delay) {
  delay = args.delay;
}

async function createOrGetCertKey() {
  const certPath = path.join(certs, 'cert.pem');
  const keyPath = path.join(certs, 'key.pem');
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    if (args.gen_exit) {
      process.exit(0);
    }
    return { serviceKey: fs.readFileSync(keyPath), certificate: fs.readFileSync(certPath) };
  }

  const certKey = await createCertificate({ commonName: args.host || 'localhost' });
  if (!fs.existsSync(certs)) {
    fs.mkdirSync(certs);
  }
  fs.writeFileSync(certPath, certKey.certificate);
  fs.writeFileSync(keyPath, certKey.serviceKey);

  if (args.gen_exit) {
    process.exit(0);
  }
  return certKey;
}

function getDefaultFormatEntries(json) {
  const results = {};
  if (!json.hasOwnProperty('data') || !Array.isArray(json.data)) {
    console.error(new Date(), 'Unknown log entry: ' + JSON.stringify(json, 0, 2));
    return results;
  }

  json.data.forEach(i => {
    let entry;
    if (i.hasOwnProperty('snapshot')) {
      i.snapshot.forEach(j => {
        entry = Object.assign(i, j);
        entry._id = new ObjectId();
        const table = entry.name;
        delete entry.snapshot;
        delete entry.name;

        if (!results[table]) {
          results[table] = [];
        }
        results[table].push(entry);
      });
    } else if (i.hasOwnProperty('columns')) {
      entry = Object.assign(i, i.columns);
      const table = entry.name;
      entry._id = new ObjectId();
      delete entry.columns;
      delete entry.name;

      if (!results[table]) {
        results[table] = [];
      }
      results[table].push(entry);
    } else {
      console.error(new Date(), 'Unknown log entry: ' + JSON.stringify(i, 0, 2));
    }
  });

  return results;
}

function getV3FormatEntries(json) {
  const results = {};
  if (!json.hasOwnProperty('tables')) {
    console.error(new Date(), 'Unknown log entry: ' + JSON.stringify(json, 0, 2));
    return results;
  }

  for (const table of Object.keys(json.tables)) {
    json.tables[table].forEach(i => {
      let entry;
      if (i.hasOwnProperty('snapshot')) {
        i.snapshot.forEach(j => {
          entry = Object.assign(i, j);
          delete entry.snapshot;
          entry._id = new ObjectId();

          if (!results[table]) {
            results[table] = [];
          }
          results[table].push(entry);
        });
      } else if (i.hasOwnProperty('columns')) {
        entry = Object.assign(i, i.columns);
        delete entry.columns;
        entry._id = new ObjectId();

        if (!results[table]) {
          results[table] = [];
        }
        results[table].push(entry);
      } else {
        console.error(new Date(), 'Unknown log entry: ' + JSON.stringify(i, 0, 2));
      }
    });
  }

  return results;
}

async function writeResults(json) {
  if (!mongoDb) {
    console.info(new Date(), 'Log:', JSON.stringify(json, 0, 2));
    return;
  }

  let results;
  if (json.logger_tls_format === 3) {
    results = getV3FormatEntries(json);
  } else {
    results = getDefaultFormatEntries(json);
  }

  for (const table of Object.keys(results)) {
    console.info(new Date(), `Log: Inserting ${results[table].length} entries into ${table}`);
    const collection = await mongoDb.collection(table);
    await collection.insertMany(results[table]);
  }
}

async function startServer() {
  await init();
  const certKey = await createOrGetCertKey();
  const app = express();
  app.use(bodyParser.json({ limit: '25mb', extended: true }));

  app.post('/enroll', enroll);
  app.post('/config', config);
  app.post('/log', log);
  app.post('/read', dr);
  app.post('/write', dw);

  const port = args.port || 8443;
  https.createServer({ key: certKey.serviceKey, cert: certKey.certificate }, app).listen(port);
  console.info('Listening on port:', port);
}

async function enroll(req, res) {
  console.info(new Date(), 'Enroll:', JSON.stringify(req.body, 0, 2));
  res.json({ node_key, node_invalid: false });
}

async function config(req, res) {
  console.info(new Date(), 'Config:', JSON.stringify(req.body, 0, 2));
  assert.strictEqual(req.body.node_key, node_key, 'Invalid node key: ' + req.body.node_key);
  res.json(conf);
}

async function log(req, res) {
  if (req.body.log_type === 'status') {
    if (args.status) {
      console.info(new Date(), 'Status:', JSON.stringify(req.body, 0, 2));
    }
  } else {
    await writeResults(req.body);
  }
  assert.strictEqual(req.body.node_key, node_key, 'Invalid node key: ' + req.body.node_key);
  res.json({});
}

async function dr(req, res) {
  console.info(new Date(), 'Read:', req.body);
  assert.strictEqual(req.body.node_key, node_key, 'Invalid node key: ' + req.body.node_key);

  if (skip === drCount) {
    const queries = {};
    queries['query' + queryIndex] = drQueries[queryIndex];
    queryIndex++;
    if (queryIndex === drQueries.length) {
      queryIndex = 0;
    }

    console.info(new Date(), 'Query index: ' + queryIndex + '. Sending DR:', JSON.stringify(queries, 0, 2));
    res.json({ queries });
    drCount = 0;
  } else {
    setTimeout(() => {
      drCount++;
      res.json({ queries: {} });
    }, delay);
  }
}

async function dw(req, res) {
  console.info(new Date(), 'Write:', JSON.stringify(req.body, 0, 2));
  assert.strictEqual(req.body.node_key, node_key, 'Invalid node key: ' + req.body.node_key);
  res.json({});
}

startServer();
