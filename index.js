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

const args = clp(process.argv);
const certs = path.join(__dirname, 'certs');
const createCertificate = util.promisify(pem.createCertificate);

if (args.help) {
  console.info('Usage:');
  console.info('\tnode', process.argv[1], ' [--help] [--port <port>] [--conf <config-file>] [--dr <distributed-read-query>] [--skip <count>]');
  console.info('\n\tNOTE:');
  console.info('\t\tMultiple distributed read queries can be specified by repeating "--dr <...>"');
  console.info('\t\t"skip" is the number of distributed read requests to skip before sending one of specified queries');
  console.info('\t\tIf "skip" is 5, one distributed read query is sent every 5 * 12 = 60 seconds');
  process.exit(0);
}

const node_key = args.node_key || 'mock-node-key';
let conf = {};
if (args.conf) {
  if (fs.existsSync(args.conf)) {
    conf = JSON.parse(fs.readFileSync(args.conf));
  } else {
    console.error('Config file not found:', args.conf);
    process.exit(1);
  }
}

let skip = args.skip || 5;
if (skip < 1) {
  skip = 1;
}

let drCount = 0, queryIndex = 0;
let drQueries = [];
if (args.dr) {
  if (Array.isArray(args.dr)) {
    drQueries = args.dr;
  } else {
    drQueries.push(dr);
  }
}

async function createOrGetCertKey() {
  const certPath = path.join(certs, 'cert.pem');
  const keyPath = path.join(certs, 'key.pem');
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    return {serviceKey: fs.readFileSync(keyPath), certificate: fs.readFileSync(certPath)};
  }

  const certKey = await createCertificate({commonName: 'localhost'});
  fs.writeFileSync(certPath, certKey.certificate);
  fs.writeFileSync(keyPath, certKey.serviceKey);

  return certKey;
}

async function startServer() {
  const certKey = await createOrGetCertKey();
  const app = express();
  app.use(bodyParser.json());

  app.post('/enroll', enroll);
  app.post('/config', config);
  app.post('/log', log);
  app.post('/read', dr);
  app.post('/write', dw);

  const port = args.port || 8443;
  https.createServer({ key: certKey.serviceKey, cert: certKey.certificate }, app).listen(port);
  console.info('Listening on port:', port);
}

function enroll(req, res) {
  console.info(new Date(), 'Enroll:', JSON.stringify(req.body, 0, 2));
  res.json({node_key, node_invalid: false});
}

function config(req, res) {
  console.info(new Date(), 'Config:', JSON.stringify(req.body, 0, 2));
  assert.strictEqual(req.body.node_key, node_key, 'Invalid node key: ' + req.body.node_key);
  res.json(conf);
}

function log(req, res) {
  if (req.body.log_type !== 'status') {
    console.info(new Date(), 'Log:', JSON.stringify(req.body, 0, 2));
  }
  assert.strictEqual(req.body.node_key, node_key, 'Invalid node key: ' + req.body.node_key);
  res.json({});
}

function dr(req, res) {
  console.info(new Date(), 'Read:', JSON.stringify(req.body, 0, 2));
  assert.strictEqual(req.body.node_key, node_key, 'Invalid node key: ' + req.body.node_key);

  drCount++;
  if (skip === drCount) {
    const queries = {};
    queries['query' + queryIndex] = drQueries[queryIndex];
    res.json({ queries });

    queryIndex++;
    if (queryIndex === queries.length) {
      queryIndex = 0;
    }
    drCount = 0;
  } else {
    setTimeout(() => res.json({ queries: {} }), 12000);
  }
}

function dw(req, res) {
  console.info(new Date(), 'Write:', JSON.stringify(req.body, 0, 2));
  assert.strictEqual(req.body.node_key, node_key, 'Invalid node key: ' + req.body.node_key);
  res.json({});
}

startServer();
