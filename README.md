# Mock Osquery TLS server

This is a mock TLS server for testing Osquery TLS plugins. It supports enroll, config, log and distributed read/write. Requests/responses are logged to console.

## TLS Server Usage

To get started, just run `index.js`. By default, it will start listening onport 8443:

```sh
npm install
node index.js
```

Listen port can be changed by passing `--port` argument

Osquery configuration can be saved in a file and the path to the file can be passed using `--conf` argument

Distributed queries can also be provided to Osquery. One or more `--dr` argument can be used to provide distributed queries. Distributed read response is sent back 12 seconds after the request is received, unless there is a query to be sent.

`--skip` argument can be used to indicate how many iterations of distributed read requests should be ignored before sending the next query. By default `skip` is set to `5` which means a query (if specified) will be sent every 5th request.

For example:
```sh
node index.js --port 8080 --conf /tmp/osquery.conf \
     --dr "SELECT * FROM time" \
     --dr "SELECT * FROM system_info" \
     --skip 10
```

* HTTPS server Will listen on port 8080
* Send /tmp/osquery.conf contents in response to config request
* Sends a distributed query every 10 distributed read requests
* 10th distributed read request will be "SELECT * FROM time"
* 20th distributed read request will be "SELECT * FROM system_info"
* 30th distributed read request will be "SELECT * FROM time"
* ...

Self-signed private key, certificate will be created in `certs` directory.

### Osquery Usage

First mock TLS server should be started. Osquery should be started with the following flags. Port number in TLS hostname should be changed to match the TLS server port.

```sh
--tls_hostname=localhost:8443
--tls_server_certs=<path-to>/mock-osquery-tls/certs/cert.pem
--config_plugin=tls
--logger_plugin=tls
--distributed_plugin=tls
--enroll_tls_endpoint=/enroll
--config_tls_endpoint=/config
--logger_tls_endpoint=/log
--distributed_tls_read_endpoint=/read
--distributed_tls_write_endpoint=/write
--disable_distributed=false
```

If you prefer no delay between distributed read requests, following flag can be used: `--distributed_interval=0`
