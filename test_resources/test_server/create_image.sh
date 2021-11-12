#!/bin/bash
cp ../test-ca/ca.crt .
cp ../test-ca/full_server.crt .
cp ../test-ca/server.key .
docker image build -t test-nginx .