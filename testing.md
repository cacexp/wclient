# Testing

## Pre-requisites

Some tests use a local echo service. The echo service is hosted on a [Docker](https://docker.io) container.

To start the container execute:

```bash

$  docker run -d -p 80:80 -p 443:443 --rm -t mendhak/http-https-echo

```

## Run the tests
To run test just execute:

```bash

$ cargo test

```