# Testing

## Pre-requisites

Some tests use services hosted on [Docker](https://docker.io) containers. Please, make sure you have installed at least `docker-ce` and `docker-compose`.

## Build the containers
Before testing, please create the container image:

```bash
$ cd test_resources/test_server
$ docker-compose build
```

## Start the containers

To start the container in foreground with logs execute:

```bash
$ cd test_resources/test_server
$ docker-compose up
```

To execute the containers in background add `-d` to the `docker-compose` command:

 ```bash
$ cd test_resources/test_server
$ docker-compose up -d
```
## Run the tests
To run the tests just execute at the project directory:

```bash

$ cargo test

```

## Stop the containers

If the containers are executed in foreground, just press `Ctrl+C`. If the containers are executed
in background, execute:

```bash
$ cd test_resources/test_server
$ docker-compose stop
```