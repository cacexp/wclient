# Testing

> **_TO DO:_**  Create cargo scripts to create images and manage test containers.
## Pre-requisites

Some tests uses services hosted on [Docker](https://docker.io) containers. Please, make sure you have installed at least `docker-ce` and `docker-compose`.

## Build the containers
Before testing, please create the container image:

```bash
$ cd test_resources/test_server
$ ./create_image.sh
```

## Start the containers

To start the container in foreground with logs execute:

```bash
$ cd test_resources/test_server
$ docker-compose -f ./docker-compose.yml up
```

To execute the containers in background add `-d` to the `docker-compose` command:

 ```bash
$ cd test_resources/test_server
$ docker-compose -f ./docker-compose.yml up -d
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
$ docker-compose -f ./docker-compose.yml stop
```