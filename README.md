# RedHat Bench for Security

![RedHat Bench for Security running](https://raw.githubusercontent.com/dxcSithLord/RHEL-Bench-Security/master/benchmark_log.png "RHEL 7 Bench for Security running")

This work is based on the Docker Bench for Security and uses the same structure
for tests and results.
The tests are provided as a script that checks for dozens of common
best-practices in use on RedHat (and Centos) Version 7. The tests are
all automated, and are inspired by the [CIS Red Hat Enterprise Linux 7 Benchmark v2.2.0](https://www.cisecurity.org/benchmark/).

This was made available as an open-source utility so the Centos/RedHat community
can have an easy way to self-assess their hosts and  against
this benchmark.  I would also recommend running the Docker Benchmark tests if you are also running docker containers.

## Running Red Hat Enterprise Linux Bench for Security

The conversion from Docker to RedHat script is still in progress the remainder of this is from the original docker 
container version and may NOT be relevant.


Note that when distributions doesn't contain `auditctl`, the audit tests will
check `/etc/audit/audit.rules` to see if a rule is present instead.


### RHEL Bench for Security options

```sh
  -b           optional  Do not print colors
  -h           optional  Print this help message
  -l FILE      optional  Log output in FILE
  -c CHECK     optional  Comma delimited list of specific check(s)
  -e CHECK     optional  Comma delimited list of specific check(s) to exclude
  -i INCLUDE   optional  Comma delimited list of patterns within a container or image name to check
  -x EXCLUDE   optional  Comma delimited list of patterns within a container or image name to exclude from check
```

By default the RHEL Bench for Security script will run all available CIS tests
and produce logs in the current directory named `docker-bench-security.sh.log.json`
and `docker-bench-security.sh.log`.
The CIS based checks are named `check_<section>_<number>`, e.g. `check_2_6`
and community contributed checks are named `check_c_<number>`.
A complete list of checks are present in [functions_lib.sh](functions_lib.sh).

`sh docker-bench-security.sh -l /tmp/docker-bench-security.sh.log -c check_2_2`
will only run check `2.2 Ensure the logging level is set to 'info'`.

`sh docker-bench-security.sh -l /tmp/docker-bench-security.sh.log -e check_2_2`
will run all available checks except `2.2 Ensure the logging level is set to 'info'`.

Note that when submitting checks, provide information why it is a
reasonable test to add and please include some kind of official documentation
verifying that information.

## TO UPDATE:
 Building Docker Bench for Security

If you wish to build and run this container yourself, you can follow the
following steps:

```sh
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
docker build --no-cache -t docker-bench-security .
docker run -it --net host --pid host --cap-add audit_control \
    -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
    -v /var/lib:/var/lib:ro \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -v /usr/lib/systemd:/usr/lib/systemd:ro \
    -v /etc:/etc:ro --label docker_bench_security \
    docker-bench-security
```

or use [Docker Compose](https://docs.docker.com/compose/):

```sh
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
docker-compose run --rm docker-bench-security
```

Also, this script can also be simply run from your base host by running:

```sh
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

This script was built to be POSIX 2004 compliant, so it should be portable
across any Unix platform.
