# RedHat Bench for Security

RHEL 7 Bench for Security running

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
and produce logs in the current directory named `RHEL-bench-security.sh.log.json`
and `RHEL-bench-security.sh.log`.
The CIS based checks are named `check_<section>_<number>`, e.g. `check_2_6`
and community contributed checks are named `check_c_<number>`.
A complete list of checks are present in [functions_lib.sh](includes/functions_lib.sh).

`sh RHEL-bench-security.sh -l /tmp/RHEL-bench-security.sh.log -c check_2_2`
will only run check `2.2 Ensure the logging level is set to 'info'`.

`sh RHEL-bench-security.sh -l /tmp/RHEL-bench-security.sh.log -e check_2_2`
will run all available checks except `2.2 Ensure the logging level is set to 'info'`.

Note that when submitting checks, provide information why it is a
reasonable test to add and please include some kind of official documentation
verifying that information.

## TO UPDATE:
This script can also be simply run from your base host by running:
```sh
git clone https://github.com/dxcSithLord/RHEL-bench-security.git
cd RHEL-bench-security
sudo sh RHEL-bench-security.sh
```
