#!/bin/sh
# ------------------------------------------------------------------------------
# Docker Bench for Security
#
# Docker, Inc. (c) 2015-
#
# Checks for dozens of common best-practices around deploying Docker containers in production.
# ------------------------------------------------------------------------------

version='2.2'

# Load dependencies
. ./helper_lib.sh
. ./functions_lib.sh

# Setup the paths
this_path=$(abspath "$0")       ## Path of this file including filename
myname=$(basename "${this_path}")     ## file name of this script.

readonly version
readonly this_path
readonly myname

export PATH="$PATH:/bin:/sbin:/usr/bin:/usr/local/bin:/usr/sbin/"

# Check for required program(s)
req_progs='awk grep ss stat'
for p in $req_progs; do
  command -v "$p" >/dev/null 2>&1 || { printf "%s command not found.\n" "$p"; exit 1; }
done

usage () {
  cat <<EOF
  usage: ${myname} [options]

  -b           optional  Do not print colors
  -h           optional  Print this help message
  -l FILE      optional  Log output in FILE
  -c CHECK     optional  Comma delimited list of specific check(s)
  -e CHECK     optional  Comma delimited list of specific check(s) to exclude
  -i INCLUDE   optional  Comma delimited list of patterns within a container or image name to check
  -x EXCLUDE   optional  Comma delimited list of patterns within a container or image name to exclude from check
EOF
}

# Get the flags
# If you add an option here, please
# remember to update usage() above.
while getopts bhl:c:e:i:x:t: args
do
  case $args in
  b) nocolor="nocolor";;
  h) usage; exit 0 ;;
  l) logger="$OPTARG" ;;
  c) check="$OPTARG" ;;
  e) checkexclude="$OPTARG" ;;
  i) include="$OPTARG" ;;
  x) exclude="$OPTARG" ;;
  *) usage; exit 1 ;;
  esac
done

if [ -z "$logger" ]; then
  logger="${myname}.log"
fi

# Load output formating
. ./output_lib.sh

yell_info

# Warn if not root
ID=$(id -u)
if [ "x$ID" != "x0" ]; then
  warn "Some tests might require root to run"
  sleep 3
fi

# Total Score
# Warn Scored -1, Pass Scored +1, Not Score -0

totalChecks=0
currentScore=0

logit "Initializing $(date)\n"
beginjson "$version" "$(date +%s)"

# Load all the tests from tests/ and run them
main () {
  # Get configuration location

  # If there is a container with label docker_bench_security, memorize it:
  benchcont="nil"
  for c in $(docker ps | sed '1d' | awk '{print $NF}'); do
    if docker inspect --format '{{ .Config.Labels }}' "$c" | \
     grep -e 'docker.bench.security' >/dev/null 2>&1; then
      benchcont="$c"
    fi
  done

  # get the image id of the docker_bench_security_image, memorize it:
  benchimagecont="nil"
  for c in $(docker images | sed '1d' | awk '{print $3}'); do
    if docker inspect --format '{{ .Config.Labels }}' "$c" | \
     grep -e 'docker.bench.security' >/dev/null 2>&1; then
      benchimagecont="$c"
    fi
  done

  if [ -n "$include" ]; then
    pattern=$(echo "$include" | sed 's/,/|/g')
    containers=$(docker ps | sed '1d' | awk '{print $NF}' | grep -v "$benchcont" | grep -E "$pattern")
    images=$(docker images | sed '1d' | grep -E "$pattern" | awk '{print $3}' | grep -v "$benchimagecont")
  elif [ -n "$exclude" ]; then
    pattern=$(echo "$exclude" | sed 's/,/|/g')
    containers=$(docker ps | sed '1d' | awk '{print $NF}' | grep -v "$benchcont" | grep -Ev "$pattern")
    images=$(docker images | sed '1d' | grep -Ev "$pattern" | awk '{print $3}' | grep -v "$benchimagecont")
  else
    containers=$(docker ps | sed '1d' | awk '{print $NF}' | grep -v "$benchcont")
    images=$(docker images -q | grep -v "$benchcont")
  fi

  if [ -z "$containers" ]; then
    running_containers=0
  else
    running_containers=1
  fi

  for test in tests/*.sh; do
    . ./"$test"
  done

  if [ -z "$check" ] && [ ! "$checkexclude" ]; then
    cis
  elif [ -z "$check" ] && [ "$checkexclude" ]; then
    checkexcluded="$(echo ",$checkexclude" | sed -e 's/^/\^/g' -e 's/,/\$|/g' -e 's/$/\$/g')"
    for c in $(grep -E 'check_[0-9]|check_[a-z]' functions_lib.sh | grep -vE "$checkexcluded"); do
      "$c"
    done
  else
    for i in $(echo "$check" | sed "s/,/ /g"); do
      if command -v "$i" 2>/dev/null 1>&2; then
        "$i"
      else
        echo "Check \"$i\" doesn't seem to exist."
        continue
      fi
    done
  fi

  printf "\n"
  info "Checks: $totalChecks"
  info "Score: $currentScore"

  endjson "$totalChecks" "$currentScore" "$(date +%s)"
}

main "$@"
