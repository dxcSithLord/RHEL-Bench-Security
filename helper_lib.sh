#!/bin/sh

# Returns the absolute path of a given string
abspath () { case "$1" in /*)printf "%s\n" "$1";; *)printf "%s\n" "$PWD/$1";; esac; }

# Audit rules default path
auditrules="/etc/audit/audit.rules"

# Compares versions of software of the format X.Y.Z
do_version_check() {
  [ "$1" = "$2" ] && return 10

  ver1front=$(printf "%s" "$1" | cut -d "." -f -1)
  ver1back=$(printf "%s" "$1" | cut -d "." -f 2-)
  ver2front=$(printf "%s" "$2" | cut -d "." -f -1)
  ver2back=$(printf "%s" "$2" | cut -d "." -f 2-)

  if [ "$ver1front" != "$1" ] || [ "$ver2front" != "$2" ]; then
    [ "$ver1front" -gt "$ver2front" ] && return 11
    [ "$ver1front" -lt "$ver2front" ] && return 9

    [ "$ver1front" = "$1" ] || [ -z "$ver1back" ] && ver1back=0
    [ "$ver2front" = "$2" ] || [ -z "$ver2back" ] && ver2back=0
      do_version_check "$ver1back" "$ver2back"
      return $?
  else
    [ "$1" -gt "$2" ] && return 11 || return 9
  fi
}

# Extracts commandline args from the newest running processes named like the first parameter
get_command_line_args() {
  PROC="$1"

  for PID in $(pgrep -f -n "$PROC"); do
    tr "\0" " " < /proc/"$PID"/cmdline
  done
}

# Extract the cumulative command line arguments for the docker daemon
#
# If specified multiple times, all matches are returned.
# Accounts for long and short variants, call with short option.
# Does not account for option defaults or implicit options.
get_docker_cumulative_command_line_args() {
  OPTION="$1"

  if ! get_command_line_args "docker daemon" >/dev/null 2>&1 ; then
    line_arg="docker daemon"
  else
    line_arg="dockerd"
  fi

  get_command_line_args "$line_arg" |
  # normalize known long options to their short versions
  sed \
    -e 's/\-\-debug/-D/g' \
    -e 's/\-\-host/-H/g' \
    -e 's/\-\-log-level/-l/g' \
    -e 's/\-\-version/-v/g' \
    |
    # normalize parameters separated by space(s) to -O=VALUE
    sed \
      -e 's/\-\([DHlv]\)[= ]\([^- ][^ ]\)/-\1=\2/g' \
      |
    # get the last interesting option
    tr ' ' "\n" |
    grep "^${OPTION}" |
    # normalize quoting of values
    sed \
      -e 's/"//g' \
      -e "s/'//g"
}

# Extract the effective command line arguments for the docker daemon
#
# Accounts for multiple specifications, takes the last option.
# Accounts for long and short variants, call with short option
# Does not account for option default or implicit options.
get_docker_effective_command_line_args() {
  OPTION="$1"
  get_docker_cumulative_command_line_args "$OPTION" | tail -n1
}

get_docker_configuration_file() {
  FILE="$(get_docker_effective_command_line_args '--config-file' | \
    sed 's/.*=//g')"

  if [ -f "$FILE" ]; then
    CONFIG_FILE="$FILE"
  elif [ -f '/etc/docker/daemon.json' ]; then
    CONFIG_FILE='/etc/docker/daemon.json'
  else
    CONFIG_FILE='/dev/null'
  fi
}

get_docker_configuration_file_args() {
  OPTION="$1"

  get_docker_configuration_file

  grep "$OPTION" "$CONFIG_FILE" | sed 's/.*://g' | tr -d '" ',
}

get_systemd_service_file() {
  SERVICE="$1"

  if [ -f "/etc/systemd/system/$SERVICE" ]; then
    echo "/etc/systemd/system/$SERVICE"
  elif systemctl show -p FragmentPath "$SERVICE" 2> /dev/null 1>&2; then
    systemctl show -p FragmentPath "$SERVICE" | sed 's/.*=//'
  else
    echo "/usr/lib/systemd/system/$SERVICE"
  fi
}

#
# This is a generic replacement for all the "check_*" functions that repeat most of the same code
# reducing the overall length significantly and avoiding repeat errors
#
# The quoted values are from the grep string expression below
# This assumes that the id reference is a string with
# starting with (beginning of the line) "^"
# number in the range 1-9 "[1-9]", followed by
# zero or more digits 0-9 "[0-9]*", followed by
# with zero or more of the following "(":
# the single underscore character "_"
# a number in the range 1-9 "[1-9]", followed by
# zero or more digits in the range 0-9 "[0-9]*"
# close sequence ")*"
# terminating with the line end "$".
# Any other test or spaces  before or after will cause the match to fail.
# Possible matches include:
# 1 2 3 4 5 6 7 8 9
# 1_1 1_1_1 1_1_1_1
# 10_1_2_3_4_50
# 900_1_604
# Not valid:
# 0 leading zero
# 1_ trailing underscore
# 1_0 leading zero
# 9_8_0 leading zero
# 2_04 leading zero
# The resulting function is a concatination of
# check_ and $1
# The id is the same, but with "_" replaced with "." character
# The functions need to return 0 for success - anything else will
# generate a warning

make_check() {
  if echo "$1" | grep -cwE '^[1-9][0-9]*(_[1-9][0-9]*)*$' -eq 1; then
    check_ref=$(echo "$1" | sed -e "s/_/./g")
    id_ref="$1"
    desc_ref="$2"
    check_desc="$check_ref - $desc_ref"
    starttestjson "$id_ref" "$desc_ref"

    totalChecks=$((totalChecks + 1))
    if check_${id_ref} -eq 0; then
      pass "$check_desc"
      resulttestjson "PASS"
      currentScore=$((currentScore + 1))
    else
      warn "$check_desc"
      resulttestjson "WARN"
      currentScore=$((currentScore - 1))
    fi
  else
    warn "$1 - test reference syntax invalid; Description: $2"
  fi
}
#example_check_call(){
#  make_check "1_2_3" "test check"
#}


check_L1() {
  # arg1 = id
  # arg2 = descrition
  # function initialises logit, puts info
  # and startsectionjson
  logit ""
  id_L1=$1
  desc_L1=$2
  check_L1="$id_L1 - $desc_L1"
  info "$check_L1"
  startsectionjson "$id_L1" "$desc_L1"
}

check_L2() {
  # arg1 = id
  # arg2 = descrition
  # function initialises logit, puts info
  logit ""
  id_L2=$(echo "$1" | sed -e "s/_/./g")
  desc_L2=$2
  check_L2="$id_L2 - $desc_L2"
  info "$check_L2"
}

check_ennd(){
  endsectionjson
}

yell_info() {
yell "# ------------------------------------------------------------------------------
# Red Hat Bench for Security v$version
#
# Based on Docker, Inc. (c) 2015-
#
# Checks for dozens of common best-practices around deploying Docker containers in production.
# Inspired by the CIS Redhat 7 Benchmark v2.2.0.
# ------------------------------------------------------------------------------"
}
