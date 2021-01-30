#!/bin/env bash
# Description: This script provides logging functions
# All functions require a single parameter that will be printed.
# logit : argument will be printed  without highlights
# info :  "[INFO]" which will be in BLUE and bold highlight before the argument
# pass : "[PASS]" which will be in GREEN and bold highlight before the argument
# warn : "[WARN]" which will be in RED and bold highlight before the argument
# note : "[NOTE]" which will be in YELLOW and bold highlight before the argument
# todo : "[TODO]" which will be in MAGENTA and bold highlight before the argument
# skip : "[SKIP]" which will be in CYAN and bold highlight before the argument
# yell : prints the whole message argument in YELLOW and bold

#
# Define text colour sequqnces
#
BLDRED='\033[1;31m'
BLDGRN='\033[1;32m'
BLDBLU='\033[1;34m'
BLDYLW='\033[1;33m' # Yellow
BLDMGT='\033[1;35m' # Magenta
BLDCYN='\033[1;36m' # Cyan 
TXTRST='\033[0m'

#
# To do : add argument checking to each function
#

logit () {
  printf "%b\n" "$1"
}

info () {
  printf "%b\n" "${BLDBLU}[INFO]${TXTRST} $1"
}

pass () {
  printf "%b\n" "${BLDGRN}[PASS]${TXTRST} $1"
}

warn () {
  printf "%b\n" "${BLDRED}[WARN]${TXTRST} $1"
}

note () {
  printf "%b\n" "${BLDYLW}[NOTE]${TXTRST} $1"
}

todo() {
  printf "%b\n" "${BLDMGT}[TODO]${TXTRST} $1"
}

skip() {
  printf "%b\n" "${BLDCYN}[SKIP]${TXTRST} $1"
}

yell () {
  printf "%b\n" "${BLDYLW}$1${TXTRST}\n"
}