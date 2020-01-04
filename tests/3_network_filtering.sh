#!/bin/sh

check_3() {
  logit ""
  id_3="3"
  desc_3="Network Configuration"
  check_3="$id_3 - $desc_3"
  info "$check_3"
  startsectionjson "$id_3" "$desc_3"
}

check_3_1() {
  logit ""
  id_3_1="3.1"
  desc_3_1="Network Parameters (Host Only)"
  check_3_1="$id_3_1 - $desc_3_1"
  info "$check_3_1"
}

check_3_1_1() {
  retval=0
  sysctl net.ipv4.ip_forward | if grep -E "net.ipv4.ip_forward([  ]*=[  ]0[  ]"; then
    retval=$((retval + 0))
    # net.ipv4.ip_forward = 0
  else
    retval=$((retval + 1))
  fi
  if grep -c "net\.ipv4\.ip_forward" /etc/sysctl.conf /etc/sysctl.d/* -eq 1; then
    if grep -c "net\.ipv4\.ip_forward[  ]*=[  ]*0" /etc/sysctl.conf /etc/sysctl.d/* -eq 1; then
      retval=$((retval + 0))
    # net.ipv4.ip_forward = 0
    else
      retval=$((retval + 1))
    fi
  else
    retval=$((retval + 1))
  fi
  return "$retval"
}

check_3_2_1() {
  retval=0
  sysctl net.ipv4.conf.all.accept_source_route
  #net.ipv4.conf.all.accept_source_route = 0
  sysctl net.ipv4.conf.default.accept_source_route
  #net.ipv4.conf.default.accept_source_route = 0
  grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
  #net.ipv4.conf.all.accept_source_route= 0
  grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
  #net.ipv4.conf.default.accept_source_route= 0

  #if [ $file -eq 1 ]; then
    retval=1
  #fi
  return $retval

}

