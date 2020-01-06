#!/bin/sh



check_2_1_1() {
  #chkconfig --list
  #xinetd based services:
  # chargen-dgram:  off
  # chargen-stream: off
  retval=0
  retval=test_config "chargen-dgram chargen-stream"
  return $retval
}

check_2_1_2() {
  #chkconfig --list
  # xinetd based services:
  # daytime-dgram:  off
  # daytime-stream: off
  retval=0
  retval=test_config "daytime-dgram daytime-stream"
  return $retval
}

check_2_1_3() {
  #chkconfig --list
  # xinetd based services:
  # discard-dgram:  off
  # discard-stream: off
  retval=0
  retval=test_config "discard-dgram discard-stream"
  return $retval
}

check_2_1_4() {
  #chkconfig --list
  # xinetd based services:
  # echo-dgram:     off
  # echo-stream:    off
  retval=0
  retval=test_config "echo-dgram echo-stream"
  return $retval
}

check_2_1_5() {
  #chkconfig --list
  # xinetd based services:
  # time-dgram:     off
  # time-stream:    off
  retval=0
  retval=test_config "time-dgram time-stream"
  return $retval
}

check_2_1_6() {
  #chkconfig --list
  # xinetd based services:
  # tftp:           off
  retval=0
  retval=test_config "tftp"
  return $retval
}

check_2_1_7() {
  # systemctl is-enabled xinetd
  # disable
  retval=0
  retval=test_service "xinetd"
  return $retval
}

check_2_2_1() {
  if rpm -q aide > /dev/null 2>&1; then
    retval=0
  else
    retval=1
  fi
  return $retval
}

check_2_2_1_1() {
  # Determine which NTP protocol application is installed
  # for virtualised systems, host based time may be used.
  # Need to use at least two synchronised time sources for all servers and network equipment

  if rpm -q ntp; then
    ntp_installed="true"
  else
    ntp_installed="false"
  fi

  if rpm -q chrony; then
    chrony_installed="true"
  else
    chrony_installed="false"
  fi

  if [ "$ntp_installed" = "true" ] || [ "$chrony_installed" = "true " ]; then
    retval=0
  else
    retval=1
  fi
  return $retval
}

check_2_2_1_2() {
  retval=0

  if [ -f /etc/ntp.conf ]; then
    grep "^restrict" /etc/ntp.conf
    # restrict -4 default kod nomodify notrap nopeer noquery
    # restrict -6 default kod nomodify notrap nopeer noquery
    grep "^(server|pool)" /etc/ntp.conf
    # server <remote-server>
  else
    logit "/etc/ntp.conf does not exisst"
  fi
  if [ -f /etc/sysconfig/ntpd ]; then
    if grep "^OPTIONS" /etc/sysconfig/ntpd; then
    # OPTIONS="-u ntp:ntp"
      retval=0
    else
      retval=1
    fi
  else
    logit "/etc/sysconfig/ntpd dioes not exist"
  fi
  if [ -f /usr/lib/systemd/system/ntpd.service ]; then
    if grep "^ExecStart" /usr/lib/systemd/system/ntpd.service; then
      retval=0
    else
      retval=1
    fi
    # ExecStart=/usr/sbin/ntpd -u ntp:ntp $OPTIONS
  else
    logit "/usr/lib/systemd/system/ntpd.service does not exist"
  fi
  retval=1
  return $retval
}

check_2_2_1_3() {
  grep -E "^(server|pool)" /etc/chrony.conf
  # server <remote-server>
  grep ^OPTIONS /etc/sysconfig/chronyd
  # OPTIONS="-u chrony"
  if rpm -q aide > /dev/null 2>&1; then
    retval=0
  else
    retval=1
  fi
  return $retval
}

check_2_2_2() {
  # rpm -qa xorg-x11*
  # <no output expected>
  retval=0
  retval=test_package "xorg-x11"
  return $retval
}

check_2_2_3() {
#  systemctl is-enabled avahi-daemon
  # disabled
  retval=0
  retval=test_service "avahi-daemon"
  return $retval
}

check_2_2_4() {
#  systemctl is-enabled cups
  # disabled
  retval=0
  retval=test_service "cups"
  return $retval
}

check_2_2_5() {
#  systemctl is-enabled dhcpd
  # disabled
  retval=0
  retval=test_service "dhcpd"
  return $retval
}

check_2_2_6() {
#  systemctl is-enabled slapd
  # disabled
  retval=0
  retval=test_service "slapd"
  return $retval
}
check_2_2_7() {
#  systemctl is-enabled nfs
  # disabled
#  systemctl is-enabled nfs-server
  # disabled
#  systemctl is-enabled rpcbind
  # disabled
  retval=0
  retval=test_service "nfs nfs-server rpcbind"
  return $retval
}

check_2_2_8() {
#  systemctl is-enabled named
  # disabled
  retval=0
  retval=test_service "named"
  return $retval
}

check_2_2_9() {
#  systemctl is-enabled vsftpd
  # disabled
  retval=0
  retval=test_service "vsftpd"
  return $retval
}

check_2_2_10() {
#  systemctl is-enabled httpd
  # disabled
  retval=0
  retval=test_service "httpd"
  return $retval
}

check_2_2_11() {
#  systemctl is-enabled dovecot
  # disabled
  retval=0
  retval=test_service "dovecot"
  return $retval
}

check_2_2_12() {
#  systemctl is-enabled smb
  # disabled
  retval=0
  retval=test_service "smb"
  return $retval
}

check_2_2_13() {
#  systemctl is-enabled squid
  # disabled
  retval=0
  retval=test_service "squid"
  return $retval
}

check_2_2_14() {
#  systemctl is-enabled snmpd
  # disabled
  retval=0
  retval=test_service "snmpd"
  return $retval
}

check_2_2_15() {
  retval=1
# SMTP port 25 only on local address
  if command -v "netstat" >/dev/null 2>&1; then
    netstat -an | grep LISTEN | grep ":25[[:space:]]"
# need to test for the following LISTEN port
    # tcp 0 0 127.0.0.1:25 0.0.0.0:* LISTEN
  else
    #  ss is a prerequisite
    ss -an | grep LISTEN | grep ":25[[:space:]]"
    # tcp LISTEN 0 100 127.0.0.1:25 *.*
    # tcp LISTEN 0 100 [::1]]:25 [::]:*
  fi
  return $retval
}
check_2_2_16() {
#  systemctl is-enabled ypserv
  # disabled
  retval=0
  retval=test_service "ypserv"
  return $retval
}

check_2_2_17() {
#  systemctl is-enabled rsh.socket
  # disabled
#  systemctl is-enabled rlogin.socket
  # disabled
#  systemctl is-enabled rexec.socket
  # disabled
  retval=0
  retval=test_service "rsh.socket rlogin.socket rexec.socket"
  return $retval
}

check_2_2_18() {
#  systemctl is-enabled ntalk
  # disabled
  retval=0
  retval=test_service "ntalk"
  return $retval
}

check_2_2_19() {
#  systemctl is-enabled telnet.socket
  # disabled
  retval=0
  retval=test_service "telnet.socket"
  return $retval
}

check_2_2_20() {
#  systemctl is-enabled tftp.socket
  # disabled
  retval=0
  retval=test_service "tftp.socket"
  return $retval
}

check_2_2_21() {
  systemctl is-enabled rsyncd
  # disabled
  retval=0
  retval=test_service "rsyncd"
  return $retval
}

check_2_3_1() {
  rpm -q ypbind
  # package ypbind is not installed
  retval=0
  retval=test_package "ypbind"
  return $retval
}

check_2_3_2() {
  rpm -q rsh
  # package rsh is not installed
  retval=0
  retval=test_package "rsh"
  return $retval
}

check_2_3_3() {
  rpm -q talk
  # package talk is not installed
  retval=0
  retval=test_package "talk"
  return $retval
}

check_2_3_4() {
  rpm -q telnet
  # package telnet is not installed
  retval=0
  retval=test_package "telnet"
  return $retval
}

check_2_3_5() {
#  rpm -q openldap-clients
  # package openldap-clients is not installed
  retval=0
  retval=test_package "openldap-clients"
  return $retval
}