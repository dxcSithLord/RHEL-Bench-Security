#!/bin/sh

test_filesystems() {
  # test the availability of filesystem provided as $1
  ret=1
  if [ $# -eq 1 ]; then
    # check that there is an argument
    # if modprobe command errors, lsmod is not executed
    # perhaps also check ls -d "/lib/modules/$(uname -r)/kernel/fs/$1" to see
    #  if the kernel module is available on this system
    res1=$(modprobe -n -v "$1" 2>/dev/null || echo "not in kernel")
    res2=$(lsmod | grep "$1")
    if [ -n "${res1}" ]; then
      # something there - if nothing, then fail
      if [ "$res1" = "install /bin/true" ]; then
        if [ -z "${res2}" ]; then
          ret=0
        fi
      fi
    fi
  else
    echo "Expecting single filesystem name - e.g. cramfs"
  fi
  return $ret
}

test_mount_point() {
  subfs=$1
  retval=1 # default to fail
  totalChecks=$((totalChecks + 1))
  #do_version_check "$docker_current_version" "$docker_version"

  if /bin/mount | /bin/grep "on ${subfs}" >/dev/null 2>&1; then
    retval=0
  fi
  return $retval
}

test_mount_opt() {
  #local retval
  #local opts
  #local my_mnt
  # Used by checks 1.1.3 to 1.1.5
  #retval=1
  # printf "Checking %s mount option %s ... \n" "$1" "$2"
  #my_mnt=$1
  #opts=$2
  # match mount point name - leading "/" in $1, followed by a space
  # followed by a non-greedy any characters up to open paren or comma " (.*)[(,]"
  # followed by the keyword and comma or close paren ${opts}[,)]
  # if /bin/mount | /bin/grep -qE "on ${my_mnt} (.*)[(,]${opts}[,)]"; then
  #  retval=0
  #fi
  /bin/mount | /bin/grep -qE "on ${1} (.*)[(,]${2}[,)]"
  return $retval
}

# 1.1.1.x
check_1_1_1_x() {
  if [ $# -eq 2 ]; then
    subtest=$1
    subfs=$2
    subid_1_1_1="1.1.1.$subtest"
    subdesc_1_1_1="Ensure mounting of $subfs filesystems is disabled"
    subcheck_1_1_1="$subid_1_1_1  - $subdesc_1_1_1"
    starttestjson "$subid_1_1_1" "$subdesc_1_1_1"

    totalChecks=$((totalChecks + 1))
    #do_version_check "$docker_current_version" "$docker_version"
    test_filesystems "$subfs"
    if [ $? -eq 1 ]; then
      warn "$subcheck_1_1_1"
      resulttestjson "WARN"
      currentScore=$((currentScore - 1))
    else
      pass "$subcheck_1_1_1"
      resulttestjson "PASS"
      currentScore=$((currentScore + 1))
    fi
  else
    echo "wrong number of arguments - expected subtest and filesystem"
  fi
}

remedy_1_1_1() {
  file="/etc/modprobe.d/CIS.conf"
  printf "Checking module hardening file %s ... ", $file
  if [ -f "$file" ]; then
    echo ok
  else
    printf "missing, creating ... "
    cat <<EOF >$file && echo ok || echo error
# Hardening rules based on CIS recommendations
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true
EOF
  fi
}

# 1.1.2
remedy_1_1_2() {
  echo "No separate tmp mount point - Correcting"
  printf "Configuring /tmp in systemd"
  systemctl unmask tmp.mount
  systemctl enable tmp.mount
}

check_1_1_2() {
  test_mount_point '/tmp'
  return $?
}

remedy_1_1_3() {
  opts=$1
  echo mismatch
  #  tmpfile="/etc/systemd/system/local-fs.target.wants/tmp.mount"
  printf "Changing /tmp mount options to %s ... " "${opts}"
  if sed -i -e "/^Options=.*/ s/$/,$opts/" $file; then
    echo ok
    printf "Remounting with new options ... "
    mount -o remount /tmp && echo ok || echo error
  else
    echo error
  fi
}

check_1_1_3() {
  test_mount_opt "/tmp" "nodev"
  return $?
}

check_1_1_4() {
  test_mount_opt "/tmp" "nosuid"
  return $?
}
check_1_1_5() {
  test_mount_opt "/tmp" "noexec"
  return $?
}
# 1.1.6 Ensure separate partition exists for /var (Scored)

check_1_1_6() {
  test_mount_point '/var'
  return $?
}

check_1_1_7() {
  test_mount_point '/var/tmp'
  return $?

}

check_1_1_8() {
  test_mount_opt "/var/tmp" "nodev"
  return $?
}

check_1_1_9() {
  test_mount_opt "/var/tmp" "nosuid"
  return $?
}
check_1_1_10() {
  test_mount_opt "/var/tmp" "noexec"
  return $?
}

check_1_1_11() {
  test_mount_point "/var/log"
  return $?
}
check_1_1_12() {
  test_mount_point "/var/log/audit"
  return $?
}

check_1_1_13() {
  test_mount_point "/home"
  return $?
}

check_1_1_14() {
  test_mount_opt "/home" "nodev"
  return $?
}

check_1_1_15() {
  test_mount_opt "/dev/shm" "nodev"
  return $?
}

check_1_1_16() {
  test_mount_opt "/dev/shm" "nosuid"
  return $?
}
check_1_1_17() {
  test_mount_opt "/dev/shm" "noexec"
  return $?
}
cat - <<EOF
# 1.1.18 Ensure nodev is set on Rmovable media partitions (not scored)
# 1.1.19 Ensure nosuid is set on Rmovable media partitions (not scored)
# 1.1.20 Ensure noexec is set on Rmovable media partitions (not scored)
EOF
# NEED to determine removable media mount points
# /cdrom
# /floppy
# /media/<user>/<device>
# /mnt
# /a
# device name for memory cards and usb devices
# check for usb device in /dev/hd? and /dev/sd?
# check mount point
# check mount point for options

#echo
#cat - <<EOF
# 1.1.21 Ensure sticky bit is set on all world-writable directories
#EOF
check_1_1_21() {

  found=0
  found="$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | wc -l)"

  if [ "$found" -eq 0 ]; then
    resval=0
  else
    resval=1
  fi
  return $resval
}

remedy_1_1_21() {

  df --local -P | \
  awk \{'if (NR!=1) print $6'\} | \
  xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs chmod a+t

}
check_1_1_22() {
  resval=0
  if systemctl --quiet is-enabled autofs 2>/dev/null; then
    resval=1
  fi
  return $resval
}

remedy_1_1_22() {
  servicelist="autofs"
  for service in $servicelist; do
    printf "Checking status of service %s ... " "${service}"
    if systemctl --quiet is-enabled ${service} 2>/dev/null; then
      printf "enabled, disabling ... "
      systemctl disable ${service} && echo ok || echo error
    else
      echo "disabled"
    fi
  done

}

#cat - <<EOF
# 1.2.1 Ensure package manager repositories are configured
# 1.2.2 Ensure gpgcheck is globally activated
#EOF
#check_1_2_1() {
#  id_1_2_1="1.2.1"
#  desc_1_2_1="Disable Automounting"
#  check_1_2_1="$id_1_2_1  - $desc_1_2_1"
#  starttestjson "$id_1_2_1" "$desc_1_2_1"
#  yum repolist
#  found=0
#  if systemctl --quiet is-enabled autofs 2>/dev/null; then
#    warn "$check_1_2_1"
#    resulttestjson "WARN"
#  else
#    pass "$check_1_2_1"
#    resulttestjson "PASS"
#  fi
#}
check_1_2_2() {

  found=0
  for file in /etc/yum.conf /etc/yum.repos.d/*; do
    printf " - %s ... " "$file"
    if grep -q "^gpgcheck=1" "$file"; then
      echo "pass"
    else
      if $(grep -c -v '^#' "$file") -gt 0; then
        echo "warn"
        found=1
      else
        echo "empty file, skipping"
      fi
    fi
  done

  if [ $found -eq 0 ]; then
    retval=0
  else
    retval=1
  fi
  return $retval
}

remedy_1_2_2() {
  for file in /etc/yum.conf /etc/yum.repos.d/*; do
    printf " - %s ... " "$file"
    if grep -q "^gpgcheck=1" "$file"; then
      echo ok
    else
      if $(grep -c -v '^#' "$file") -gt 0; then
        printf "no, changing ... "
        sed -i -e 's/^\(gpgcheck=\).*/\11/' "$file" && echo ok || echo error
      fi
    fi
  done

}
check_1_2_3() {
  echo "Verifying global activation of gpgcheck:"

  echo
#  cat - <<EOF
# 1.2.3 Ensure GPG keys are installed
#EOF

  echo "Verifying Red Hat GPG keys ... "
  if rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'; then
    retval=0
  else
    retval=1
  fi
  return $retval
}

echo
#cat - <<EOF
# 1.2.5 Disable the rhnsd Daemon
#EOF
check_1_2_5(){
  chkconfig --list rhnsd
for service in autofs rhnsd; do
  printf "Checking status of service %s ... " "${service}"
  if systemctl --quiet is-enabled ${service} 2>/dev/null; then
    printf "enabled, disabling ... "
    systemctl disable ${service} off && echo ok || echo error
  else
    echo "disabled"
  fi
done
}

check_1_3_1() {
  if rpm -q aide > /dev/null 2>&1; then
    retval=0
  else
    retval=1
  fi
  return $retval
}

check_1_3_2() {
  if sudo crontab -l \| grep aide > /dev/null 2>&1; then
    retval=0
  else
    retval=1
  fi
  return $retval
}
echo
#cat - <<EOF
# 1.4.1 Ensure permissions on bootloader config are configured
#EOF
check_1_4() {
  logit ""
  id_1_4="1.4"
  desc_1_4="Secure Boot Setting"
  check_1_4="$id_1_4 - $desc_1_4"
  info "$check_1_4"
}
check_1_4_1(){
  retval=0
  file="/boot/grub2/grub.cfg"
  stat -c "%u %g" $file | if grep -qv "0 0"; then
    printf "Setting %s owner as root:root ... " "$file"
    chmod root:root $file && echo ok || retval=1
  else
    echo "$file already owned by root:root"
  fi
  stat -c "%a" $file | if grep -qv "600"; then
    printf "Setting %s permissions as 0600 ... " "$file"
    chmod 0600 $file && echo ok || echo error
  else
    echo "$file already has permissions 0600"
  fi
}
#cat - <<EOF
# 1.4.3 Ensure authentication required for single user mode
#EOF
check_1_4_3(){
  retval=0
  file="/usr/lib/systemd/system/rescue.service"
  if grep -q "^ExecStart.*/sbin/sulogin" $file; then
    retval=1
  else
    printf "no, enabling ... "
    sed -i -e 's%^\(ExecStart=\).*%\1-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"%' $file && echo ok || echo error
  fi
  return $retval
}
remedy_1_4_3(){
  retval=0
  if grep -q "^ExecStart.*/sbin/sulogin" $file; then
    retval=1
  else
    printf "no, enabling ... "
    sed -i -e 's%^\(ExecStart=\).*%\1-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"%' $file && echo ok || echo error
  fi
  return $retval

}
echo
#cat - <<EOF
# 1.5.3 Ensure address space layout randomization (ASLR) is enabled
#EOF
check_1_5_3(){
  retval=0
  file="/etc/sysctl.conf"
  parm="kernel.randomize_va_space"
  if $(sysctl -n "${parm}") -ne 2; then
    retval=1
  fi
  return $retval
}

remedy_1_5_3(){
    printf "Checking status of sysctl variable %s ... " "${parm}"
    if $(sysctl -n "${parm}") -ne 2; then
      printf "disabled, enabling ... "
      sysctl -q -w ${parm}=2 && echo ok || echo error
      if grep -q ${parm} $file; then
        sed -i -e "s/^$parm.*/$parm = 2/" $file
      else
        echo "$parm = 2" >>$file
      fi
    fi
}
#cat - <<EOF
# 1.5.4 Ensure prelink is disabled
# 1.6.1.4 Ensure SETroubleshoot is not installed
# 1.6.1.5 Ensure the MCS Translation Service (mcstrans) is not installed
#EOF
check_1_5_4(){
  retval=0
  retval=test_package "prelink"
  return $retval
}
check_1_6_1_4(){
  retval=0
  retval=test_package "setroubleshoot"
  return $retval
}
check_1_6_1_5(){
  retval=0
  retval=test_package "mctrans"
  return $retval
}
remedy_1_5_4(){
for pkg in prelink setroubleshoot mctrans; do
  printf "Checking if package %s exists ... " "${pkg}"
  if rpm -q --quiet ${pkg}; then
    printf "yes, removing ... "
    yum remove -y -q ${pkg} && echo ok || echo error
  else
    echo no
  fi
done

}
#cat - <<EOF
# 1.7.1.1 Ensure message of the day is configured properly
# 1.7.1.2 Ensure local login warning banner is configured properly
# 1.7.1.3 Ensure remote login warning banner is configured properly
#EOF
check_1_7_1_1(){
  retval=0
  file="/etc/motd"
  if grep -E -q '(\\v|\\r|\\m|\\s)' "$file"; then
    retval=1
  fi
  return $retval
}
check_1_7_1_2(){
  retval=0
  file="/etc/issue"
  if grep -E -q '(\\v|\\r|\\m|\\s)' "$file"; then
    retval=1
  fi
  return $retval
}
check_1_7_1_3(){
  retval=0
  file="/etc/issue.net"
  if grep -E -q '(\\v|\\r|\\m|\\s)' "$file"; then
    retval=0
  fi
  return $retval
}
#cat - <<EOF
# 1.7.1.4 Ensure permissions on /etc/motd are configured
# 1.7.1.5 Ensure permissions on /etc/issue are configured
# 1.7.1.6 Ensure permissions on /etc/issue.net are configured
#EOF
check_1_7_1_4(){
  retval=0
  file="/etc/motd"
  mode="644"
  uid="0"
  gid="0"
  if stat -c "%a %u %g" "$file" \| grep -qv "$mode $uid $gid"; then
    retval=1
  fi
  return $retval
}

check_1_7_1_5(){
  retval=0
  file="/etc/issue"
  mode="644"
  uid="0"
  gid="0"
  if stat -c "%a %u %g" "$file" \| grep -qv "$mode $uid $gid"; then
    retval=1
  fi
  return $retval
}
check_1_7_1_6(){
  retval=0
  file="/etc/issue.net"
  mode="644"
  uid="0"
  gid="0"
  if  stat -c "%a %u %g" "$file" \| grep -qv "$mode $uid $gid"; then
    retval=1
  fi
  return $retval
}


remedy_1_7_1_4(){
echo "/etc/motd 644 0 0
/etc/issue 644 0 0
/etc/issue.net 644 0 0" | while read -r file mode uid gid; do
   if stat -c "%a %u %g" "$file" \| grep -qv "$mode $uid $gid"; then
    printf "no, changing ... "
    chown "$uid":"$gid" "$file" && chmod "$mode" "$file" && echo ok || echo error
  else
    echo yes
  fi
done

}
