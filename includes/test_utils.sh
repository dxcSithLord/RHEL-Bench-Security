#!/bin/env bash

YUM_CONF='/etc/yum.conf'
GRUB_CFG='/boot/grub2/grub.cfg'
GRUB_DIR='/etc/grub.d'
SELINUX_CFG='/etc/selinux/config'
NTP_CONF='/etc/ntp.conf'
SYSCON_NTPD='/etc/sysconfig/ntpd'
NTP_SRV='/usr/lib/systemd/system/ntpd.service'
CHRONY_CONF='/etc/chrony.conf'
CHRONY_SYSCON='/etc/sysconfig/chronyd'
LIMITS_CNF='/etc/security/limits.conf'
SYSCTL_CNF='/etc/sysctl.conf'
CENTOS_REL='/etc/centos-release'
HOSTS_ALLOW='/etc/hosts.allow'
HOSTS_DENY='/etc/hosts.deny'
CIS_CNF='/etc/modprobe.d/CIS.conf'
RSYSLOG_CNF='/etc/rsyslog.conf'
SYSLOGNG_CONF='/etc/syslog-ng/syslog-ng.conf'
AUDITD_CNF='/etc/audit/auditd.conf'
AUDIT_RULES='/etc/audit/audit.rules'
LOGR_SYSLOG='/etc/logrotate.d/syslog'
ANACRONTAB='/etc/anacrontab'
CRONTAB='/etc/crontab'
CRON_HOURLY='/etc/cron.hourly'
CRON_DAILY='/etc/cron.daily'
CRON_WEEKLY='/etc/cron.weekly'
CRON_MONTHLY='/etc/cron.monthly'
CRON_DIR='/etc/cron.d'
AT_ALLOW='/etc/at.allow'
AT_DENY='/etc/at.deny'
CRON_ALLOW='/etc/cron.allow'
CRON_DENY='/etc/cron.deny'
SSHD_CFG='/etc/ssh/sshd_config'
SYSTEM_AUTH='/etc/pam.d/system-auth'
PWQUAL_CNF='/etc/security/pwquality.conf'
PASS_AUTH='/etc/pam.d/password-auth'
PAM_SU='/etc/pam.d/su'
GROUP='/etc/group'
LOGIN_DEFS='/etc/login.defs'
PASSWD='/etc/passwd'
SHADOW='/etc/shadow'
GSHADOW='/etc/gshadow'
BASHRC='/etc/bashrc'
PROF_D='/etc/profile.d'
MOTD='/etc/motd'
ISSUE='/etc/issue'
ISSUE_NET='/etc/issue.net'
GDM_PROFILE='/etc/dconf/profile/gdm'
GDM_BANNER_MSG='/etc/dconf/db/gdm.d/01-banner-message'
RESCUE_SRV='/usr/lib/systemd/system/rescue.service'

if [[ "$BENCH_SKIP_SLOW" == "1" ]]; then
  DO_SKIP_SLOW=1
else
  DO_SKIP_SLOW=0
fi

test_module_disabled() {
  local module="${1}"
  modprobe -n -v "${module}" 2>&1 | grep -q "install \+/bin/true" || return
  lsmod | grep -qv "${module}" || return
}

test_separate_partition() {
  local target="${1}"
  findmnt -n "${target}" | grep -q "${target}" || return
}

test_mount_option() {
  local target="${1}"
  local mnt_option="${2}"
  findmnt -nlo options "${target}" | grep -q "${mnt_option}" || return
}

test_system_file_perms() {
  local dirs
  dirs="$(rpm -Va --nomtime --nosize --nomd5 --nolinkto)"
  [[ -z "${dirs}" ]] || return
}

test_sticky_wrld_w_dirs() {
  local dirs
  dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \))"
  [[ -z "${dirs}" ]] || return
}

test_wrld_writable_files() {
  local dirs
  dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002)"
  [[ -z "${dirs}" ]] || return
}

test_unowned_files() {
  local dirs
  dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser)"
  [[ -z "${dirs}" ]] || return
}

test_ungrouped_files() {
  local dirs
  dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup)"
  [[ -z "${dirs}" ]] || return
}

test_suid_executables() {
  local dirs
  dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000)"
  [[ -z "${dirs}" ]] || return
}

test_sgid_executables() {
  local dirs
  dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000)"
  [[ -z "${dirs}" ]] || return
}

test_service_disable() {
  local service="$1" 
  systemctl is-enabled "${service}" 2>&1 | grep -E -q 'disabled|Failed' || return
}

test_service_enabled() {
  local service="$1" 
  systemctl is-enabled "${service}" 2>&1 | grep -q 'enabled' || return
}

test_yum_gpgcheck() {
  if [[ -f ${YUM_CONF} ]]; then
    grep -q ^gpgcheck ${YUM_CONF} 2>/dev/null || return
  fi
  ! grep ^gpgcheck /etc/yum.repos.d/* | grep 0$ || return
}

test_rpm_installed() {
  local rpm="${1}"
  rpm -q ${rpm} | grep -qe "^${rpm}" || return
}

test_rpm_not_installed() {
  local rpm="${1}"
  rpm -q ${rpm} | grep -q "not installed" || return
}

test_aide_cron() {
  crontab -u root -l 2>/dev/null | cut -d\# -f1 | grep -q "aide \+--check" || return
}

test_file_perms() {
  local file="${1}"
  local pattern="${2}"  
  stat -L -c "%a" ${file} | grep -qE "^${pattern}$" || return
}

test_root_owns() {
  local file="${1}"
  stat -L -c "%u %g" ${file} | grep -q '0 0' || return
}

test_grub_permissions() {
  test_root_owns ${GRUB_CFG}
  test_file_perms ${GRUB_CFG} 0600
}

test_boot_pass() {
  grep -q 'set superusers=' "${GRUB_CFG}"
  if [[ "$?" -ne 0 ]]; then
    grep -q 'set superusers=' ${GRUB_DIR}/* || return
    file="$(grep 'set superusers' ${GRUB_DIR}/* | cut -d: -f1)"
    grep -q 'password' "${file}" || return
  else
    grep -q 'password' "${GRUB_CFG}" || return
  fi
}

test_auth_rescue_mode() {
  grep -q /sbin/sulogin ${RESCUE_SRV} || return
}

test_sysctl() {
  local flag="$1"
  local value="$2"
  sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep -q "${value}" || return
}

test_restrict_core_dumps() {
  grep -E -q "\*{1}[[:space:]]+hard[[:space:]]+core[[:space:]]+0" "${LIMITS_CNF}" || return
  for f in /etc/security/limits.d/*; do
    grep -E -q "\*{1}[[:space:]]+hard[[:space:]]+core[[:space:]]+0" "${f}" || return
  done
  test_sysctl fs.suid_dumpable 0 || return 
}

test_xd_nx_support_enabled() {
  dmesg | grep -E -q "NX[[:space:]]\(Execute[[:space:]]Disable\)[[:space:]]protection:[[:space:]]active" || return
}

test_selinux_grubcfg() {
  local grep_out1
  grep_out1="$(grep selinux=0 ${GRUB_CFG})"
  [[ -z "${grep_out1}" ]] || return
  local grep_out2
  grep_out2="$(grep enforcing=0 ${GRUB_CFG})"
  [[ -z "${grep_out2}" ]] || return
}

test_selinux_state() {
  cut -d \# -f1 ${SELINUX_CFG} | grep 'SELINUX=' | tr -d '[[:space:]]' | grep -q 'SELINUX=enforcing' || return
}

test_selinux_policy() {
  cut -d \# -f1 ${SELINUX_CFG} | grep 'SELINUXTYPE=' | tr -d '[[:space:]]' | grep -q 'SELINUXTYPE=targeted' || return
}

test_unconfined_procs() {
  local ps_out
  ps_out="$(ps -eZ | grep -E 'initrc|unconfined' | grep -E -v 'bash|ps|grep')"
  [[ -n "${ps_out}" ]] || return
}

test_warn_banner() {
  local banner
  banner="$(grep -E '(\\v|\\r|\\m|\\s)' ${1})"
  [[ -z "${banner}" ]] || return
}

test_permissions_0644_root_root() {
  local file=$1
  test_root_owns ${file} || return
  test_file_perms ${file} 644 || return
}

test_permissions_0600_root_root() {
  local file=$1
  test_root_owns ${file} || return
  test_file_perms ${file} 600 || return
}

test_permissions_0000_root_root() {
  local file=$1
  test_root_owns ${file} || return
  test_file_perms ${file} 0 || return
}

test_gdm_banner_msg() {
  if [[ -f "${BANNER_MSG}" ]] ; then
    grep -E '[org/gnome/login-screen]' ${BANNER_MSG} || return
    grep -E 'banner-message-enable=true' ${BANNER_MSG} || return
    grep -E 'banner-message-text=' ${BANNER_MSG} || return
  fi
}

test_gdm_banner() {
  if [[ -f "${GDM_PROFILE}" ]] ; then
    grep -E 'user-db:user' ${GDM_PROFILE} || return
    grep -E 'system-db:gdm' ${GDM_PROFILE} || return
    grep -E 'file-db:/usr/share/gdm/greeter-dconf-defaults' ${GDM_PROFILE} || return
    test_gdm_banner_msg || return
  fi
}

test_yum_check_update() {
  yum -q check-update &>/dev/null || return
}

test_dgram_stream_services_disabled() {
  local service=$1
  test_service_disable ${service}-dgram || return
  test_service_disable ${service}-stream || return
}

test_time_sync_services_enabled() {
  test_service_enabled ntpd && return
  test_service_enabled chronyd && return
  return 1
}

test_ntp_cfg() {
  cut -d\# -f1 ${NTP_CONF} | grep -E "restrict{1}[[:space:]]+default{1}" ${NTP_CONF} | grep kod | grep nomodify | grep notrap | grep nopeer | grep -q noquery || return
  cut -d\# -f1 ${NTP_CONF} | grep -E "restrict{1}[[:space:]]+\-6{1}[[:space:]]+default" | grep kod | grep nomodify | grep notrap | grep nopeer | grep -q noquery || return
  cut -d\# -f1 ${NTP_CONF} | grep -E -q "^[[:space:]]*server" || return
  cut -d\# -f1 ${SYSCON_NTPD} | grep "OPTIONS=" | grep -q "ntp:ntp" && return
  cut -d\# -f1 ${NTP_SRV} | grep "^ExecStart" | grep -q "ntp:ntp" && return
  return 1
}

test_chrony_cfg() {
  cut -d\# -f1 ${CHRONY_CONF} | grep -E -q "^[[:space:]]*server" || return
  cut -d\# -f1 ${CHRONY_SYSCON} | grep "OPTIONS=" | grep -q "\-u chrony" || return
}

test_nfs_rpcbind_services_disabled() {
  test_service_disable nfs || return
  test_service_disable rpcbind || return
}

test_mta_local_only() {
  netstat_out="$(netstat -an | grep "LIST" | grep ":25[[:space:]]")"
  if [[ "$?" -eq 0 ]] ; then
    ip=$(echo ${netstat_out} | cut -d: -f1 | cut -d" " -f4)
    [[ "${ip}" = "127.0.0.1" ]] || return    
  fi
}

test_rsh_service_disabled() {
  test_service_disable rsh.socket || return
  test_service_disable rlogin.socket || return
  test_service_disable rexec.socket || return
}

test_net_ipv4_conf_all_default() {
  local suffix=$1
  local value=$2
  test_sysctl "net.ipv4.conf.all.${suffix}" ${value} || return
  test_sysctl "net.ipv4.conf.default.${suffix}" ${value} || return
}

test_net_ipv6_conf_all_default() {
  local suffix=$1
  local value=$2
  test_sysctl "net.ipv6.conf.all.${suffix}" ${value} || return
  test_sysctl "net.ipv6.conf.default.${suffix}" ${value} || return
}

test_ipv6_disabled() {
  modprobe -c | grep -E -q '[[:space:]]*options[[:space:]]+ipv6[[:space:]]+disable=1' || return
}

test_tcp_wrappers_installed() {
  test_rpm_installed tcp_wrappers
  test_rpm_installed tcp_wrappers-libs
}

test_hosts_deny_content() {
  cut -d\# -f1 ${HOSTS_DENY} | grep -q "ALL[[:space:]]*:[[:space:]]*ALL" || return
}

test_firewall_policy() {
  iptables -L | grep -E -q "Chain[[:space:]]+INPUT[[:space:]]+" | grep -E -q "policy[[:space:]]+DROP" || return
  iptables -L | grep -E -q "Chain[[:space:]]+FORWARD[[:space:]]+" | grep -E -q "policy[[:space:]]+DROP" || return
  iptables -L | grep -E -q "Chain[[:space:]]+OUTPUT[[:space:]]+" | grep -E -q "policy[[:space:]]+DROP" || return
}

test_loopback_traffic_conf() {
  local accept="ACCEPT[[:space:]]+all[[:space:]]+--[[:space:]]+lo[[:space:]]+\*[[:space:]]+0\.0\.0\.0\/0[[:space:]]+0\.0\.0\.0\/0"
  local drop="DROP[[:space:]]+all[[:space:]]+--[[:space:]]+\*[[:space:]]+\*[[:space:]]+127\.0\.0\.0\/8[[:space:]]+0\.0\.0\.0\/0"
  iptables -L INPUT -v -n | grep -E -q ${accept} || return
  iptables -L INPUT -v -n | grep -E -q ${drop} || return
  iptables -L OUTPUT -v -n | grep -E -q ${accept} || return
}

test_wireless_if_disabled() {
  for i in $(iwconfig 2>&1 | grep -E -v "no[[:space:]]*wireless" | cut -d' ' -f1); do
    ip link show up | grep "${i}:"
    if [[ "$?" -eq 0 ]]; then
    return 1
    fi
  done
}

test_audit_log_storage_size() {
  cut -d\# -f1 ${AUDITD_CNF} | grep -E -q "max_log_file[[:space:]]|max_log_file=" || return
}

test_dis_on_audit_log_full() {
  cut -d\# -f2 ${AUDITD_CNF} | grep 'space_left_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'email' || return
  cut -d\# -f2 ${AUDITD_CNF} | grep 'action_mail_acct' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'root' || return
  cut -d\# -f2 ${AUDITD_CNF} | grep 'admin_space_left_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'halt' || return
}

test_keep_all_audit_info() {
  cut -d\# -f2 ${AUDITD_CNF} | grep 'max_log_file_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'keep_logs' || return
}

test_audit_procs_prior_2_auditd() {
  grep_grub="$(grep "^[[:space:]]*linux" ${GRUB_CFG} | grep -v 'audit=1')"
  [[ -z "${grep_grub}" ]] || return
}

test_audit_date_time() {
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+time-change" | grep -E "\-S[[:space:]]+settimeofday" \
  | grep -E "\-S[[:space:]]+adjtimex" | grep -E "\-F[[:space:]]+arch=b64" | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+time-change" | grep -E "\-S[[:space:]]+settimeofday" \
  | grep -E "\-S[[:space:]]+adjtimex" | grep -E "\-F[[:space:]]+arch=b32" | grep -E "\-S[[:space:]]+stime" | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+time-change" | grep -E "\-F[[:space:]]+arch=b64" \
  | grep -E "\-S[[:space:]]+clock_settime" | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+time-change" | grep -E "\-F[[:space:]]+arch=b32" \
  | grep -E "\-S[[:space:]]+clock_settime" | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+time-change" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/etc\/localtime" || return
}

test_audit_user_group() {
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+identity" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/etc\/group" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+identity" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/etc\/passwd" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+identity" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/etc\/gshadow" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+identity" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/etc\/shadow" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+identity" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/etc\/security\/opasswd" || return
}

test_audit_network_env() {
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+system-locale" | grep -E "\-S[[:space:]]+sethostname" \
  | grep -E "\-S[[:space:]]+setdomainname" | grep -E "\-F[[:space:]]+arch=b64" | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+system-locale" | grep -E "\-S[[:space:]]+sethostname" \
  | grep -E "\-S[[:space:]]+setdomainname" | grep -E "\-F[[:space:]]+arch=b32" | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+system-locale" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/etc\/issue" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+system-locale" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/etc\/issue.net" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+system-locale" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/etc\/hosts" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+system-locale" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/etc\/sysconfig\/network" || return
}

test_audit_sys_mac() {
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+MAC-policy" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/etc\/selinux\/" || return
}

test_audit_logins_logouts() {
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+logins" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/var\/log\/faillog" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+logins" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/var\/log\/lastlog" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+logins" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/var\/log\/tallylog" || return
}

test_audit_session_init() {
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+session" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/var\/run\/utmp" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+session" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/var\/log\/wtmp" || return
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+session" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/var\/log\/btmp" || return
}

test_audit_dac_perm_mod_events() {
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+perm_mod" | grep -E "\-S[[:space:]]+chmod" \
  | grep -E "\-S[[:space:]]+fchmod" | grep -E "\-S[[:space:]]+fchmodat" | grep -E "\-F[[:space:]]+arch=b64" \
  | grep -E "\-F[[:space:]]+auid>=1000" | grep -E "\-F[[:space:]]+auid\!=4294967295" \
  | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+perm_mod" | grep -E "\-S[[:space:]]+chmod" \
  | grep -E "\-S[[:space:]]+fchmod" | grep -E "\-S[[:space:]]+fchmodat" | grep -E "\-F[[:space:]]+arch=b32" \
  | grep -E "\-F[[:space:]]+auid>=1000" | grep -E "\-F[[:space:]]+auid\!=4294967295" \
  | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+perm_mod" | grep -E "\-S[[:space:]]+chown" \
  | grep -E "\-S[[:space:]]+fchown" | grep -E "\-S[[:space:]]+fchownat" | grep -E "\-S[[:space:]]+fchown" \
  | grep -E "\-F[[:space:]]+arch=b64" | grep -E "\-F[[:space:]]+auid>=1000" | grep -E "\-F[[:space:]]+auid\!=4294967295" \
  | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+perm_mod" | grep -E "\-S[[:space:]]+chown" \
  | grep -E "\-S[[:space:]]+fchown" | grep -E "\-S[[:space:]]+fchownat" | grep -E "\-S[[:space:]]+fchown" \
  | grep -E "\-F[[:space:]]+arch=b32" | grep -E "\-F[[:space:]]+auid>=1000" | grep -E "\-F[[:space:]]+auid\!=4294967295" \
  | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+perm_mod" | grep -E "\-S[[:space:]]+setxattr" \
  | grep -E "\-S[[:space:]]+lsetxattr" | grep -E "\-S[[:space:]]+fsetxattr" | grep -E "\-S[[:space:]]+removexattr" \
  | grep -E "\-S[[:space:]]+lremovexattr" | grep -E "\-S[[:space:]]+fremovexattr" | grep -E "\-F[[:space:]]+arch=b64" \
  | grep -E "\-F[[:space:]]+auid>=1000" | grep -E "\-F[[:space:]]+auid\!=4294967295" \
  | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+perm_mod" | grep -E "\-S[[:space:]]+setxattr" \
  | grep -E "\-S[[:space:]]+lsetxattr" | grep -E "\-S[[:space:]]+fsetxattr" | grep -E "\-S[[:space:]]+removexattr" \
  | grep -E "\-S[[:space:]]+lremovexattr" | grep -E "\-S[[:space:]]+fremovexattr" | grep -E "\-F[[:space:]]+arch=b32" \
  | grep -E "\-F[[:space:]]+auid>=1000" | grep -E "\-F[[:space:]]+auid\!=4294967295" \
  | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
}

test_unsuc_unauth_acc_attempts() {
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+access" | grep -E "\-S[[:space:]]+creat" \
  | grep -E "\-S[[:space:]]+open" | grep -E "\-S[[:space:]]+openat" | grep -E "\-S[[:space:]]+truncate" \
  | grep -E "\-S[[:space:]]+ftruncate" | grep -E "\-F[[:space:]]+arch=b64" | grep -E "\-F[[:space:]]+auid>=1000" \
  | grep -E "\-F[[:space:]]+auid\!=4294967295" | grep -E "\-F[[:space:]]exit=\-EACCES" \
  | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+access" | grep -E "\-S[[:space:]]+creat" \
  | grep -E "\-S[[:space:]]+open" | grep -E "\-S[[:space:]]+openat" | grep -E "\-S[[:space:]]+truncate" \
  | grep -E "\-S[[:space:]]+ftruncate" | grep -E "\-F[[:space:]]+arch=b32" | grep -E "\-F[[:space:]]+auid>=1000" \
  | grep -E "\-F[[:space:]]+auid\!=4294967295" | grep -E "\-F[[:space:]]exit=\-EACCES" \
  | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+access" | grep -E "\-S[[:space:]]+creat" \
  | grep -E "\-S[[:space:]]+open" | grep -E "\-S[[:space:]]+openat" | grep -E "\-S[[:space:]]+truncate" \
  | grep -E "\-S[[:space:]]+ftruncate" | grep -E "\-F[[:space:]]+arch=b64" | grep -E "\-F[[:space:]]+auid>=1000" \
  | grep -E "\-F[[:space:]]+auid\!=4294967295" | grep -E "\-F[[:space:]]exit=\-EPERM" \
  | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+access" | grep -E "\-S[[:space:]]+creat" \
  | grep -E "\-S[[:space:]]+open" | grep -E "\-S[[:space:]]+openat" | grep -E "\-S[[:space:]]+truncate" \
  | grep -E "\-S[[:space:]]+ftruncate" | grep -E "\-F[[:space:]]+arch=b32" | grep -E "\-F[[:space:]]+auid>=1000" \
  | grep -E "\-F[[:space:]]+auid\!=4294967295" | grep -E "\-F[[:space:]]exit=\-EPERM" \
  | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

}

test_coll_priv_cmds() {
  local priv_cmds
  priv_cmds="$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f)"
  for cmd in ${priv_cmds} ; do
    cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+privileged" | grep -E "\-F[[:space:]]+path=${cmd}" \
    | grep -E "\-F[[:space:]]+perm=x" | grep -E "\-F[[:space:]]+auid>=1000" | grep -E "\-F[[:space:]]+auid\!=4294967295" \
    | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  done
}

test_coll_suc_fs_mnts() {
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+mounts" | grep -E "\-S[[:space:]]+mount" \
  | grep -E "\-F[[:space:]]+arch=b64" | grep -E "\-F[[:space:]]+auid>=1000" \
  | grep -E "\-F[[:space:]]+auid\!=4294967295" \
  | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+mounts" | grep -E "\-S[[:space:]]+mount" \
  | grep -E "\-F[[:space:]]+arch=b32" | grep -E "\-F[[:space:]]+auid>=1000" \
  | grep -E "\-F[[:space:]]+auid\!=4294967295" \
  | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
}

test_coll_file_del_events() {
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+delete" | grep -E "\-S[[:space:]]+unlink" \
  | grep -E "\-F[[:space:]]+arch=b64" | grep -E "\-S[[:space:]]+unlinkat" | grep -E "\-S[[:space:]]+rename" \
  | grep -E "\-S[[:space:]]+renameat" | grep -E "\-F[[:space:]]+auid>=1000" \
  | grep -E "\-F[[:space:]]+auid\!=4294967295" \
  | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+delete" | grep -E "\-S[[:space:]]+unlink" \
  | grep -E "\-F[[:space:]]+arch=b32" | grep -E "\-S[[:space:]]+unlinkat" | grep -E "\-S[[:space:]]+rename" \
  | grep -E "\-S[[:space:]]+renameat" | grep -E "\-F[[:space:]]+auid>=1000" \
  | grep -E "\-F[[:space:]]+auid\!=4294967295" \
  | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

}

test_coll_chg2_sysadm_scope() {
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+scope" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/etc\/sudoers" || return

}

test_coll_sysadm_actions() {
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+actions" | grep -E "\-p[[:space:]]+wa" \
  | grep -E -q "\-w[[:space:]]+\/var\/log\/sudo.log" || return
}

test_kmod_lod_unlod() {
  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+modules" | grep -E "\-p[[:space:]]+x" \
  | grep -E -q "\-w[[:space:]]+\/sbin\/insmod" || return

  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+modules" | grep -E "\-p[[:space:]]+x" \
  | grep -E -q "\-w[[:space:]]+\/sbin\/rmmod" || return

  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+modules" | grep -E "\-p[[:space:]]+x" \
  | grep -E -q "\-w[[:space:]]+\/sbin\/modprobe" || return

  cut -d\# -f1 ${AUDIT_RULES} | grep -E "\-k[[:space:]]+modules" | grep -E "\-S[[:space:]]+delete_module" \
  | grep -E "\-F[[:space:]]+arch=b64" | grep -E "\-S[[:space:]]+init_module" \
  | grep -E -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
}

test_audit_cfg_immut() {
  cut -d\# -f1 ${AUDIT_RULES} | grep -E -q "^-e[[:space:]]+2" || return
}

test_rsyslog_content() {
  grep -q "^*.*[^I][^I]*@" ${RSYSLOG_CNF} 2>/dev/null || return
}

test_syslogng_content() {
  grep -E -q "destination[[:space:]]+logserver[[:space:]]+\{[[:space:]]*tcp\(\".+\"[[:space:]]+port\([[:digit:]]+\)\)\;[[:space:]]*\}\;" ${SYSLOGNG_CONF} 2>/dev/null || return
  grep -E -q "log[[:space:]]+\{[[:space:]]*source\(src\)\;[[:space:]]*destination\(logserver\)\;[[:space:]]*\}\;" ${SYSLOGNG_CONF} 2>/dev/null || return
}

test_rsyslog_syslogng_installed() {
  test_rpm_installed rsyslog && return
  test_rpm_installed syslog-ng && return
  return 1
}

test_var_log_files_permissions() {
  [[ $(find /var/log -type f -ls | grep -v "\-r\-\-\-\-\-\-\-\-" | grep -v "\-rw\-\-\-\-\-\-\-" | grep -v "\-rw\-r\-\-\-\-\-" | wc -l) -eq 0 ]] || return
}

test_at_cron_auth_users() {
  [[ ! -f ${AT_DENY} ]] || return 
  [[ ! -f ${CRON_DENY} ]] || return 
  test_permissions_0600_root_root "${CRON_ALLOW}" || return
  test_permissions_0600_root_root "${AT_ALLOW}" || return
}

test_param() {
  local file="${1}" 
  local parameter="${2}" 
  local value="${3}" 
  cut -d\# -f1 ${file} | grep -E -q "^${parameter}[[:space:]]+${value}" || return
}

test_ssh_param_le() {
  local parameter="${1}" 
  local allowed_max="${2}"
  local actual_value
  actual_value=$(cut -d\# -f1 ${SSHD_CFG} | grep "${parameter}" | cut -d" " -f2)
  [[ ${actual_value} -le ${allowed_max} ]] || return 
}

test_ssh_idle_timeout() {
  test_ssh_param_le ClientAliveInterval 300 || return
  test_ssh_param_le ClientAliveCountMax 3 || return
}

test_ssh_access() {
  local allow_users
  local allow_groups
  local deny_users
  local deny_users
  allow_users="$(cut -d\# -f1 ${SSHD_CFG} | grep "AllowUsers" | cut -d" " -f2)"
  allow_groups="$(cut -d\# -f1 ${SSHD_CFG} | grep "AllowGroups" | cut -d" " -f2)"
  deny_users="$(cut -d\# -f1 ${SSHD_CFG} | grep "DenyUsers" | cut -d" " -f2)"
  deny_groups="$(cut -d\# -f1 ${SSHD_CFG} | grep "DenyGroups" | cut -d" " -f2)"
  [[ -n "${allow_users}" ]] || return
  [[ -n "${allow_groups}" ]] || return
  [[ -n "${deny_users}" ]] || return
  [[ -n "${deny_groups}" ]] || return
}

test_password_limits() {
  local retval
  local parm
  local pvalue
  local eqtest
  retval=0
  # minimul length, implies that it could be greater, this only tests for equality
  # subshell when piped into while loop, so can't set retval=1 inside loop
# while read -r parm value great
#do
  printf "Checking if %s option '%s' has value '%s' ... " "$PWQUAL_CNF" "${parm}" "${pvalue}"
  case "$eqtest" in
    "1") # test for maximum value
      printf "Test for maximum"
      if grep -E "^${parm}\s*=\s*[0-9]*\s*" "$PWQUAL_CNF" | awk -F'=' '{print $2}' | awk -v val="${pvalue}" '{if ($1 > val) {print "0"}' -eq "0"; then
        retval=1;
      fi ;;
    "0") # test for equality
      printf "Test for equality"
      if ! grep -Eq "^${parm}\s*=\s*${pvalue}$" "$PWQUAL_CNF"; then
        retval=1
      fi;;
    "-1") # test for minimum value;;
      printf "Test for minimum"
      if grep -E "^${parm}\s*=\s*[0-9]*\s*" "$PWQUAL_CNF" | awk -F'=' '{print $2}' | awk -v val="${pvalue}" '{if ($1 < val) {print "0"}' -eq "0"; then
        retval=1;
      fi ;;

    else) printf "test_password_limits - parameter error expected -1, 0 or 1, value passed : %s", "$eqtest";;
  esac
#done
return "$retval"
}

#test_password_limits "difok" "3" "0"
test_password_limits "minlen" "14" "-1"
test_password_limits "dcredit" "-1" "0"
test_password_limits "ocredit" "-1" "0"
test_password_limits "lcredit" "-1" "0"
#test_password_limits "maxrepeat" "2" "1"

remedy_PWQUAL_CNF(){

  if grep -q "^${parm}[[:space:]]" "$PWQUAL_CNF"
  then
    # option exists but with different value
    printf "changing ... "
    sed -i -e "s/^\($parm\) .*/\1 = $value/" "$PWQUAL_CNF" && echo ok || echo error
  elif grep -E -q "^#[[:space:]]{0,}${parm}[[:space:]]" "$PWQUAL_CNF"
  then
    # option exists but is commented
    printf "changing ... "
    sed -i -e "s/^#\?\s\{0,\}\($parm\) .*/\1 = $value/" "$PWQUAL_CNF" && echo ok || echo error
  else
    # option was not present, adding
    printf "adding ... "
    echo "${parm} = ${value}" >> "$PWQUAL_CNF" && echo ok || echo error
  fi

}

file="/etc/pam.d/system-auth"
module="pam_pwquality.so"
opts="try_first_pass local_users_only retry=3"
if [ -h "$file" ]
then
  target=$(dirname $file)/$(file $file | awk '/symbolic link to/ { print $NF }' | sed -e "s/[\`']//g")
  [ -f "$target" ] && file="$target"
fi
printf "Checking if PAM module ${module} has '${opts}' ... "
if grep -q "^password.*requisite.*${module}.*${opts}" $file
then
  echo yes
else
  printf "no, changing ... "
  sed -i -e "/^password.*requisite.*$module/ s/^\(.*\.so\s\{1,\}\).*/\1$opts/" $file && echo ok || echo error
fi

}
test_wrapper() {
  local do_skip=$1
  shift
  local msg=$1
  shift
  local func=$1
  shift
  local args=$@
  if [[ "$do_skip" -eq 0 ]]; then
    ${func} ${args} 
    if [[ "$?" -eq 0 ]]; then
      pass "${msg}"
    else
      warn "${msg}"
    fi
  else
    skip "${msg}"
  fi
}
