from __future__ import(absolute_import, division, print_function)
from unittest import result
__metaclass__ = type
 
DOCUMENTATION = ''' #'''
EXAMPLES = ''' # '''
RETURN = ''' # '''
###############################################################################
from ansible.module_utils.basic import AnsibleModule
module=AnsibleModule(argument_spec={})
import os
import csv
supports_check_mode=True
if module.check_mode:
    module.exit_json(changed=False)
 
def bash():
 
    try:
       
        l = {'6.2.10': {'parameter':'Ensure no users have .netrc files' , 'validation':'0' , 'cmd':'sh /tmp/netrc.sh; echo $?'}, '6.2.11': {'parameter':'Ensure users .netrc Files are not group or world accessible' , 'validation':'0' , 'cmd':'sh /tmp/netrc_world.sh; echo $?'}, '6.2.12': {'parameter':'Ensure no users have .rhosts files' , 'validation':'0' , 'cmd':'sh /tmp/rhosts.sh; echo $?'}, '6.2.13': {'parameter':'Ensure all groups in /etc/passwd exist in /etc/group' , 'validation':'0' , 'cmd':'sh /tmp/groups.sh; echo $?'}, '6.2.14': {'parameter':'Ensure no duplicate UIDs exist' , 'validation':'0' , 'cmd':'sh /tmp/uid.sh; echo $?'}, '6.2.15': {'parameter':'Ensure no duplicate GIDs exist' , 'validation':'0' , 'cmd':'sh /tmp/gid.sh; echo $?'}, '6.2.16': {'parameter':'Ensure no duplicate user names exist' , 'validation':'0' , 'cmd':'sh /tmp/dup_user.sh; echo $?'}, '6.2.17': {'parameter':'Ensure no duplicate group names exist' , 'validation':'0' , 'cmd':'sh /tmp/dup_group.sh; echo $?'}, '6.2.4': {'parameter':'Ensure root PATH Integrity' , 'validation':'0' , 'cmd':'sh /tmp/root_path.sh; echo $?'}, '6.2.6': {'parameter':'Ensure users home directories permissions are 750 or more restrictive' , 'validation':'0' , 'cmd':'sh /tmp/usr_hdir_perm.sh; echo $?'}, '6.2.8': {'parameter':'Ensure users dot files are not group or world writable' , 'validation':'0' , 'cmd':'sh /tmp/usr_dot.sh; echo $?'}, '6.2.9': {'parameter':'Ensure no users have .forward files' , 'validation':'0' , 'cmd':'sh /tmp/usr_forward.sh; echo $?'}}
       
                                for i in l:
            y=os.popen(l[i]['cmd'])
            z=y.read()
 
            if l[i]['validation'] in z:
                l[i]['status']='Pass'
            else:
                l[i]['status']='Fail'
 
        bash = l
        return bash
    except Exception as e:
        return e
 
def grep():
 
    try:
        l = {'5.4.5': {'parameter':'Ensure default user umask is configured' , 'validation':'umask  027' , 'cmd' : 'grep "^umask" /etc/bashrc'}, '5.4.5': {'parameter':'Ensure default user umask is configured' , 'validation':'umask  027' , 'cmd' : 'grep "^umask" /etc/profile'}, '5.4.3': {'parameter':'Ensure default group for the root account is GID 0' , 'validation':'0' , 'cmd' : 'grep "^root:" /etc/passwd | cut -f4 -d :'}, '5.4.1.3': {'parameter':'Ensure password expiration warning days is 7 or more' , 'validation':'7' , 'cmd' : 'grep PASS_WARN_AGE /etc/login.defs'}, '5.4.1.2': {'parameter':'Ensure minimum days between password changes is configured' , 'validation':'7' , 'cmd' : 'grep PASS_MIN_DAYS /etc/login.defs'}, '5.4.1.4': {'parameter':'Ensure inactive password lock is 30 days or less' , 'validation':'INACTIVE=30' , 'cmd' : 'useradd -D | grep INACTIVE'}, '5.6': {'parameter':'Ensure access to the su command is restricted' , 'validation':'root' , 'cmd' : "cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'"}, '5.3.4': {'parameter':'Ensure password reuse is limited' , 'validation':'remember=5' , 'cmd' : 'egrep "^password\s+sufficient\s+pam_unix.so" /etc/pam.d/password-auth'}, '5.3.4': {'parameter':'Ensure password reuse is limited' , 'validation':'remember=5' , 'cmd' : 'egrep "^password\s+sufficient\s+pam_unix.so" /etc/pam.d/system-auth'}, '5.3.4': {'parameter':'Ensure password reuse is limited' , 'validation':'remember=5' , 'validation':'sha512' , 'cmd' : 'egrep "^password\s+sufficient\s+pam_unix.so" /etc/pam.d/password-auth'}, '5.3.3': {'parameter':'Ensure password hashing algorithm is SHA-512' , 'validation':'sha512' , 'cmd' : 'egrep "^password\s+sufficient\s+pam_unix.so" /etc/pam.d/system-auth'}, '5.3.1': {'parameter':'Ensure password creation requirements are configured' , 'validation':'retry=3' , 'cmd' : 'grep pam_pwquality.so /etc/pam.d/password-auth'}, '5.3.1': {'parameter':'Ensure password creation requirements are configured' , 'validation':'retry=3' , 'cmd' : 'grep pam_pwquality.so /etc/pam.d/system-auth'}, '5.3.1': {'parameter':'Ensure password creation requirements are configured' , 'validation':'minlen = 14' , 'cmd' : 'grep ^minlen /etc/security/pwquality.conf'}, '5.3.1': {'parameter':'Ensure password creation requirements are configured' , 'validation':'dcredit = -1' , 'cmd' : 'grep ^dcredit /etc/security/pwquality.conf'}, '5.3.1': {'parameter':'Ensure password creation requirements are configured' , 'validation':'lcredit = -1' , 'cmd' : 'grep ^lcredit /etc/security/pwquality.conf'}, '5.2.6': {'parameter':'Ensure SSH X11 forwarding is disabled' , 'validation':'X11Forwarding no' , 'cmd' : 'grep "^X11Forwarding" /etc/ssh/sshd_config'}, '5.2.7': {'parameter':'Ensure SSH MaxAuthTries is set to 4 or less' , 'validation':'MaxAuthTries 4' , 'cmd' : 'grep "^MaxAuthTries" /etc/ssh/sshd_config'}, '5.2.8': {'parameter':'Ensure SSH IgnoreRhosts is enabled' , 'validation':'IgnoreRhosts yes' , 'cmd' : 'grep "^IgnoreRhosts" /etc/ssh/sshd_config'}, '5.2.9': {'parameter':'Ensure SSH HostbasedAuthentication is disabled' , 'validation':'HostbasedAuthentication no' , 'cmd' : 'grep "^HostbasedAuthentication" /etc/ssh/sshd_config'}, '5.2.5': {'parameter':'Ensure SSH LogLevel is appropriate' , 'validation':'LogLevel INFO' , 'cmd' : 'grep "^LogLevel" /etc/ssh/sshd_config'}, '5.2.4': {'parameter':'Ensure SSH access is limited' , 'validation':'AllowUsers' , 'cmd' : 'grep "^AllowUsers" /etc/ssh/sshd_config'}, '5.2.18': {'parameter':'Ensure SSH warning banner is configured' , 'validation':'Banner /etc/issue.net' , 'cmd' : 'grep "^Banner" /etc/ssh/sshd_config'}, '5.2.17': {'parameter':'Ensure SSH LoginGraceTime is set to one minute or less' , 'validation':'LoginGraceTime 60' , 'cmd' : 'grep "^LoginGraceTime" /etc/ssh/sshd_config'}, '5.2.16': {'parameter':'Ensure SSH Idle Timeout Interval is configured' , 'validation':'ClientAliveCountMax 0' , 'cmd' : 'grep "^ClientAliveCountMax" /etc/ssh/sshd_config'}, '5.2.16': {'parameter':'Ensure SSH Idle Timeout Interval is configured' , 'validation':'ClientAliveInterval 300' , 'cmd' : 'grep "^ClientAliveInterval" /etc/ssh/sshd_config'}, '5.2.12': {'parameter':'Ensure SSH PermitUserEnvironment is disabled' , 'validation':'PermitUserEnvironment no' , 'cmd' : 'grep PermitUserEnvironment /etc/ssh/sshd_config'}, '5.2.11': {'parameter':'Ensure SSH PermitEmptyPasswords is disabled' , 'validation':'PermitEmptyPasswords no' , 'cmd' : 'grep "^PermitEmptyPasswords" /etc/ssh/sshd_config'}, '5.2.10': {'parameter':'Ensure SSH root login is disabled' , 'validation':'PermitRootLogin no' , 'cmd' : 'grep "^PermitRootLogin" /etc/ssh/sshd_config'}, '4.2.15': {'parameter':'Ensure rsyslog is configured to send logs to a remote log host' , 'validation':'*.* @@loghost.example.com' , 'cmd' : 'grep "^*.*[^I][^I]*@" /etc/rsyslog.conf'}, '1.2.3': {'parameter':'Ensure gpgcheck is globally activated' , 'validation':'gpgcheck=1' , 'cmd' : 'grep ^gpgcheck /etc/yum.conf'}, '1.5.1': {'parameter':'Ensure bootloader password is set' , 'validation':'set superusers=' , 'cmd' : 'grep "^set superusers" /boot/grub2/grub.cfg'}, '1.5.1': {'parameter':'Ensure bootloader password is set' , 'validation':'password_pbkdf2' , 'cmd' : 'grep "^password" /boot/grub2/grub.cfg'}, '1.5.3': {'parameter':'Ensure authentication required for single user mode' , 'validation':'--no-block default' , 'cmd' : 'grep /sbin/sulogin /usr/lib/systemd/system/rescue.service'}, '1.5.3': {'parameter':'Ensure authentication required for single user mode' , 'validation':'--no-block default' , 'cmd' : 'grep /sbin/sulogin /usr/lib/systemd/system/emergency.service'}, '1.6.1': {'parameter':'Ensure core dumps are restricted' , 'validation':'hard core 0' , 'cmd' : 'grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*'}, '1.7.1.2': {'parameter':'Ensure SELinux is not disabled in bootloader configuration' , 'validation':'audit=1' , 'cmd' : 'grep "^\s*linux" /boot/grub2/grub.cfg'}, '1.7.1.3': {'parameter':'Ensure SELinux policy is configured' , 'validation':'SELINUXTYPE=targeted' , 'cmd' : 'grep SELINUXTYPE=targeted /etc/selinux/config'}, '1.7.1.4': {'parameter':'Ensure the SELinux mode is enforcing or permissive' , 'validation':'SELINUX=enforcing' , 'cmd' : 'grep SELINUX=enforcing /etc/selinux/config'}, '2.2.1.3': {'parameter':'Ensure ntp is configured' , 'validation':'restrict' , 'cmd' : 'grep "^restrict" /etc/ntp.conf'}, '2.2.1.2': {'parameter':'Ensure chrony is configured' , 'validation':'server' , 'cmd' : 'grep "^server" /etc/chrony.conf'}, '2.2.16': {'parameter':'Ensure mail transfer agent is configured for local-only mode' , 'validation':'LISTEN' , 'cmd' : 'netstat -an | grep LIST | grep ":25[[:space:]]"'}, '4.1.12': {'parameter':'Ensure successful file system mounts are collected' , 'validation':'-a always,exit' , 'cmd' : 'grep mounts /etc/audit/audit.rules'}, '4.1.10': {'parameter':'Ensure unsuccessful unauthorized file access attempts are collected' , 'validation':'-a always,exit' , 'cmd' : 'grep access /etc/audit/audit.rules'}, '4.1.14': {'parameter':'Ensure changes to system administration scope (sudoers) is collected' , 'validation':'-w /etc/sudoers' , 'cmd' : 'grep scope /etc/audit/audit.rules'}, '4.1.15': {'parameter':'Ensure system administrator actions (sudolog) are collected' , 'validation':'-w /var/log/sudo.log -p wa -k actions' , 'cmd' : 'grep actions /etc/audit/audit.rules'}, '4.1.16': {'parameter':'Ensure kernel module loading and unloading is collected' , 'validation':'modules' , 'cmd' : 'grep modules /etc/audit/audit.rules'}, '4.1.17': {'parameter':'Ensure the audit configuration is immutable' , 'validation':'-e 2' , 'cmd' : 'grep "^\s*[^#]" /etc/audit/audit.rules | tail -1'}, '4.1.2.2': {'parameter':'Ensure audit logs are not automatically deleted' , 'validation':'max_log_file_action = keep_logs' , 'cmd' : 'grep max_log_file_action /etc/audit/auditd.conf'}, '4.1.2.3': {'parameter':'Ensure system is disabled when audit logs are full' , 'validation':'email' , 'cmd' : 'grep space_left_action /etc/audit/auditd.conf'}, '4.1.2.3': {'parameter':'Ensure system is disabled when audit logs are full' , 'validation':'root' , 'cmd' : 'grep action_mail_acct /etc/audit/auditd.conf'}, '4.1.2.3': {'parameter':'Ensure system is disabled when audit logs are full' , 'validation':'halt' , 'cmd' : 'grep admin_space_left_action /etc/audit/auditd.conf'}, '4.1.3': {'parameter':'Ensure events that modify date and time information are collected' , 'validation':'-a always,exit' , 'cmd' : 'grep time-change /etc/audit/audit.rules'}, '4.1.4': {'parameter':'Ensure events that modify user/group information are collected' , 'validation':'identity' , 'cmd' : 'grep identity /etc/audit/audit.rules'}, '4.1.6': {'parameter':'Ensure events that modify the systems Mandatory Access Controls are collected' , 'validation':'-w /etc/selinux/ -p wa -k MAC-policy' , 'cmd' : 'grep MAC-policy /etc/audit/audit.rules'}, '4.1.7': {'parameter':'Ensure login and logout events are collected' , 'validation':'logins' , 'cmd' : 'grep logins /etc/audit/audit.rules'}, '4.1.8': {'parameter':'Ensure session initiation information is collected' , 'validation':'session' , 'cmd' : 'grep session /etc/audit/audit.rules'}, '4.1.9': {'parameter':'Ensure discretionary access control permission modification events are collected' , 'validation':'perm_mod' , 'cmd' : 'grep perm_mod /etc/audit/audit.rules'}, '1.10': {'parameter':'Ensure GDM is removed or login is configured' , 'validation':'banner-message-enable=true' , 'cmd' : 'cat /etc/dconf/db/gdm.d/01-banner-message'}, '1.4.2': {'parameter':'Ensure filesystem integrity is regularly checked' , 'validation':'--check' , 'cmd' : 'crontab -u root -l | grep aide'}}
        for i in l:
           x=os.popen(l[i]['cmd'])
            y=x.read()
            if l[i]['validation'] in y:
                l[i]['status']='Pass'
            else:
                l[i]['status']='Fail'
        #for i in l:
            #print(i)
 
        grep = l
        return grep
    except Exception as e:
        return e

def log():
 
    try:
        #Logfile permission script
        x=os.popen("find /var/log -type f -ls | awk '{print $3, $11}'").readlines()
        #Status="Pass"
        l={'4.2.3' : {'parameter':'Ensure permissions on all logfiles are configured' , 'status':''}}
 
        for i in x:
            if "-rw-------" in i:
                #Status="Pass"
                l['status']='Pass'
            else:
                #Status="Fail"
                l['status']='Fail'
                break
 
        #for i in l:
        #print(i)
 
        log = l
        return log
    except Exception as e:
        return e
 
def mod():
    try:
        l = {'1.1.1.1': {'parameter':'Ensure mounting of cramfs filesystems is disabled' , 'validation':'install /bin/true' , 'cmd':'modprobe -n -v cramfs'}, '1.1.1.2': {'parameter':'Ensure mounting of squashfs filesystems is disabled' , 'validation':'install /bin/true' , 'cmd':'modprobe -n -v squashfs'}, '1.1.1.3': {'parameter':'Ensure mounting of udf filesystems is disabled' , 'validation':'install /bin/true' , 'cmd':'modprobe -n -v udf'}, '4.2.1.3': {'parameter':'Ensure rsyslog default file permissions configured' , 'validation':'0640' , 'cmd':'grep ^\$FileCreateMode /etc/rsyslog.conf'}}
   
        for i in l:
            y=os.popen(l[i]['cmd'])
            z=y.read()
 
            if l[i]['validation'] in z:
                l[i]['status']='Pass'
            else:
                l[i]['status']='Fail'
 
        mod = l
        return mod
    except Exception as e:
        return e
 
def mount():
    try:
        l = {'1.1.2': {'parameter':'Ensure /tmp is configured' , 'validation':'/tmp' , 'cmd' : 'mount | grep /tmp' , 'required' : 'yes'}, '1.1.3': {'parameter':'Ensure noexec option set on /tmp partition' , 'validation':'noexec' , 'cmd' : 'mount | grep /tmp' , 'required' : 'yes'}, '1.1.4': {'parameter':'Ensure nodev option set on /tmp partition' , 'validation':'nodev' , 'cmd' : 'mount | grep /tmp' , 'required' : 'yes'}, '1.1.5': {'parameter':'Ensure nosuid option set on /tmp partition' , 'validation':'nosuid' , 'cmd' : 'mount | grep /tmp' , 'required' : 'yes'}, '1.1.6': {'parameter':'Ensure /dev/shm is configured' , 'validation':'/dev/shm ' , 'cmd' : 'mount | grep /dev/shm' , 'required' : 'yes'}, '1.1.7': {'parameter':'Ensure noexec option set on /dev/shm partition' , 'validation':'noexec' , 'cmd' : 'mount | grep /dev/shm' , 'required' : 'yes'}, '1.1.8': {'parameter':'Ensure nodev option set on /dev/shm partition' , 'validation':'nodev' , 'cmd' : 'mount | grep /dev/shm' , 'required' : 'yes'}, '1.1.9': {'parameter':'Ensure nosuid option set on /dev/shm partition' , 'validation':'nosuid' , 'cmd' : 'mount | grep /dev/shm' , 'required' : 'yes'}, '1.1.10': {'parameter':'Ensure separate partition exists for /var' , 'validation':'/var' , 'cmd' : 'mount | grep /var' , 'required' : 'yes'}, '1.1.11': {'parameter':'Ensure separate partition exists for /var/tmp' , 'validation':'/var/tmp ' , 'cmd' : 'mount | grep /var/tmp' , 'required' : 'yes'}, '1.1.12': {'parameter':'Ensure noexec option set on /var/tmp partition' , 'validation':'noexec' , 'cmd' : 'mount | grep /var/tmp' , 'required' : 'yes'}, '1.1.13': {'parameter':'Ensure nodev option set on /var/tmp partition' , 'validation':'nodev' , 'cmd' : 'mount | grep /var/tmp' , 'required' : 'yes'}, '1.1.14': {'parameter':'Ensure nosuid option set on /var/tmp partition' , 'validation':'nosuid' , 'cmd' : 'mount | grep /var/tmp' , 'required' : 'yes'}, '1.1.15': {'parameter':'Ensure separate partition exists for /var/log' , 'validation':'/var/log' , 'cmd' : 'mount | grep /var/log' , 'required' : 'yes'}, '1.1.16': {'parameter':'Ensure separate partition exists for /var/log/audit' , 'validation':'/var/log/audit' , 'cmd' : 'mount | grep /var/log' , 'required' : 'yes'}, '1.1.17': {'parameter':'Ensure separate partition exists for /home' , 'validation':'/home' , 'cmd' : 'mount | grep /home' , 'required' : 'yes'}, '1.1.18': {'parameter':'Ensure nodev option set on /home partition' , 'validation':'nodev' , 'cmd' : 'mount | grep /home' , 'required' : 'yes'}}
 
        for i in l:
            x=os.popen(l[i]['cmd'])
            y=x.read()
 
            if l[i]['validation'] in y:
                l[i]['results']='Present'
            else:
                l[i]['results']='Not Present'
 
            if l[i]['required']=='yes' and l[i]['results']=='Present':
                l[i]['status']='Pass'
            elif l[i]['required']=='no' and l[i]['results']=='Not Present':
                l[i]['status']='Pass'
            else:
                l[i]['status']='Fail'
 
        mount = l
        return mount
    except Exception as e:
        return e
 
def rpm():
    try:
        l = {'1.3.1': {'parameter':'Ensure sudo is installed' , 'validation':'0' , 'cmd' : 'rpm -qa|grep -i sudo; echo $?' , 'required' : 'yes'}, '1.4.1': {'parameter':'Ensure AIDE is installed' , 'validation':'0' , 'cmd' : 'rpm -q aide; echo $?' , 'required' : 'yes'}, '1.6.4': {'parameter':'Ensure prelink is disabled' , 'validation':'0' , 'cmd' : 'rpm -q prelink; echo $?' , 'required' : 'no'}, '1.7.1.1': {'parameter':'Ensure SELinux is installed' , 'validation':'0' , 'cmd' : 'rpm -q libselinux; echo $?' , 'required' : 'yes'}, '1.7.1.7': {'parameter':'Ensure SETroubleshoot is not installed' , 'validation':'0' , 'cmd' : 'rpm -q setroubleshoot; echo $?' , 'required' : 'no'}, '1.7.1.8': {'parameter':'Ensure the MCS Translation Service (mcstrans) is not installed' , 'validation':'0' , 'cmd' : 'rpm -q mcstrans; echo $?' , 'required' : 'no'}, '2.2.15': {'parameter':'Ensure net-snmp is not installed' , 'validation':'0' , 'cmd' : 'rpm -qa | grep net-snmp; echo $?' , 'required' : 'no'}, '2.2.19': {'parameter':'Ensure telnet-server is not installed' , 'validation':'0' , 'cmd' : 'rpm -qa | grep telnet; echo $?' , 'required' : 'no'}, '2.3.1': {'parameter':'Ensure NIS Client is not installed' , 'validation':'0' , 'cmd' : 'rpm -q ypbind; echo $?' , 'required' : 'no'}, '2.3.2': {'parameter':'Ensure rsh client is not installed' , 'validation':'0' , 'cmd' : 'rpm -q rsh; echo $?' , 'required' : 'no'}, '2.3.3': {'parameter':'Ensure talk client is not installed' , 'validation':'0' , 'cmd' : 'rpm -q talk; echo $?' , 'required' : 'no'}, '2.3.4': {'parameter':'Ensure telnet client is not installed' , 'validation':'0' , 'cmd' : 'rpm -q telnet; echo $?' , 'required' : 'no'}, '2.3.5': {'parameter':'Ensure LDAP client is not installed' , 'validation':'0' , 'cmd' : 'rpm -q openldap-clients; echo $?' , 'required' : 'no'}, '3.5.3.1.1': {'parameter':'Ensure iptables packages are installed' , 'validation':'0' , 'cmd' : 'rpm -q iptables; echo $?' , 'required' : 'yes'}, '4.1.1.1': {'parameter':'Ensure auditd is installed' , 'validation':'0' , 'cmd' : 'rpm -qa auditd; echo $?' , 'required' : 'yes'}, '4.2.1.1': {'parameter':'Ensure rsyslog is installed' , 'validation':'0' , 'cmd' : 'rpm  -qa rsyslog; echo $?' , 'required' : 'yes'}}
 
        for i in l:
            x=os.popen(l[i]['cmd'])
            y=x.read()
            y=y.split("\n")[-2]
            y=y.strip()
            #print(y)
            if l[i]['validation'] in y:
                l[i]['results']='Present'
            else:
                l[i]['results']='Not Present'
 
            if l[i]['required']=='no' and l[i]['results']=='Not Present':
                l[i]['status']='Pass'
            elif l[i]['required']=='yes' and l[i]['results']=='Present':
                l[i]['status']='Pass'
            else:
                l[i]['status']='Fail'
 
        rpm = l
        return rpm
    except Exception as e:
        return e
 
def stat():
    try:
        l = {'1.5.2': {'parameter':'Ensure permissions on bootloader config are configured' , 'validation':'Access: (0600/-rw-------)' , 'cmd' : 'stat /boot/grub2/grub.cfg' , 'required' : 'yes'}, '1.8.1.5': {'parameter':'Ensure permissions on /etc/issue are configured' , 'validation':'Access: (0644/-rw-r--r--)' , 'cmd' : 'stat /etc/issue' , 'required' : 'yes'}, '5.1.2': {'parameter':'Ensure permissions on /etc/crontab are configured' , 'validation':'Access: (0600/-rw-------)' , 'cmd' : 'stat /etc/crontab' , 'required' : 'yes'}, '5.1.3': {'parameter':'Ensure permissions on /etc/cron.hourly are configured' , 'validation':'Access: (0600/-rw-------)' , 'cmd' : 'stat /etc/cron.hourly' , 'required' : 'yes'}, '5.1.4': {'parameter':'Ensure permissions on /etc/cron.daily are configured' , 'validation':'Access: (0600/-rw-------)' , 'cmd' : 'stat /etc/cron.daily' , 'required' : 'yes'}, '5.1.5': {'parameter':'Ensure permissions on /etc/cron.weekly are configured' , 'validation':'Access: (0600/-rw-------)' , 'cmd' : 'stat /etc/cron.weekly' , 'required' : 'yes'}, '5.1.6': {'parameter':'Ensure permissions on /etc/cron.monthly are configured' , 'validation':'Access: (0600/-rw-------)' , 'cmd' : 'stat /etc/cron.monthly' , 'required' : 'yes'}, '5.1.7': {'parameter':'Ensure permissions on /etc/cron.d are configured' , 'validation':'Access: (0600/-rw-------)' , 'cmd' : 'stat /etc/cron.d' , 'required' : 'yes'}, '5.1.8': {'parameter':'Ensure cron is restricted to authorized users' , 'validation':'No such file or directory' , 'cmd' : 'stat /etc/cron.deny' , 'required' : 'yes'}, '5.1.9': {'parameter':'Ensure at is restricted to authorized users' , 'validation':'No such file or directory' , 'cmd' : 'stat /etc/at.deny' , 'required' : 'yes'}, '5.2.1': {'parameter':'Ensure permissions on /etc/ssh/sshd_config are configured' , 'validation':'Access: (0600/-rw-------)' , 'cmd' : 'stat /etc/ssh/sshd_config' , 'required' : 'yes'}, '6.1.2': {'parameter':'Ensure permissions on /etc/passwd are configured' , 'validation':'Access: (0644/-rw-r--r--)' , 'cmd' : 'stat /etc/passwd' , 'required' : 'yes'}, '6.1.3': {'parameter':'Ensure permissions on /etc/shadow are configured' , 'validation':'Access: (0000/----------)' , 'cmd' : 'stat /etc/shadow' , 'required' : 'yes'}, '6.1.4': {'parameter':'Ensure permissions on /etc/group are configured' , 'validation':'Access: (0644/-rw-r--r--)' , 'cmd' : 'stat /etc/group' , 'required' : 'yes'}, '6.1.5': {'parameter':'Ensure permissions on /etc/gshadow are configured' , 'validation':'Access: (0600/-rw-------)' , 'cmd' : 'stat /etc/gshadow' , 'required' : 'yes'}, '6.1.6': {'parameter':'Ensure permissions on /etc/passwd- are configured' , 'validation':'Access: (0600/-rw-------)' , 'cmd' : 'stat /etc/passwd-' , 'required' : 'yes'}, '6.1.7': {'parameter':'Ensure permissions on /etc/shadow- are configured' , 'validation':'Access: (0600/-rw-------)' , 'cmd' : 'stat /etc/shadow-' , 'required' : 'yes'}, '6.1.8': {'parameter':'Ensure permissions on /etc/group- are configured' , 'validation':'Access: (0600/-rw-------)' , 'cmd' : 'stat /etc/group-' , 'required' : 'yes'}, '6.1.9': {'parameter':'Ensure permissions on /etc/gshadow- are configured' , 'validation':'Access: (0600/-rw-------)' , 'cmd' : 'stat /etc/gshadow-' , 'required' : 'yes'}}
 
        for i in l:
            x=os.popen(l[i]['cmd'])
            y=x.read()
 
            if l[i]['validation'] in y:
                l[i]['status']='Pass'
            else:
                l[i]['status']='Fail'
 
        #for i in l:
            #print(i)
        stat = l
        return stat
    except Exception as e:
        return e
 
def sysctl():
    try:
        l = {'1.6.3': {'parameter':'Ensure address space layout randomization (ASLR) is enabled' , 'validation':'kernel.randomize_va_space = 2' , 'cmd' : 'sysctl kernel.randomize_va_space'}, '3.2.1': {'parameter':'Ensure IP forwarding is disabled' , 'validation':'net.ipv4.ip_forward = 0' , 'cmd' : 'sysctl net.ipv4.ip_forward'}, '3.2.2': {'parameter':'Ensure packet redirect sending is disabled' , 'validation':'net.ipv4.conf.all.send_redirects = 0' , 'cmd' : 'sysctl net.ipv4.conf.all.send_redirects'}, '3.2.2': {'parameter':'Ensure packet redirect sending is disabled' , 'validation':'net.ipv4.conf.default.send_redirects = 0' , 'cmd' : 'sysctl net.ipv4.conf.default.send_redirects'}, '3.3.1': {'parameter':'Ensure source routed packets are not accepted' , 'validation':'net.ipv4.conf.all.accept_source_route = 0' , 'cmd' : 'sysctl net.ipv4.conf.all.accept_source_route'}, '3.3.1': {'parameter':'Ensure source routed packets are not accepted' , 'validation':'net.ipv4.conf.default.accept_source_route = 0' , 'cmd' : 'sysctl net.ipv4.conf.default.accept_source_route'}, '3.3.2': {'parameter':'Ensure ICMP redirects are not accepted' , 'validation':'net.ipv4.conf.all.accept_redirects = 0' , 'cmd' : 'sysctl net.ipv4.conf.all.accept_redirects'}, '3.3.2': {'parameter':'Ensure ICMP redirects are not accepted' , 'validation':'net.ipv4.conf.default.accept_redirects = 0' , 'cmd' : 'sysctl net.ipv4.conf.default.accept_redirects'}, '3.3.3': {'parameter':'Ensure secure ICMP redirects are not accepted' , 'validation':'net.ipv4.conf.all.secure_redirects = 0' , 'cmd' : 'sysctl net.ipv4.conf.all.secure_redirects'}, '3.3.3': {'parameter':'Ensure secure ICMP redirects are not accepted' , 'validation':'net.ipv4.conf.default.secure_redirects = 0' , 'cmd' : 'sysctl net.ipv4.conf.default.secure_redirects'}, '3.3.4': {'parameter':'Ensure suspicious packets are logged' , 'validation':'net.ipv4.conf.all.log_martians = 1' , 'cmd' : 'sysctl net.ipv4.conf.all.log_martians'}, '3.3.4': {'parameter':'Ensure suspicious packets are logged' , 'validation':'net.ipv4.conf.default.log_martians = 1' , 'cmd' : 'sysctl net.ipv4.conf.default.log_martians'}, '3.3.5': {'parameter':'Ensure broadcast ICMP requests are ignored' , 'validation':'net.ipv4.icmp_echo_ignore_broadcasts = 1' , 'cmd' : 'sysctl net.ipv4.icmp_echo_ignore_broadcasts'}, '3.3.6': {'parameter':'Ensure bogus ICMP responses are ignored' , 'validation':'net.ipv4.icmp_ignore_bogus_error_responses = 1' , 'cmd' : 'sysctl net.ipv4.icmp_ignore_bogus_error_responses'}, '3.3.7': {'parameter':'Ensure Reverse Path Filtering is enabled' , 'validation':'net.ipv4.conf.all.rp_filter = 1' , 'cmd' : 'sysctl net.ipv4.conf.all.rp_filter'}, '3.3.7': {'parameter':'Ensure Reverse Path Filtering is enabled' , 'validation':'net.ipv4.conf.default.rp_filter = 1' , 'cmd' : 'sysctl net.ipv4.conf.default.rp_filter'} ,   '3.3.8': {'parameter':'Ensure TCP SYN Cookies is enabled' , 'validation':'net.ipv4.tcp_syncookies = 1' , 'cmd' : 'sysctl net.ipv4.tcp_syncookies'}, '4.1.1.2': {'parameter':'Ensure auditd service is enabled and running' , 'validation':'enabled' , 'cmd' : 'systemctl is-enabled auditd'}, '4.2.1.2': {'parameter':'Ensure rsyslog Service is enabled and running' , 'validation':'enabled' , 'cmd' : 'systemctl is-enabled rsyslog'}, '5.1.1': {'parameter':'Ensure cron daemon is enabled and running' , 'validation':'enabled' , 'cmd' : 'systemctl is-enabled crond'}}
 
        for i in l:
            x=os.popen(l[i]['cmd'])
            y=x.read()
            if l[i]['validation'] in y:
                l[i]['status']='Pass'
            else:
                l[i]['status']='Fail'
        sysctl = l
        return sysctl
    except Exception as e:
        return e
 
def systemctl():
    try:
        l = {'1.1.23': {'parameter':'Disable Automounting' , 'validation':'active (running)' , 'cmd' : 'systemctl is-enabled autofs' , 'required' : 'no'}, '2.2.4': {'parameter':'Ensure CUPS is not installed' , 'validation':'active (running)' , 'cmd' : 'systemctl is-enabled cups' , 'required' : 'no'}, '2.2.5': {'parameter':'Ensure DHCP Server is not installed' , 'validation':'active (running)' , 'cmd' : 'systemctl status dhcpd' , 'required' : 'no'}, '2.2.6': {'parameter':'Ensure LDAP Server is not installed' , 'validation':'active (running)' , 'cmd' : 'systemctl status slapd' , 'required' : 'no'}, '2.2.8': {'parameter':'Ensure rpcbind is not installed or the rpcbind services are masked' , 'validation':'active (running) ' , 'cmd' : 'systemctl status rpcbind' , 'required' : 'no'}, '2.2.9': {'parameter':'Ensure DNS Server is not installed' , 'validation':'active (running)' , 'cmd' : 'systemctl status named' , 'required' : 'no'}, '2.2.10': {'parameter':'Ensure FTP Server is not installed' , 'validation':'active (running)' , 'cmd' : 'systemctl status vsftpd' , 'required' : 'no'}, '2.2.11': {'parameter':'Ensure HTTP server is not installed' , 'validation':'active (running)' , 'cmd' : 'systemctl status httpd' , 'required' : 'no'}, '2.2.12': {'parameter':'Ensure IMAP and POP3 server is not installed' , 'validation':'active (running)' , 'cmd' : 'systemctl status dovecot' , 'required' : 'no'}, '2.2.13': {'parameter':'Ensure Samba is not installed' , 'validation':'active (running)' , 'cmd' : 'systemctl status smb' , 'required' : 'no'}, '2.2.14': {'parameter':'Ensure HTTP Proxy Server is not installed' , 'validation':'active (running)' , 'cmd' : 'systemctl status squid' , 'required' : 'no'}, '2.2.17': {'parameter':'Ensure rsync is not installed or the rsyncd service is masked' , 'validation':'active (running)' , 'cmd' : 'systemctl status rsyncd' , 'required' : 'no'}, '2.2.18': {'parameter':'Ensure NIS server is not installed' , 'validation':'active (running)' , 'cmd' : 'systemctl status ypserv' , 'required' : 'no'}, '3.5.1.1': {'parameter':'Ensure FirewallD is installed' , 'validation':'active (running)' , 'cmd' : 'systemctl status firewalld' , 'required' : 'yes'}, '3.5.1.2': {'parameter':'Ensure iptables-services package is not installed' , 'validation':'active (running)' , 'cmd' : 'systemctl status iptables' , 'required' : 'no'}}
 
        for i in l:
            x=os.popen(l[i]['cmd'])
            y=x.read()
 
            if l[i]['validation'] in y:
                l[i]['results']='Active'
            else:
                l[i]['results']='Not Active'
           
            if l[i]['required']=='no' and l[i]['results']=='Not Active':
                l[i]['status']='Pass'
            elif l[i]['required']=='yes' and l[i]['results']=='Active':
                l[i]['status']='Pass'
            else:
                l[i]['status']='Fail'
       
        #for i in l:
            #print(i)
        systemctl = l
        return systemctl
    except Exception as e:
        return e
 
def appender(method_cmd):
    fo=[]
    for key in method_cmd:
        tl = []
        tl.append(key)
        tl.append(method_cmd[key]['parameter'])
        tl.append(method_cmd[key]['status'])
        fo.append(tl)
    return fo
 
def main():
    result={}
    finaloutput=[]
    try:
        result['bash']=bash()
        #finaloutput.append(appender(result['bash']))
        result['grep']=grep()
        #finaloutput.append(appender(result['grep']))
        result['log']=log()
        #finaloutput.append(appender(result['log']))
        result['mod']=mod()
        #finaloutput.append(appender(result['mod']))
        result['mount']=mount()
        #finaloutput.append(appender(result['mount']))
        result['rpm']=rpm()
        #finaloutput.append(appender(result['rpm']))
        result['stat']=stat()
        #finaloutput.append(appender(result['stat']))
        result['sysctl']=sysctl()
        #finaloutput.append(appender(result['sysctl']))
        result['systemctl']=systemctl()
        #finaloutput.append(appender(result['systemctl']))
       
        module.exit_json(changed='false', meta=result)
 
    except Exception as e:
        msg = "Failed"
        module.fail_json(msg=msg)
 
if __name__ == '__main__':
    main()