#!/bin/bash
#
# setup-smtp.sh — Complete SMTP Server Setup Script
# Targets: Ubuntu 22.04 / 24.04 LTS on Hetzner, Contabo, or similar VPS
# Run as root: sudo bash setup-smtp.sh
#
set -e

# ──────────────────────────────────────────────────────────────────────
# CONFIGURATION — EDIT THESE BEFORE RUNNING
# ──────────────────────────────────────────────────────────────────────
DOMAIN="pantwestconsultant.net"               # Your domain (must own DNS)
HOSTNAME="mail.${DOMAIN}"             # Server FQDN — set rDNS to this
SELECTOR="mail"                       # DKIM selector (can be anything)
ADMIN_EMAIL="contact@${DOMAIN}"         # Where system mail goes
# ──────────────────────────────────────────────────────────────────────

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  SMTP Server Setup for ${DOMAIN}${NC}"
echo -e "${GREEN}========================================${NC}"

# ── 1. System Updates & Hostname ────────────────────────────────────
echo -e "\n${YELLOW}[1/8] Setting hostname and updating system...${NC}"

hostnamectl set-hostname "${HOSTNAME}"
echo "${HOSTNAME}" > /etc/hostname

# Add to /etc/hosts if not already there
if ! grep -q "${HOSTNAME}" /etc/hosts; then
    # Get primary IP
    IP=$(ip route get 1 | awk '{print $7; exit}')
    echo "${IP} ${HOSTNAME} ${DOMAIN}" >> /etc/hosts
fi

apt-get update -qq && apt-get upgrade -y -qq

# ── 2. Install Packages ─────────────────────────────────────────────
echo -e "\n${YELLOW}[2/8] Installing Postfix, OpenDKIM, and deps...${NC}"

# Pre-seed Postfix config to avoid interactive prompts
debconf-set-selections <<< "postfix postfix/mailname string ${HOSTNAME}"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

apt-get install -y -qq \
    postfix \
    postfix-policyd-spf-python \
    opendkim \
    opendkim-tools \
    libsasl2-modules \
    bind9-dnsutils \
    mailutils \
    certbot

# ── 3. Configure Postfix (Send-Only, Secure) ────────────────────────
echo -e "\n${YELLOW}[3/8] Configuring Postfix...${NC}"

cat > /etc/postfix/main.cf << 'POSTFIX_EOF'
# ── Basic ───────────────────────────────────────────
smtpd_banner = $myhostname ESMTP
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 3.6

# ── Hostname & Domain ───────────────────────────────
myhostname = MAILHOSTNAME_PLACEHOLDER
mydomain = DOMAIN_PLACEHOLDER
myorigin = $mydomain
mydestination = $myhostname, localhost.$mydomain, localhost

# ── Send-Only (loopback-only for inbound) ───────────
inet_interfaces = all
inet_protocols = ipv4

# ── Outbound Relay — Direct Delivery ────────────────
relayhost =
# No smarthost — deliver directly via DNS MX records

# ── TLS: Always encrypt outbound ────────────────────
smtp_tls_security_level = may
smtp_tls_loglevel = 1
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_mandatory_ciphers = medium

# ── Message Size ────────────────────────────────────
message_size_limit = 25600000

# ── DKIM Milter ────────────────────────────────────
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:127.0.0.1:8891
non_smtpd_milters = inet:127.0.0.1:8891

# ── SPF Policy Agent ───────────────────────────────
policyd-spf_time_limit = 3600
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    check_policy_service unix:private/policyd-spf

# ── Rate Limits (prevents abuse spikes) ────────────
default_destination_concurrency_limit = 20
default_destination_recipient_limit = 50
smtp_destination_concurrency_limit = 10
smtp_extra_connection_limit = 5
POSTFIX_EOF

# Substitute placeholders
sed -i "s/MAILHOSTNAME_PLACEHOLDER/${HOSTNAME}/g" /etc/postfix/main.cf
sed -i "s/DOMAIN_PLACEHOLDER/${DOMAIN}/g" /etc/postfix/main.cf

# ── Configure SPF policy agent ─────────────────────
cat > /etc/postfix-policyd-spf-python/policyd-spf.conf << 'SPF_EOF'
# SPF Policy configuration
HELO_reject = False
Mail_From_reject = False
SPF_Not_Pass = reject
SPF_Not_Pass_Defer = False
SPF_Not_Pass_Reject_Defer = False
SPF_Not_Pass_Temp_Error_Defer = False
SPF_Pass_Good_Enough = True
SPF_Guess = v=spf1 a mx ~all
SPF_Internal_IPs = 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
SPF_Default_Policy_For_Unknown_Helo_Scoring = 0.0
SPF_Default_Policy_For_Unknown_MailFrom_Scoring = 3.0
SPF_Default_Whitelist_Scoring = 0.0
SPF_Minimum_Score_For_Rejection = 4.0
SPF_Expand_Limit = 5
SPF_Max_DNS_Requests = 20
SPF_Enabled_On_Startup = True
SPF_Policy_Enabled = True
SPF_Log_Level = 1
SPF_Milter_Log_Level = 1
SPF_Sender_Config = True
SPF_Helo_Config = True
SPF_Reject_Code = 550
SPF_Reject_Message = Rejected due to SPF failure
SPF_Defer_Message = Temporarily rejected due to SPF failure
SPF_Defer_Code = 450
SPF_Milter_Defer_Code = 450
SPF_Milter_Reject_Code = 550
SPF_Milter_Reject_Message = Rejected due to SPF failure
SPF_Policy_Per_Domain = True
SPF_Domain_Policy_File = /etc/postfix-policyd-spf-python/spf_domain_policy
SPF_Policy_Default_Domain_Policy = ~all
SPF_Policy_Default_Domain_Reject_Message = Rejected due to SPF failure
SPF_Policy_Default_Domain_Defer_Message = Temporarily rejected due to SPF failure
SPF_Policy_Default_Domain_Reject_Code = 550
SPF_Policy_Default_Domain_Defer_Code = 450
SPF_Policy_Default_Domain_Reject_Reason = SPF check failed
SPF_Policy_Default_Domain_Defer_Reason = SPF check deferred
SPF_Policy_Default_Domain_Reject_Defer_Reason = SPF check deferred/rejected
SPF_Policy_Default_Domain_Reject_Defer_Code = 450
SPF_Policy_Default_Domain_Reject_Defer_Message = Temporarily rejected due to SPF failure
SPF_Policy_Default_Domain_Reject_Defer_Defer_Message = Temporarily rejected due to SPF failure
SPF_Policy_Default_Domain_Reject_Defer_Reject_Message = Rejected due to SPF failure
SPF_Policy_Default_Domain_Reject_Defer_Reject_Code = 550
SPF_Policy_Default_Domain_Reject_Defer_Defer_Code = 450
SPF_Policy_Default_Domain_Reject_Defer_Reject_Reason = SPF check failed
SPF_Policy_Default_Domain_Reject_Defer_Defer_Reason = SPF check deferred
SPF_Policy_Default_Domain_Reject_Defer_Reject_Defer_Reason = SPF check deferred/rejected
SPF_Policy_Default_Domain_Reject_Defer_Reject_Defer_Code = 450
SPF_Policy_Default_Domain_Reject_Defer_Reject_Defer_Message = Temporarily rejected due to SPF failure
SPF_Policy_Default_Domain_Reject_Defer_Reject_Defer_Reject_Message = Rejected due to SPF failure
SPF_Policy_Default_Domain_Reject_Defer_Reject_Defer_Reject_Code = 550
SPF_Policy_Default_Domain_Reject_Defer_Reject_Defer_Defer_Code = 450
SPF_Policy_Default_Domain_Reject_Defer_Reject_Defer_Reject_Reason = SPF check failed
SPF_Policy_Default_Domain_Reject_Defer_Reject_Defer_Defer_Reason = SPF check deferred
SPF_Policy_Default_Domain_Reject_Defer_Reject_Defer_Reject_Defer_Reason = SPF check deferred/rejected
SPF_Policy_Default_Domain_Reject_Defer_Reject_Defer_Reject_Defer_Code = 450
SPF_Policy_Default_Domain_Reject_Defer_Reject_Defer_Reject_Defer_Message = Temporarily rejected due to SPF failure
SPF_EOF

# Add SPF policy to master.cf
if ! grep -q "policyd-spf" /etc/postfix/master.cf; then
    cat >> /etc/postfix/master.cf << 'MASTER_SPF_EOF'

# SPF policy agent
policyd-spf  unix  -       n       n       -       0       spawn
    user=policyd-spf argv=/usr/bin/policyd-spf
MASTER_SPF_EOF
fi

# ── 4. Configure OpenDKIM ──────────────────────────────────────────
echo -e "\n${YELLOW}[4/8] Configuring OpenDKIM...${NC}"

mkdir -p /etc/opendkim/keys/${DOMAIN}

cat > /etc/opendkim.conf << 'DKIM_EOF'
# OpenDKIM configuration
Syslog                  yes
UMask                   002
LogWhy                  yes
Mode                    sv
SubDomains              no
OversignHeaders         From
AutoRestart             yes
AutoRestartRate         10/1M
Background              yes
Canonicalization        relaxed/simple
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
SignatureAlgorithm      rsa-sha256
Socket                  inet:8891@127.0.0.1
PidFile                 /run/opendkim/opendkim.pid
DKIM_EOF

# Generate DKIM keys
cd /etc/opendkim/keys/${DOMAIN}
opendkim-genkey -D /etc/opendkim/keys/${DOMAIN}/ -d ${DOMAIN} -s ${SELECTOR} -b 2048
chown -R opendkim:opendkim /etc/opendkim

# KeyTable
cat > /etc/opendkim/KeyTable << KEYTABLE_EOF
${SELECTOR}._domainkey.${DOMAIN} ${DOMAIN}:${SELECTOR}:/etc/opendkim/keys/${DOMAIN}/${SELECTOR}.private
KEYTABLE_EOF

# SigningTable
cat > /etc/opendkim/SigningTable << SIGNINGTABLE_EOF
*@${DOMAIN} ${SELECTOR}._domainkey.${DOMAIN}
SIGNINGTABLE_EOF

# TrustedHosts
cat > /etc/opendkim/TrustedHosts << TRUSTED_EOF
127.0.0.1
::1
localhost
${DOMAIN}
${HOSTNAME}
TRUSTED_EOF

# ── 5. Restart Services ────────────────────────────────────────────
echo -e "\n${YELLOW}[5/8] Restarting services...${NC}"

systemctl enable opendkim
systemctl restart opendkim
systemctl restart postfix


 chown root:root /etc
 chmod 755 /etc

 chown root:root /etc/opendkim
 chmod 755 /etc/opendkim

 chown root:root /etc/opendkim/keys
 chmod 755 /etc/opendkim/keys

 chown opendkim:opendkim /etc/opendkim/keys/panwestconsultant.net
 chmod 750 /etc/opendkim/keys/panwestconsultant.net

 chown opendkim:opendkim /etc/opendkim/keys/panwestconsultant.net/mail.private
 chmod 600 /etc/opendkim/keys/panwestconsultant.net/mail.private



 chown root:root /etc/opendkim/keys/panwestconsultant.net
 chmod 755 /etc/opendkim/keys/panwestconsultant.net

 chown opendkim:opendkim /etc/opendkim/keys/panwestconsultant.net/mail.private
 chmod 600 /etc/opendkim/keys/panwestconsultant.net/mail.private

 systemctl restart opendkim
 systemctl restart postfix


# ── 6. nginx configuration ────────────────────────────────────────────
echo -e "\n${YELLOW}[6/8]Installing nginx and configuring MTA-STS...${NC}"

sudo apt update
sudo apt install nginx certbot python3-certbot-nginx -y
sudo mkdir -p /var/www/mta-sts/.well-known

cat > /var/www/mta-sts/.well-known/mta-sts.txt << MTA_STS_EOF
version: STSv1
mode: enforce
mx: ${HOSTNAME}
max_age: 86400
MTA_STS_EOF     

#-7. Create nginx config for MTA-STS
echo -e "\n${YELLOW}[7/8]Create nginx config for MTA-STS...${NC}"

cat > /etc/nginx/sites-available/mta-sts.conf << NGINX_MTA_EOF
server {
    listen 80;
    server_name mta-sts.${DOMAIN};

    root /var/www/mta-sts;

    location /.well-known/mta-sts.txt {
        default_type text/plain;
    }
}
NGINX_MTA_EOF
ln -s /etc/nginx/sites-available/mta-sts.conf /etc/nginx/sites-enabled/mta-sts.conf
nginx -t && systemctl reload nginx

sudo certbot --nginx -d mta-sts.${DOMAIN} --non-interactive --agree-tos -m ${ADMIN_EMAIL}


# ── 8. Display DKIM Public Key ─────────────────────────────────────
echo -e "\n${YELLOW}[8/8] DKIM public key — add this to your DNS:${NC}"
echo -e "${GREEN}=====================================================${NC}"
cat /etc/opendkim/keys/${DOMAIN}/${SELECTOR}.txt
echo -e "${GREEN}=====================================================${NC}"

# ── 9. Firewall Rules ──────────────────────────────────────────────
echo -e "\n${YELLOW}[9/8] Configuring firewall...${NC}"

# Check for ufw
if command -v ufw &> /dev/null; then
    ufw allow 25/tcp
    ufw allow 465/tcp
    ufw allow 587/tcp
    echo "UFW rules added for ports 25, 465, 587"
fi

# Also check for iptables/nftables fallback (common on Hetzner)
if ! command -v ufw &> /dev/null; then
    echo "UFW not found. Ensure your VPS firewall (Hetzner/Contabo panel) allows:"
    echo "  - Inbound TCP 25, 465, 587"
    echo "  - Outbound TCP 25 (may be blocked — see notes below)"
fi


# ── 1 adding users to smtp ─────────────────────────────────────────────
echo -e "\n${YELLOW}[1/8] adding users to smtp... ${NC}"
echo -e "\n${YELLOW}installing packages... ${NC}"
sudo apt update
sudo apt install sasl2-bin libsasl2-modules -y

# ---2 enable postfix sasl authentication
echo -e "\n${YELLOW}[2/8] enabling postfix submission service... ${NC}"
cat >> /etc/postfix/master.cf << EOF
#
# Postfix master process configuration file.  For details on the format
# of the file, see the master(5) manual page (command: "man 5 master" or
# on-line: http://www.postfix.org/master.5.html).
#
# Do not forget to execute "postfix reload" after editing this file.
#
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (no)    (never) (100)
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
# ==========================================================================
smtp      inet  n       -       y       -       -       smtpd
#smtp      inet  n       -       y       -       1       postscreen
#smtpd     pass  -       -       y       -       -       smtpd
#dnsblog   unix  -       -       y       -       0       dnsblog
#tlsproxy  unix  -       -       y       -       0       tlsproxy
# Choose one: enable submission for loopback clients only, or for any client.
#127.0.0.1:submission inet n -   y       -       -       smtpd
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
#  -o smtpd_tls_auth_only=yes
#  -o local_header_rewrite_clients=static:all
#  -o smtpd_reject_unlisted_recipient=no
#     Instead of specifying complex smtpd_<xxx>_restrictions here,
#     specify "smtpd_<xxx>_restrictions=$mua_<xxx>_restrictions"
#     here, and specify mua_<xxx>_restrictions in main.cf (where
#     "<xxx>" is "client", "helo", "sender", "relay", or "recipient").
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
#  -o smtpd_helo_restrictions=
#  -o smtpd_sender_restrictions=
#  -o smtpd_relay_restrictions=
#  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o smtpd_sender_login_maps=
  -o milter_macro_daemon_name=ORIGINATING
# Choose one: enable submissions for loopback clients only, or for any client.
#127.0.0.1:submissions inet n  -       y       -       -       smtpd
#submissions     inet  n       -       y       -       -       smtpd
#  -o syslog_name=postfix/submissions
#  -o smtpd_tls_wrappermode=yes
#  -o smtpd_sasl_auth_enable=yes
#  -o local_header_rewrite_clients=static:all
#  -o smtpd_reject_unlisted_recipient=no
#     Instead of specifying complex smtpd_<xxx>_restrictions here,
#     specify "smtpd_<xxx>_restrictions=$mua_<xxx>_restrictions"
#     here, and specify mua_<xxx>_restrictions in main.cf (where
#     "<xxx>" is "client", "helo", "sender", "relay", or "recipient").
#  -o smtpd_client_restrictions=
#  -o smtpd_helo_restrictions=
#  -o smtpd_sender_restrictions=
#  -o smtpd_relay_restrictions=
#  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
#  -o milter_macro_daemon_name=ORIGINATING
#628       inet  n       -       y       -       -       qmqpd
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
#qmgr     unix  n       -       n       300     1       oqmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
defer     unix  -       -       y       -       0       bounce
trace     unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       y       -       -       smtp
relay     unix  -       -       y       -       -       smtp
        -o syslog_name=${multi_instance_name?{$multi_instance_name}:{postfix}}/$service_name
#       -o smtp_helo_timeout=5 -o smtp_connect_timeout=5
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
#
# ====================================================================
# Interfaces to non-Postfix software. Be sure to examine the manual
# pages of the non-Postfix software to find out what options it wants.
#
# Many of the following services use the Postfix pipe(8) delivery
# agent.  See the pipe(8) man page for information about ${recipient}
# and other message envelope options.
# ====================================================================
#
# maildrop. See the Postfix MAILDROP_README file for details.
# Also specify in main.cf: maildrop_destination_recipient_limit=1
#
#maildrop  unix  -       n       n       -       -       pipe
#  flags=DRXhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
#
# ====================================================================
#
# Recent Cyrus versions can use the existing "lmtp" master.cf entry.
#
# Specify in cyrus.conf:
#   lmtp    cmd="lmtpd -a" listen="localhost:lmtp" proto=tcp4
#
# Specify in main.cf one or more of the following:
#  mailbox_transport = lmtp:inet:localhost
#  virtual_transport = lmtp:inet:localhost
#
# ====================================================================
#
# Cyrus 2.1.5 (Amos Gouaux)
# Also specify in main.cf: cyrus_destination_recipient_limit=1
#
#cyrus     unix  -       n       n       -       -       pipe
#  flags=DRX user=cyrus argv=/cyrus/bin/deliver -e -r ${sender} -m ${extension} ${user}
#
# ====================================================================
#
# Old example of delivery via Cyrus.
#
#old-cyrus unix  -       n       n       -       -       pipe
#  flags=R user=cyrus argv=/cyrus/bin/deliver -e -m ${extension} ${user}
#
# ====================================================================
#
# See the Postfix UUCP_README file for configuration details.
#
#uucp      unix  -       n       n       -       -       pipe
#  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
#
# ====================================================================
#
# Other external delivery methods.
#
#ifmail    unix  -       n       n       -       -       pipe
#  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
#
#bsmtp     unix  -       n       n       -       -       pipe
#  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -f $sender $nexthop $recipient
#
#scalemail-backend unix -       n       n       -       2       pipe
#  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store
#  ${nexthop} ${user} ${extension}
#
#mailman   unix  -       n       n       -       -       pipe
#  flags=FRX user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
#  ${nexthop} ${user}

# SPF policy agent
policyd-spf  unix  -       n       n       -       0       spawn
    user=policyd-spf argv=/usr/bin/policyd-spf
EOF


echo -e "copying config to main.cf... ${NC}"
cat >> /etc/postfix/main.cf << EOF
# ── Basic ───────────────────────────────────────────
smtpd_banner = $myhostname ESMTP
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 3.6

# ── Hostname & Domain ───────────────────────────────
myhostname = mail.panwestconsultant.net
mydomain = panwestconsultant.net
myorigin = $mydomain
mydestination = $myhostname, localhost.$mydomain, localhost

# ── Send-Only (loopback-only for inbound) ───────────
inet_interfaces = all
inet_protocols = ipv4

# ── Outbound Relay — Direct Delivery ────────────────
relayhost =
# No smarthost — deliver directly via DNS MX records

# ── TLS: Always encrypt outbound ────────────────────
smtp_tls_security_level = may
smtp_tls_loglevel = 1
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_mandatory_ciphers = medium

# ── Message Size ────────────────────────────────────
message_size_limit = 25600000

# ── DKIM Milter ────────────────────────────────────
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:127.0.0.1:8891
non_smtpd_milters = inet:127.0.0.1:8891

# ── SPF Policy Agent ───────────────────────────────
policyd-spf_time_limit = 3600
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    check_policy_service unix:private/policyd-spf

# ── Rate Limits (prevents abuse spikes) ────────────
default_destination_concurrency_limit = 20
default_destination_recipient_limit = 50
smtp_destination_concurrency_limit = 10

smtpd_sasl_type = cyrus
smtpd_sasl_path = smtpd
smtpd_sasl_auth_enable = yes
broken_sasl_auth_clients = yes

smtpd_tls_auth_only = yes

smtpd_tls_cert_file=/etc/letsencrypt/live/mail.panwestconsultant.net/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/mail.panwestconsultant.net/privkey.pem
smtpd_sasl_security_options = noanonymous
EOF

echo -e "[4/8] Copying sasl config... ${NC}"
cat > /etc/default/saslauthd << EOF
#
# Settings for saslauthd daemon
# Please read /usr/share/doc/sasl2-bin/README.Debian.gz for details.
#
START=yes
# Description of this saslauthd instance. Recommended.
# (suggestion: SASL Authentication Daemon)
DESC="SASL Authentication Daemon"

# Short name of this saslauthd instance. Strongly recommended.
# (suggestion: saslauthd)
NAME="saslauthd"

# Which authentication mechanisms should saslauthd use? (default: pam)
#
# Available options in this Debian package:
# getpwent  -- use the getpwent() library function
# kerberos5 -- use Kerberos 5
# pam       -- use PAM
# rimap     -- use a remote IMAP server
# shadow    -- use the local shadow password file
# sasldb    -- use the local sasldb database file
# ldap      -- use LDAP (configuration is in /etc/saslauthd.conf)
#
# Only one option may be used at a time. See the saslauthd man page
# for more information.
#
# Example: MECHANISMS="pam"
MECHANISMS="pam"

# Additional options for this mechanism. (default: none)
# See the saslauthd man page for information about mech-specific options.
MECH_OPTIONS=""

# How many saslauthd processes should we run? (default: 5)
# A value of 0 will fork a new process for each connection.
THREADS=5

# Other options (default: -c -m /var/run/saslauthd)
# Note: You MUST specify the -m option or saslauthd won't run!
#
# WARNING: DO NOT SPECIFY THE -d OPTION.
# The -d option will cause saslauthd to run in the foreground instead of as
# a daemon. This will PREVENT YOUR SYSTEM FROM BOOTING PROPERLY. If you wish
# to run saslauthd in debug mode, please run it by hand to be safe.
#
# See the saslauthd man page and the output of 'saslauthd -h' for general
# information about these options.
#
# Example for chroot Postfix users: "-c -m /var/spool/postfix/var/run/saslauthd"
# Example for non-chroot Postfix users: "-c -m /var/run/saslauthd"
#
# To know if your Postfix is running chroot, check /etc/postfix/master.cf.
# If it has the line "smtp inet n - y - - smtpd" or "smtp inet n - - - - smtpd"
# then your Postfix is running in a chroot.
# If it has the line "smtp inet n - n - - smtpd" then your Postfix is NOT
# running in a chroo
OPTIONS="-c -m /run/saslauthd"
EOF

echo -e "\n${YELLOW}[5/8] Restarting saslauthd... ${NC}"
sudo systemctl restart saslauthd
systemctl status saslauthd --no-pager -l

echo -e "\n${YELLOW}[6/8] Creating saslauthd user... ${NC}"
sudo adduser smtpuser --disabled-password --gecos ""
echo "smtpuser:strongpassword" | sudo chpasswd
testsaslauthd -u smtpuser -p strongpassword

echo -e "\n${YELLOW}[7/8] Opening firewall ports... ${NC}"
sudo ufw allow 587/tcp
sudo ufw allow 465/tcp

echo -e "\n${YELLOW}[8/8] Restarting postfix... ${NC}"
sudo systemctl restart saslauthd
sudo systemctl restart postfix


# ── 10. Summary ─────────────────────────────────────────────────────
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}  SETUP COMPLETE${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Hostname:       ${HOSTNAME}"
echo -e "Domain:         ${DOMAIN}"
echo -e "DKIM Selector:  ${SELECTOR}"
echo -e "Server IP:      $(ip route get 1 | awk '{print $7; exit}')"
echo ""
echo -e "${YELLOW}NEXT STEPS — DO THESE MANUALLY IN YOUR DNS PROVIDER:${NC}"
echo ""
echo "──────────────────────────────────────────────"
echo "1. A RECORD"
echo "   Host: mail"
echo "   Type: A"
echo "   Value: $(ip route get 1 | awk '{print $7; exit}')"
echo ""
echo "2. MX RECORD"
echo "   Host: @"
echo "   Type: MX"
echo "   Priority: 10"
echo "   Value: ${HOSTNAME}"
echo ""
echo "3. SPF RECORD"
echo "   Host: @"
echo "   Type: TXT"
echo "   Value: v=spf1 mx a:${HOSTNAME} ~all"
echo ""
echo "4. DKIM RECORD (from the key shown above)"
echo "   Host: ${SELECTOR}._domainkey"
echo "   Type: TXT"
echo "   Value: (paste the content between the quotes from above)"
echo ""
echo "5. DMARC RECORD"
echo "   Host: _dmarc"
echo "   Type: TXT"
echo "   Value: v=DMARC1; p=quarantine; rua=mailto:${ADMIN_EMAIL}; ruf=mailto:${ADMIN_EMAIL}; fo=1"
echo ""
echo "6. rDNS / PTR RECORD (IN YOUR VPS PROVIDER'S PANEL)"
echo "   Set the reverse DNS of your IP to: ${HOSTNAME}"
echo ""
echo "7. OUTBOUND PORT 25 CHECK"
echo "   Hetzner: blocks port 25 outbound for ~1 month / until first paid invoice."
echo "   Contabo: port 25 is open by default."
echo "   DigitalOcean/Vultr: may block — check their policy."
echo "   Confirm with: nc -zv gmail-smtp-in.l.google.com 25"
echo ""
echo "8. MTA-STS TXT RECORD (OPTIONAL, FOR ENHANCED SECURITY)"
echo "   Type: TXT"
echo "   Host: _mta-sts"
echo "   Value: v=STSv1; id=20260513"
echo ""
echo "9. TLS reporting TXT RECORD (OPTIONAL, FOR ENHANCED SECURITY)"
echo "   Type: TXT"
echo "   Host: _smtp._tls"
echo "   Value: v=TLSRPTv1; rua=mailto:contact@panwestconsultant.net"
echo ""
echo "10. Create hostname for policy server (OPTIONAL, FOR ENHANCED SECURITY)"
echo "   Type: A"
echo "   Host: mta-sts"
echo "   Value: 51.255.199.110"
echo ""
echo -e "${YELLOW}After adding DNS records, verify with:${NC}"
echo "  dig A ${HOSTNAME}"
echo "  dig MX ${DOMAIN}"
echo "  dig TXT ${DOMAIN}            # SPF"
echo "  dig TXT ${SELECTOR}._domainkey.${DOMAIN}   # DKIM"
echo "  dig TXT _dmarc.${DOMAIN}    # DMARC"
echo "  dig -x $(ip route get 1 | awk '{print $7; exit}')   # rDNS/PTR"
echo ""
echo -e "${YELLOW}verify mta sts:${NC}"
echo "  dig TXT _mta-sts.${DOMAIN}"
echo "  dig TXT _smtp._tls.${DOMAIN}"
echo "  visit https://mta-sts.${DOMAIN}/.well-known/mta-sts.txt"
echo " you will seee"
echo "version: STSv1"
echo "mode: enforce"
echo "mx: mail.${DOMAIN}"
echo "max_age: 86400"
echo ""

echo -e "${YELLOW}Send a test email:${NC}"
echo '  echo "Test body" | mail -s "Test Subject" your-email@gmail.com'
echo ""
echo -e "${YELLOW}Check mail logs:${NC}"
echo "  tail -f /var/log/mail.log"