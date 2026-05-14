
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