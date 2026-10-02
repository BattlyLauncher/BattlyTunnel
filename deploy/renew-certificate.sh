#!/bin/sh
set -eu
umask 077
cd /etc/battly-tunnel
if openssl x509 -checkend 2592000 -noout -in fullchain.pem >/dev/null; then exit 0; fi
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca-private/ca.key -CAserial ca-private/ca.srl -CAcreateserial -days 365 -sha256 -extfile leaf.ext -out fullchain.next.pem
chown root:battly-tunnel fullchain.next.pem
chmod 640 fullchain.next.pem
mv fullchain.next.pem fullchain.pem
systemctl restart battly-tunnel.service
