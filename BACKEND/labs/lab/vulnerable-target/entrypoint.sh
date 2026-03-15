#!/bin/sh
set -u

STATE_DIR="/srv/backups/.horus_state"
ROTATED_CREDS_FILE="/srv/backups/.horus_rotated_credentials.txt"

mkdir -p /srv/labdata /srv/backups "$STATE_DIR" /var/run/vsftpd/empty /run/sshd
chmod -R 0777 /srv/labdata

if ! grep -q "documento_01" /srv/labdata/.seeded 2>/dev/null; then
  for i in $(seq -w 1 40); do
    echo "Documento de laboratorio ${i}" > "/srv/labdata/documento_${i}.txt"
  done
  cat > /srv/labdata/index.html <<'HTML'
<!doctype html>
<html lang="es">
  <head><meta charset="utf-8"><title>HORUS Vulnerable Lab</title></head>
  <body>
    <h1>HORUS Vulnerable Lab</h1>
    <p>HTTP expuesto intencionalmente para pruebas controladas.</p>
  </body>
</html>
HTML
  echo "documento_01" > /srv/labdata/.seeded
fi

has_state() {
  [ -f "${STATE_DIR}/$1.applied" ]
}

configure_ssh_auth() {
  password_auth="$1"
  root_login="$2"

  if grep -q '^#\?PasswordAuthentication' /etc/ssh/sshd_config; then
    sed -i "s/^#\\?PasswordAuthentication.*/PasswordAuthentication ${password_auth}/" /etc/ssh/sshd_config
  else
    echo "PasswordAuthentication ${password_auth}" >> /etc/ssh/sshd_config
  fi

  if grep -q '^#\?PermitRootLogin' /etc/ssh/sshd_config; then
    sed -i "s/^#\\?PermitRootLogin.*/PermitRootLogin ${root_login}/" /etc/ssh/sshd_config
  else
    echo "PermitRootLogin ${root_login}" >> /etc/ssh/sshd_config
  fi
}

set_smb_password() {
  smb_user="$1"
  smb_pass="$2"

  if pdbedit -L | grep -q "^${smb_user}:"; then
    (printf '%s\n%s\n' "${smb_pass}" "${smb_pass}" | smbpasswd -s "${smb_user}" >/dev/null) || true
  else
    (printf '%s\n%s\n' "${smb_pass}" "${smb_pass}" | smbpasswd -s -a "${smb_user}" >/dev/null) || true
  fi
}

apply_weak_credentials() {
  echo "admin:admin" | chpasswd || true
  echo "user:password" | chpasswd || true
  set_smb_password admin admin
  set_smb_password user password
}

apply_hardened_credentials() {
  admin_pw=""
  user_pw=""

  if [ -f "${ROTATED_CREDS_FILE}" ]; then
    admin_pw="$(grep '^admin=' "${ROTATED_CREDS_FILE}" | head -n 1 | cut -d '=' -f 2-)"
    user_pw="$(grep '^user=' "${ROTATED_CREDS_FILE}" | head -n 1 | cut -d '=' -f 2-)"
  fi

  if [ -z "${admin_pw}" ] || [ -z "${user_pw}" ]; then
    stamp="$(date +%s)"
    admin_pw="HorusAdmin${stamp}"
    user_pw="HorusUser${stamp}"

    {
      echo "rotated_at=${stamp}"
      echo "admin=${admin_pw}"
      echo "user=${user_pw}"
    } > "${ROTATED_CREDS_FILE}"
    chmod 600 "${ROTATED_CREDS_FILE}" || true
  fi

  echo "admin:${admin_pw}" | chpasswd || true
  echo "user:${user_pw}" | chpasswd || true
  set_smb_password admin "${admin_pw}"
  set_smb_password user "${user_pw}"
}

if has_state weak_credentials; then
  apply_hardened_credentials
else
  apply_weak_credentials
fi

if has_state telnet_open && [ -f /etc/inetd.conf ]; then
  sed -i 's/^telnet /# telnet /' /etc/inetd.conf || true
fi

if has_state smb_v1_enabled && [ -f /etc/samba/smb.conf ]; then
  sed -i 's/^[[:space:]]*server min protocol.*/  server min protocol = SMB3/' /etc/samba/smb.conf || true
  sed -i 's/^[[:space:]]*client min protocol.*/  client min protocol = SMB3/' /etc/samba/smb.conf || true
  sed -i 's/^[[:space:]]*lanman auth.*/  lanman auth = no/' /etc/samba/smb.conf || true
  sed -i 's/^[[:space:]]*ntlm auth.*/  ntlm auth = no/' /etc/samba/smb.conf || true
  sed -i 's/^[[:space:]]*map to guest.*/  map to guest = Never/' /etc/samba/smb.conf || true
  sed -i 's/^[[:space:]]*guest ok.*/  guest ok = no/' /etc/samba/smb.conf || true
fi

if has_state open_critical_ports; then
  configure_ssh_auth no no
else
  configure_ssh_auth yes yes
fi

if ! has_state open_critical_ports; then
  /usr/sbin/inetd &
  /usr/sbin/vsftpd /etc/vsftpd.conf &
  /usr/sbin/smbd --foreground --no-process-group &
  /usr/sbin/nmbd --foreground --no-process-group &
fi

/usr/sbin/sshd -D &
python3 -m http.server 80 --directory /srv/labdata >/var/log/http-lab.log 2>&1 &

# Keep lab container alive even if remediation stops vulnerable services.
while :; do
  sleep 3600
done
