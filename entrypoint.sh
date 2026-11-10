#!/bin/sh

set -eu

RULES_DIR="/opt/SubMonitor/rules"
SSL_DIR="/etc/nginx/ssl"
ACME_HOME="$RULES_DIR/acme"
DOMAIN_FILE="$RULES_DIR/domain.conf"
LOCK_FILE="$RULES_DIR/.domain_locked"
ALLOW_FILE="$RULES_DIR/domain_allow.conf"

# UID/GID 82 is the PHP runtime user. Runtime state files created by Nginx
# are handed back to UID/GID 82 so PHP can update them without 777 permissions.
APP_UID=82
APP_GID=82

mkdir -p /etc/nginx/conf.d "$RULES_DIR" "$SSL_DIR" "$ACME_HOME"

touch \
  "$RULES_DIR/ip_blacklist.conf" \
  "$RULES_DIR/ua_blacklist.conf" \
  "$RULES_DIR/token_blacklist.conf" \
  "$ALLOW_FILE"

# Shared rules/state directory: PHP (82) can write; Nginx runs as root and can read/write.
chown "$APP_UID:$APP_GID" "$RULES_DIR"
chmod 775 "$RULES_DIR"

for file in \
  "$RULES_DIR/ip_blacklist.conf" \
  "$RULES_DIR/ua_blacklist.conf" \
  "$RULES_DIR/token_blacklist.conf" \
  "$ALLOW_FILE"; do
  chown "$APP_UID:$APP_GID" "$file"
  chmod 664 "$file"
done

# ACME working data contains account/private material and is managed only by root.
chown root:root "$ACME_HOME"
chmod 700 "$ACME_HOME"

# Nginx owns certificate writes. PHP sees ./ssl as read-only in docker-compose.
chmod 755 "$SSL_DIR"

# Initial installation uses a temporary self-signed certificate; a successful
# ACME certificate will replace it.
if [ ! -s "$SSL_DIR/cert.pem" ] || [ ! -s "$SSL_DIR/key.pem" ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$SSL_DIR/key.pem" -out "$SSL_DIR/cert.pem" \
    -subj "/CN=localhost" >/dev/null 2>&1

  chmod 600 "$SSL_DIR/key.pem"
  chmod 644 "$SSL_DIR/cert.pem"
  echo "[Init] 自签名证书已生成"
else
  chmod 600 "$SSL_DIR/key.pem" 2>/dev/null || true
  chmod 644 "$SSL_DIR/cert.pem" 2>/dev/null || true
fi

# acme.sh is stored under the persistent rules directory so it survives
# container recreation. It is managed only by the Nginx/root process.
if [ ! -f "$ACME_HOME/acme.sh" ]; then
  echo "[Init] 正在安装 acme.sh..."
  curl -s https://get.acme.sh | sh -s email=admin@qq.com --home "$ACME_HOME" >/dev/null 2>&1
fi

ACME="$ACME_HOME/acme.sh"
if [ -f "$ACME" ]; then
  chmod 700 "$ACME" 2>/dev/null || true
  "$ACME" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
fi

# Write a shared runtime file with permissions that allow PHP (82) to update it.
# %b is used intentionally so callers can pass \n for a trailing newline.
write_app_file() {
  file="$1"
  content="$2"
  printf '%b' "$content" > "$file"
  chown "$APP_UID:$APP_GID" "$file"
  chmod 664 "$file"
}

write_allow_file() {
  domain="$1"
  : > "$ALLOW_FILE"
  if [ -n "$domain" ]; then
    printf '"%s" 1;\n' "$domain" > "$ALLOW_FILE"
  fi
  chown "$APP_UID:$APP_GID" "$ALLOW_FILE"
  chmod 664 "$ALLOW_FILE"
}

write_lock_map() {
  if [ -f "$LOCK_FILE" ]; then
    write_app_file "$RULES_DIR/domain_lock.conf" 'map $host $domain_locked { default 1; }\n'
  else
    write_app_file "$RULES_DIR/domain_lock.conf" 'map $host $domain_locked { default 0; }\n'
  fi
}

is_formal_cert_for_domain() {
  domain="$1"
  [ -n "$domain" ] || return 1
  [ -s "$SSL_DIR/cert.pem" ] || return 1

  subject=$(openssl x509 -in "$SSL_DIR/cert.pem" -noout -subject 2>/dev/null || true)
  issuer=$(openssl x509 -in "$SSL_DIR/cert.pem" -noout -issuer 2>/dev/null || true)

  printf '%s' "$subject" | grep -Eiq "CN[[:space:]]*=[[:space:]]*${domain}([, /]|$)" || return 1
  printf '%s' "$issuer" | grep -Eiq 'Let.s Encrypt|ZeroSSL|Google Trust Services|Buypass' || return 1
  return 0
}

# Restore access mode from persistent certificate/domain state.
DOMAIN=$(cat "$DOMAIN_FILE" 2>/dev/null | tr -d '\n ' || true)
if is_formal_cert_for_domain "$DOMAIN"; then
  write_app_file "$LOCK_FILE" "1\n"
  write_allow_file "$DOMAIN"
  echo "[Init] 检测到正式证书：$DOMAIN，已恢复域名锁定模式"
else
  rm -f "$LOCK_FILE"
  write_allow_file ""
  echo "[Init] 当前未检测到有效正式证书，保持 IP 可访问模式"
fi

write_lock_map

# Background task: certificate issuance/renewal and Nginx reloads.
(
while true; do
  if [ -f "$RULES_DIR/.cert_flag" ]; then
    DOMAIN=$(cat "$RULES_DIR/.cert_flag" | tr -d '\n ')
    rm -f "$RULES_DIR/.cert_flag"

    if [ -z "$DOMAIN" ]; then
      write_app_file "$RULES_DIR/cert_status.json" '{"status":"error","msg":"域名为空，跳过申请"}\n'
      sleep 3
      continue
    fi

    # Domain changes temporarily disable the lock until the new certificate
    # has been successfully issued and verified.
    rm -f "$LOCK_FILE"
    write_allow_file ""
    write_lock_map
    nginx -s reload >/dev/null 2>&1 || true

    echo "[Cert] 开始申请域名证书：$DOMAIN"
    write_app_file "$RULES_DIR/cert_status.json" "{\"status\":\"processing\",\"msg\":\"正在申请 $DOMAIN 证书，请稍候...\"}\n"

    if "$ACME" --issue -d "$DOMAIN" -w /opt/SubMonitor/html \
      --accountemail admin@qq.com --force --keylength 2048; then

      if "$ACME" --install-cert -d "$DOMAIN" \
        --key-file "$SSL_DIR/key.pem" \
        --fullchain-file "$SSL_DIR/cert.pem" \
        --reloadcmd "nginx -s reload"; then

        if is_formal_cert_for_domain "$DOMAIN"; then
          printf '%s\n' "$DOMAIN" > "$DOMAIN_FILE"
          chown "$APP_UID:$APP_GID" "$DOMAIN_FILE"
          chmod 664 "$DOMAIN_FILE"

          write_app_file "$LOCK_FILE" "1\n"
          write_allow_file "$DOMAIN"
          write_lock_map

          chmod 600 "$SSL_DIR/key.pem" 2>/dev/null || true
          chmod 644 "$SSL_DIR/cert.pem" 2>/dev/null || true

          nginx -s reload >/dev/null 2>&1 || true
          echo "[Cert] ✅ $DOMAIN 正式证书已生效，已切换为强制域名模式"
          write_app_file "$RULES_DIR/cert_status.json" "{\"status\":\"success\",\"msg\":\"✅ $DOMAIN 证书申请成功，已自动生效；IP 与未绑定域名已禁止访问。\"}\n"
        else
          rm -f "$LOCK_FILE"
          write_allow_file ""
          write_lock_map
          echo "[Cert] ❌ ACME 命令成功但证书校验失败，保持 IP 可访问"
          write_app_file "$RULES_DIR/cert_status.json" '{"status":"error","msg":"证书已返回，但未检测到与绑定域名匹配的正式 CA 证书。"}\n'
        fi
      else
        rm -f "$LOCK_FILE"
        write_allow_file ""
        write_lock_map
        nginx -s reload >/dev/null 2>&1 || true
        echo "[Cert] ❌ 证书安装失败，保持 IP 可访问模式"
        write_app_file "$RULES_DIR/cert_status.json" '{"status":"error","msg":"❌ 证书安装失败，保持 IP 可访问模式。"}\n'
      fi
    else
      rm -f "$LOCK_FILE"
      write_allow_file ""
      write_lock_map
      nginx -s reload >/dev/null 2>&1 || true
      echo "[Cert] ❌ $DOMAIN 证书申请失败，保持 IP 可访问模式"
      write_app_file "$RULES_DIR/cert_status.json" '{"status":"error","msg":"❌ 申请失败！请确认域名已解析到本机IP、80端口开放且未被 CDN/代理拦截。"}\n'
    fi
  fi

  if [ -f "$RULES_DIR/.reload_flag" ]; then
    rm -f "$RULES_DIR/.reload_flag"
    nginx -t >/dev/null 2>&1 && nginx -s reload >/dev/null 2>&1 || true
  fi

  sleep 3
done
) &

echo "[Init] 启动 Nginx 服务..."
exec nginx -g 'daemon off;'
