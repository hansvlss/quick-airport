#!/usr/bin/env bash
# quick-airport.sh
# 4 合 1（VLESS Reality / Trojan / VMess-WS+TLS / Hysteria2）一键部署
# - 证书由 Caddy 自动签发
# - 订阅以静态文件 /sub/source.txt 提供
# - 运行前：传入环境变量 DOMAIN=你的域名.com （EMAIL 可选）
#   例：DOMAIN="vpn.example.com" EMAIL="me@example.com" bash quick-airport.sh

set -euo pipefail

#========================== 基础变量 ==========================#
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"                 # 可留空
HY2_PORT="${HY2_PORT:-8445}"       # UDP
VLESS_PORT="${VLESS_PORT:-8442}"
TROJAN_PORT="${TROJAN_PORT:-8443}"
VMESS_PORT="${VMESS_PORT:-8444}"

SB_BIN="/usr/local/bin/sing-box"
CADDY_BIN="/usr/bin/caddy"
CADDYFILE="/etc/caddy/Caddyfile"
WEBROOT="/var/www"
SUB_DIR="$WEBROOT/sub"
ENV_FILE="/root/airport.env"
LOG="/root/quick-airport.log"

#========================== 日志/工具 ==========================#
log(){ echo -e "[$(date +'%F %T')] $*" | tee -a "$LOG" >&2; }
die(){ echo -e "✖ $*" | tee -a "$LOG" >&2; exit 1; }
ok(){  echo -e "✔ $*" | tee -a "$LOG" >&2; }

trap 'die "脚本异常中止。日志见：$LOG"' ERR

[[ -z "$DOMAIN" ]] && die "未传入 DOMAIN。示例：DOMAIN=\"vpn.example.com\" bash $0"

#========================== 0) DNS 自救（仅当无法解析时） ==========================#
if ! ping -c1 -W2 github.com >/dev/null 2>&1; then
  log "检测到 DNS 解析异常，临时写入 /etc/resolv.conf"
  echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf || true
fi

#========================== 1) 基础软件/时区/时间同步/BBR/UFW ==========================#
log "安装基础软件 & 设置时区/时间同步/BBR/UFW"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl wget jq tar coreutils gnupg lsb-release chrony ufw net-tools dnsutils

# 时区 & 时间同步
timedatectl set-timezone Asia/Shanghai || true
systemctl enable --now chrony || true
timedatectl set-ntp true || true

# BBR
modprobe tcp_bbr 2>/dev/null || true
sysctl -w net.core.default_qdisc=fq >/dev/null
sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null
grep -q "net.core.default_qdisc" /etc/sysctl.conf || echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
grep -q "net.ipv4.tcp_congestion_control" /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
ok "$(sysctl net.core.default_qdisc | tr -s ' ')"
ok "$(sysctl net.ipv4.tcp_congestion_control | tr -s ' ')"

# UFW
ufw --force reset || true
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp || true
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw allow ${VLESS_PORT}/tcp
ufw allow ${TROJAN_PORT}/tcp
ufw allow ${VMESS_PORT}/tcp
ufw allow ${HY2_PORT}/udp
ufw --force enable
ok "[OK] UFW 已启用。放行端口：80/tcp, 443/tcp, 443/udp, ${VLESS_PORT}/tcp, ${TROJAN_PORT}/tcp, ${VMESS_PORT}/tcp, ${HY2_PORT}/udp"

#========================== 2) 安装 Caddy（APT 源，含 GPG Key 修复） ==========================#
log "安装 Caddy（APT）"
install -d /usr/share/keyrings /etc/apt/sources.list.d
curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
  | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

cat >/etc/apt/sources.list.d/caddy-stable.list <<'LIST'
deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main
deb-src [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main
LIST

apt-get update -y || {
  # 若再次提示 NO_PUBKEY，重新写 key 再试一次
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  apt-get update -y
}
apt-get install -y caddy

#========================== 3) 最简 Caddyfile & Web 根目录 ==========================#
install -d "$WEBROOT" "$SUB_DIR" /etc/caddy
cat >"$CADDYFILE" <<CADDY
${DOMAIN} {
    encode zstd gzip
    root * ${WEBROOT}
    file_server
}
CADDY

# 一个简单首页，带订阅入口
cat >"${WEBROOT}/index.html" <<HTML
<!doctype html><meta charset="utf-8"><title>OK</title>
<h1>Caddy OK</h1>
<p>订阅地址：<a href="/sub/source.txt">/sub/source.txt</a></p>
HTML

# 先放个占位订阅，稍后回填
echo "# 正在初始化，请稍候…" > "${SUB_DIR}/source.txt"

# 设定邮箱（可选）
if [[ -n "$EMAIL" ]]; then
  sed -i '/^#.*email/c\' /etc/caddy/Caddyfile 2>/dev/null || true
  # Caddyfile 顶部 email directive（可选，不加也能签）
  sed -i "1i email ${EMAIL}" "$CADDYFILE"
fi

caddy validate --config "$CADDYFILE"
systemctl enable --now caddy
log "等待 Let's Encrypt 证书颁发…"
sleep 3
ok "Caddy 已运行"

#========================== 4) 安装 sing-box（自动识别架构） ==========================#
log "安装 sing-box"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64) SB_ARCH="amd64" ;;
  aarch64|arm64) SB_ARCH="arm64" ;;
  armv7l) SB_ARCH="armv7" ;;
  *) die "不支持的架构: $ARCH_RAW" ;;
esac

VER="$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)"
[[ -z "$VER" || "$VER" == "null" ]] && die "获取 sing-box 最新版本失败"
FILE_VER="${VER#v}"
URL="https://github.com/SagerNet/sing-box/releases/download/${VER}/sing-box-${FILE_VER}-linux-${SB_ARCH}.tar.gz"

TMP_DIR="$(mktemp -d)"
pushd "$TMP_DIR" >/dev/null
curl -fL --retry 3 -o sb.tgz "$URL"
tar -xzf sb.tgz
install -m 0755 sing-box-*/sing-box "$SB_BIN"
popd >/dev/null
rm -rf "$TMP_DIR"
$SB_BIN version | tee -a "$LOG" | sed -n '1p' | xargs -I{} ok "{}"

#========================== 5) 生成凭据 & 写入 config.json ==========================#
log "生成凭据"
KP="$($SB_BIN generate reality-keypair)"
REALITY_PRIV="$(echo "$KP" | awk '/PrivateKey/{print $2}')"
REALITY_PUB="$(echo "$KP"  | awk '/PublicKey/{print $2}')"
UUID="$($SB_BIN generate uuid)"
REALITY_SID="$(openssl rand -hex 8)"
HY2_PASS="$(openssl rand -hex 16)"
HY2_OBFS="$(openssl rand -hex 16)"
TROJAN_PASS="$(openssl rand -hex 16)"

cat >"$ENV_FILE" <<EOF
DOMAIN="${DOMAIN}"
UUID="${UUID}"
REALITY_PRIV="${REALITY_PRIV}"
REALITY_PUB="${REALITY_PUB}"
REALITY_SID="${REALITY_SID}"
HY2_PASS="${HY2_PASS}"
HY2_OBFS="${HY2_OBFS}"
TROJAN_PASS="${TROJAN_PASS}"
HY2_PORT="${HY2_PORT}"
VLESS_PORT="${VLESS_PORT}"
TROJAN_PORT="${TROJAN_PORT}"
VMESS_PORT="${VMESS_PORT}"
EOF
chmod 600 "$ENV_FILE"

log "写入 sing-box 配置与服务"
install -d /etc/sing-box

cat > /etc/sing-box/config.json <<JSON
{
  "log": { "level": "warn" },

  "dns": {
    "strategy": "prefer_ipv4",
    "servers": [
      { "address": "1.1.1.1" },
      { "address": "8.8.8.8" }
    ]
  },

  "inbounds": [
    {
      "type": "hysteria2",
      "listen": "::",
      "listen_port": ${HY2_PORT},
      "users": [{ "name": "user1", "password": "${HY2_PASS}" }],
      "obfs": { "type": "salamander", "password": "${HY2_OBFS}" },
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/${DOMAIN}/${DOMAIN}.crt",
        "key_path": "/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/${DOMAIN}/${DOMAIN}.key"
      }
    },
    {
      "type": "vless",
      "listen": "::",
      "listen_port": ${VLESS_PORT},
      "users": [{ "uuid": "${UUID}" }],
      "tls": {
        "enabled": true,
        "reality": {
          "enabled": true,
          "handshake": { "server": "www.cloudflare.com", "server_port": 443 },
          "private_key": "${REALITY_PRIV}",
          "short_id": ["${REALITY_SID}"]
        }
      }
    },
    {
      "type": "trojan",
      "listen": "::",
      "listen_port": ${TROJAN_PORT},
      "users": [{ "password": "${TROJAN_PASS}" }],
      "tls": {
        "enabled": true,
        "alpn": ["h2","http/1.1"],
        "server_name": "${DOMAIN}",
        "certificate_path": "/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/${DOMAIN}/${DOMAIN}.crt",
        "key_path": "/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/${DOMAIN}/${DOMAIN}.key"
      }
    },
    {
      "type": "vmess",
      "listen": "::",
      "listen_port": ${VMESS_PORT},
      "users": [{ "uuid": "${UUID}" }],
      "transport": { "type": "ws", "path": "/vmess" },
      "tls": {
        "enabled": true,
        "server_name": "${DOMAIN}",
        "certificate_path": "/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/${DOMAIN}/${DOMAIN}.crt",
        "key_path": "/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/${DOMAIN}/${DOMAIN}.key"
      }
    }
  ],

  "outbounds": [{ "type": "direct" }, { "type": "block" }]
}
JSON

cat > /etc/systemd/system/sing-box.service <<SVC
[Unit]
Description=Sing-box
After=network.target

[Service]
ExecStart=${SB_BIN} run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=2s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
$SB_BIN check -c /etc/sing-box/config.json
systemctl enable --now sing-box

#========================== 6) 等证书并“回填路径” & 生成订阅 ==========================#
log "定位 Caddy 证书"
CERT_BASE="/var/lib/caddy/.local/share/caddy"
CRT_PATH=""; KEY_PATH=""
for i in {1..18}; do
  CRT_PATH="$(find "$CERT_BASE" -type f -path "*/${DOMAIN}/${DOMAIN}.crt" -print -quit 2>/dev/null || true)"
  KEY_PATH="$(find "$CERT_BASE/certificates" -type f -path "*/${DOMAIN}/${DOMAIN}.key" -print -quit 2>/dev/null || true)"
  [[ -z "$KEY_PATH" ]] && KEY_PATH="$(find "$CERT_BASE/keys" -type f -path "*/${DOMAIN}/${DOMAIN}.key" -print -quit 2>/dev/null || true)"
  [[ -f "$CRT_PATH" && -f "$KEY_PATH" ]] && break
  # 主动触发访问，促进自动签发
  curl -skI "https://${DOMAIN}/" >/dev/null 2>&1 || true
  sleep 10
done

if [[ ! -f "$CRT_PATH" || ! -f "$KEY_PATH" ]]; then
  die "仍未找到证书：/var/lib/caddy/.local/share/caddy/.../${DOMAIN}/{.crt,.key}。请确认 DNS 已生效且为灰云。\n查看：journalctl -u caddy -n 100 --no-pager"
fi
ok "证书已找到：$CRT_PATH | $KEY_PATH"

# 用 jq 回填（以防 Caddy 目录结构差异）
jq \
  --arg crt "$CRT_PATH" \
  --arg key "$KEY_PATH" \
  '.inbounds |= map(
     if .type=="hysteria2" or .type=="trojan" or (.type=="vmess" and (.tls//{}).enabled==true)
     then .tls.certificate_path=$crt | .tls.key_path=$key
     else .
     end
   )' /etc/sing-box/config.json > /etc/sing-box/config.json.new

mv /etc/sing-box/config.json.new /etc/sing-box/config.json
$SB_BIN check -c /etc/sing-box/config.json
systemctl restart sing-box
sleep 1

# 重新生成订阅（以实际端口/密钥）
set -a; source "$ENV_FILE"; set +a

VMESS_JSON=$(cat <<EOJ
{"v":"2","ps":"VMess-WS-TLS","add":"${DOMAIN}","port":"${VMESS_PORT}","id":"${UUID}","aid":"0","net":"ws","type":"","host":"${DOMAIN}","path":"/vmess","tls":"tls","sni":"${DOMAIN}"}
EOJ
)
VMESS_B64="$(echo -n "$VMESS_JSON" | base64 -w 0)"
HY2="hysteria2://${HY2_PASS}@${DOMAIN}:${HY2_PORT}/?obfs=salamander&obfsParam=${HY2_OBFS}&peer=${DOMAIN}&alpn=h3#HY2"
TROJAN="trojan://${TROJAN_PASS}@${DOMAIN}:${TROJAN_PORT}?peer=${DOMAIN}&alpn=h2,http/1.1#Trojan"
VLESS="vless://${UUID}@${DOMAIN}:${VLESS_PORT}?encryption=none&flow=&type=tcp&security=reality&pbk=${REALITY_PUB}&sid=${REALITY_SID}&sni=www.cloudflare.com#VLESS-REALITY"
VMESS="vmess://${VMESS_B64}"

cat > "${SUB_DIR}/source.txt" <<EOF
$HY2
$TROJAN
$VLESS
$VMESS
EOF

# 站点权限 & Reload
chown -R caddy:caddy "$WEBROOT" 2>/dev/null || chown -R www-data:www-data "$WEBROOT" || true
systemctl reload caddy || true

#========================== 完成 & 提示 ==========================#
ok "部署完成！"
echo "——————————————————————————————————"
echo "订阅地址： https://${DOMAIN}/sub/source.txt"
echo "HY2:     $HY2"
echo "Trojan:  $TROJAN"
echo "VLESS:   $VLESS"
echo "VMess:   $VMESS"
echo
echo "端口监听："
ss -tunlp | grep -E ":${VLESS_PORT}|:${TROJAN_PORT}|:${VMESS_PORT}|:${HY2_PORT}|:443\\b" || true
echo
echo "如有问题，请执行："
echo "journalctl -u caddy -n 80 --no-pager"
echo "journalctl -u sing-box -n 80 --no-pager"
echo "环境变量保存于：$ENV_FILE"
