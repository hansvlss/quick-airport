#!/usr/bin/env bash
# quick-airport-v7.sh
# 4 合 1（VLESS Reality / Trojan / VMess-WS+TLS / Hysteria2）一键部署
# 证书由 Caddy 自动签发；订阅以静态文件 /sub/source.txt 提供
# 运行前：需传入环境变量 DOMAIN=你的域名.com （EMAIL 可选）
# 例：DOMAIN="vpn.example.com" EMAIL="me@example.com" bash quick-airport-v7.sh

set -euo pipefail

#========================== 基础变量 ==========================#
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"                      # 可留空
HY2_PORT="${HY2_PORT:-8445}"            # UDP
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

CADDY_KEYRING="/usr/share/keyrings/caddy-stable-archive-keyring.gpg"
CADDY_LIST="/etc/apt/sources.list.d/caddy.list"
CADDY_DEB_VER="2.10.2"  # 失败回落用

#========================== 日志/工具 ==========================#
log(){ echo -e "[$(date +'%F %T')] $*" | tee -a "$LOG" >&2; }
die(){ echo -e "✖ $*" | tee -a "$LOG" >&2; exit 1; }
ok(){  echo -e "✔ $*" | tee -a "$LOG" >&2; }

trap 'die "脚本异常中止。日志见：$LOG"' ERR

if [[ -z "$DOMAIN" ]]; then
  die "未传入 DOMAIN。示例：DOMAIN=\"vpn.example.com\" bash $0"
fi

#========================== 1) 基础环境/时区/BBR/UFW ==========================#
log "安装基础软件 & 设置时区/时间同步/BBR/UFW"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl wget jq tar ufw chrony lsb-release

# 时区 & 时间同步（Ubuntu/Focal 适用）
timedatectl set-timezone Asia/Shanghai || true
systemctl enable --now chrony || true

# BBR + FQ
cat >/etc/sysctl.d/99-bbr.conf <<'SYSCTL'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
SYSCTL
sysctl --system >/dev/null

# UFW 放行
ufw --force reset || true
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    || true
ufw allow 80/tcp    || true
ufw allow 443/tcp   || true
ufw allow 443/udp   || true
ufw allow ${VLESS_PORT}/tcp || true
ufw allow ${TROJAN_PORT}/tcp || true
ufw allow ${VMESS_PORT}/tcp || true
ufw allow ${HY2_PORT}/udp || true
yes | ufw enable
ok "[OK] UFW 已启用。放行端口：80/tcp, 443/tcp, 443/udp, ${VLESS_PORT}/tcp, ${TROJAN_PORT}/tcp, ${VMESS_PORT}/tcp, ${HY2_PORT}/udp"

#========================== 2) 安装/修复 Caddy ==========================#
install_caddy_apt() {
  # 清理重复旧条目（有些机器会残留 caddy-stable.list）
  rm -f /etc/apt/sources.list.d/caddy-stable.list 2>/dev/null || true

  # 写入官方源（固定 any-version，避免 codename 不匹配）
  curl -1sSfL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    | gpg --dearmor -o "$CADDY_KEYRING"
  chmod 644 "$CADDY_KEYRING"

  cat > "$CADDY_LIST" <<EOF
deb [signed-by=${CADDY_KEYRING}] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main
deb-src [signed-by=${CADDY_KEYRING}] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main
EOF

  apt-get update -y
  apt-get install -y caddy
}

install_caddy_fallback_deb() {
  ARCH_RAW="$(uname -m)"
  case "$ARCH_RAW" in
    x86_64|amd64) DEB_ARCH="amd64" ;;
    aarch64|arm64) DEB_ARCH="arm64" ;;
    *) die "不支持的架构: $ARCH_RAW（Caddy 回落安装失败）" ;;
  esac
  URL="https://github.com/caddyserver/caddy/releases/download/v${CADDY_DEB_VER}/caddy_${CADDY_DEB_VER}_linux_${DEB_ARCH}.deb"
  TMP="$(mktemp -d)"; cd "$TMP"
  log "安装 Caddy（回落 .deb）：$URL"
  curl -fL -o caddy.deb "$URL"
  apt-get install -y ./caddy.deb
  cd /root && rm -rf "$TMP"
}

log "安装/修复 Caddy 源并安装"
if ! command -v caddy >/dev/null 2>&1; then
  if ! install_caddy_apt; then
    log "APT 安装 Caddy 失败，尝试回落 .deb 安装"
    install_caddy_fallback_deb
  fi
else
  ok "系统已存在 Caddy"
fi

#========================== 3) 写 Caddyfile + 站点根 ==========================#
install -d "$WEBROOT" "$SUB_DIR"
# 占位订阅，避免 404 / 502
echo "# 将由脚本覆盖生成" > "$SUB_DIR/source.txt"

# 极简静态站点（不反代，不占 443/udp 以外内容）
cat > "$CADDYFILE" <<CADDY
${DOMAIN} {
    encode zstd gzip
    root * ${WEBROOT}
    file_server
}
CADDY

# 尝试把 /var/www 赋给运行用户（不同系统可能是 caddy 或 www-data）
chown -R caddy:caddy "$WEBROOT" 2>/dev/null || chown -R www-data:www-data "$WEBROOT" 2>/dev/null || true

# 启/重载
systemctl enable --now caddy
log "等待 Let's Encrypt 证书颁发…"
sleep 3
ok "Caddy 已运行"

#========================== 4) 安装 sing-box（最新 stable） ==========================#
log "安装 sing-box"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64) SB_ARCH="amd64" ;;
  aarch64|arm64) SB_ARCH="arm64" ;;
  armv7l)        SB_ARCH="armv7" ;;
  *) die "不支持的架构: $ARCH_RAW" ;;
esac
VER="$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name')"
[ -z "$VER" ] && die "获取 sing-box 最新版本失败"
FILE_VER="${VER#v}"
URL="https://github.com/SagerNet/sing-box/releases/download/${VER}/sing-box-${FILE_VER}-linux-${SB_ARCH}.tar.gz"

TMP_SB="$(mktemp -d)"; cd "$TMP_SB"
curl -fL -o sb.tgz "$URL"
tar -xzf sb.tgz
install -m 0755 sing-box-*/sing-box "$SB_BIN"
cd /root && rm -rf "$TMP_SB"
ok "$($SB_BIN version | head -n1)"

#========================== 5) 生成凭据 & 定位证书 ==========================#
log "生成凭据"
KP="$($SB_BIN generate reality-keypair)"
REALITY_PRIV="$(echo "$KP" | awk '/PrivateKey/ {print $2}')"
REALITY_PUB="$(echo  "$KP" | awk '/PublicKey/  {print $2}')"
UUID="$($SB_BIN generate uuid)"
REALITY_SID="$(openssl rand -hex 8)"
HY2_PASS="$(openssl rand -hex 16)"
HY2_OBFS="$(openssl rand -hex 16)"
TROJAN_PASS="$(openssl rand -hex 16)"

cat > "$ENV_FILE" <<EOF
DOMAIN="$DOMAIN"
UUID="$UUID"
REALITY_PRIV="$REALITY_PRIV"
REALITY_PUB="$REALITY_PUB"
REALITY_SID="$REALITY_SID"
HY2_PASS="$HY2_PASS"
HY2_OBFS="$HY2_OBFS"
TROJAN_PASS="$TROJAN_PASS"
HY2_PORT="$HY2_PORT"
VLESS_PORT="$VLESS_PORT"
TROJAN_PORT="$TROJAN_PORT"
VMESS_PORT="$VMESS_PORT"
EOF
chmod 600 "$ENV_FILE"

log "定位 Caddy 证书"
CERT_BASE="/var/lib/caddy/.local/share/caddy"
CRT_PATH=""
KEY_PATH=""

# 最多等 3 分钟（18*10s）
for i in {1..18}; do
  CRT_PATH="$(find "$CERT_BASE" -type f -path "*/${DOMAIN}/${DOMAIN}.crt" 2>/dev/null | head -n1 || true)"
  KEY_PATH="$(find "$CERT_BASE" -type f -path "*/${DOMAIN}/${DOMAIN}.key" 2>/dev/null | head -n1 || true)"
  # 兼容旧布局（keys 目录）
  if [[ -z "$KEY_PATH" ]]; then
    KEY_PATH="$(find /var/lib/caddy/.local/share/caddy/keys -type f -path "*/${DOMAIN}/${DOMAIN}.key" 2>/dev/null | head -n1 || true)"
  fi
  [[ -f "$CRT_PATH" && -f "$KEY_PATH" ]] && break
  sleep 10
done

if [[ ! -f "$CRT_PATH" || ! -f "$KEY_PATH" ]]; then
  die "仍未找到证书：/var/lib/caddy/.local/share/caddy/.../${DOMAIN}/{.crt,.key}。请确认 DNS 已指向本机且 Cloudflare 为灰云。\n$(journalctl -u caddy -n 100 --no-pager | tail -n +1)"
fi
ok "找到证书：$CRT_PATH / $KEY_PATH"

#========================== 6) 写 sing-box 配置 & 服务 ==========================#
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
        "certificate_path": "${CRT_PATH}",
        "key_path": "${KEY_PATH}"
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
        "certificate_path": "${CRT_PATH}",
        "key_path": "${KEY_PATH}"
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
        "certificate_path": "${CRT_PATH}",
        "key_path": "${KEY_PATH}"
      }
    }
  ],

  "outbounds": [
    { "type": "direct" },
    { "type": "block" }
  ]
}
JSON

cat > /etc/systemd/system/sing-box.service <<'SVC'
[Unit]
Description=Sing-box
After=network.target

[Service]
User=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SVC

$SB_BIN check -c /etc/sing-box/config.json
systemctl daemon-reload
systemctl enable --now sing-box

#========================== 7) 生成四合一订阅 ==========================#
log "生成订阅"
# 读取变量
set -a; source "$ENV_FILE"; set +a

VMESS_JSON=$(cat <<EOF
{"v":"2","ps":"VMess-WS-TLS","add":"${DOMAIN}","port":"${VMESS_PORT}","id":"${UUID}","aid":"0","net":"ws","type":"","host":"${DOMAIN}","path":"/vmess","tls":"tls","sni":"${DOMAIN}"}
EOF
)
VMESS_B64="$(echo -n "$VMESS_JSON" | base64 -w 0)"
HY2="hysteria2://${HY2_PASS}@${DOMAIN}:${HY2_PORT}/?obfs=salamander&obfsParam=${HY2_OBFS}&peer=${DOMAIN}&alpn=h3#HY2"
TROJAN="trojan://${TROJAN_PASS}@${DOMAIN}:${TROJAN_PORT}?peer=${DOMAIN}&alpn=h2,http/1.1#Trojan"
VLESS="vless://${UUID}@${DOMAIN}:${VLESS_PORT}?encryption=none&flow=&type=tcp&security=reality&pbk=${REALITY_PUB}&sid=${REALITY_SID}&sni=www.cloudflare.com#VLESS-REALITY"
VMESS="vmess://${VMESS_B64}"

install -d "$SUB_DIR"
cat > "$SUB_DIR/source.txt" <<EOF
$HY2
$TROJAN
$VLESS
$VMESS
EOF

# 权限（取决于 Caddy 运行用户）
chown -R caddy:caddy "$WEBROOT" 2>/dev/null || chown -R www-data:www-data "$WEBROOT" 2>/dev/null || true
systemctl reload caddy || true

ok "部署完成！"
echo "——————————————————————————————————"
echo "订阅地址： https://${DOMAIN}/sub/source.txt"
echo "HY2:     $HY2"
echo "Trojan:  $TROJAN"
echo "VLESS:   $VLESS"
echo "VMess:   $VMESS"
echo
echo "日志排查："
echo "  sing-box：journalctl -u sing-box -n 60 --no-pager"
echo "  caddy：   journalctl -u caddy -n 60 --no-pager"
echo "环境变量保存在：$ENV_FILE"
