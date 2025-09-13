#!/usr/bin/env bash
# quick-airport.sh
# 4 合 1（VLESS Reality / Trojan / VMess-WS+TLS / Hysteria2）
# 证书由 Caddy 自动签发；订阅以静态文件 /sub/source.txt 提供
# 运行示例：
#   DOMAIN="vpn.example.com" EMAIL="me@example.com" bash quick-airport.sh

set -euo pipefail

#========================== 基础变量 ==========================#
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"                       # 可留空
HY2_PORT="${HY2_PORT:-8445}"             # UDP
VLESS_PORT="${VLESS_PORT:-8442}"
TROJAN_PORT="${TROJAN_PORT:-8443}"
VMESS_PORT="${VMESS_PORT:-8444}"

SB_BIN="/usr/local/bin/sing-box"
CADDY_BIN="/usr/bin/caddy"
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

#========================== 自检 1：网络与域名 ==========================#
log "自检：解析 $DOMAIN"
IPV4_LOCAL="$(curl -fsS --max-time 5 https://ipinfo.io/ip || true)"
IPV4_DNS="$(dig +short A "$DOMAIN" | tr '\n' ' ' || true)"
[[ -z "${IPV4_DNS// }" ]] && die "域名 $DOMAIN 未解析到 A 记录。请先在 DNS 面板添加 A 记录到本机 IP（灰云）。"

if [[ -n "$IPV4_LOCAL" ]] && ! grep -qw "$IPV4_LOCAL" <(echo "$IPV4_DNS"); then
  log "警告：域名解析($IPV4_DNS)与本机公网 IP($IPV4_LOCAL)不一致。若是多IP或中转请确认可达。"
fi
log "DNS A: $IPV4_DNS  | 本机: ${IPV4_LOCAL:-unknown}"

#========================== 自检 2：端口占用 ==========================#
for p in 80 443; do
  if ss -tunlp | grep -qE ":${p}\b"; then
    log "端口 $p 已被占用，将尝试用 Caddy 接管（如非预期请先释放）。"
  fi
done

#========================== 1) 基础环境 / 时区 / BBR / UFW ==========================#
log "安装基础软件 & 设置时区/时间同步/BBR/UFW"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl wget jq tar unzip socat ufw chrony ca-certificates gnupg lsb-release dnsutils net-tools

# 时区与时间同步
timedatectl set-timezone Asia/Shanghai || true
systemctl enable --now chrony || true
timedatectl set-ntp true || true

# BBR
if ! sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
  cat >/etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
  sysctl --system >/dev/null 2>&1 || true
fi
log "BBR: $(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')"

# UFW
ufw --force reset || true
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw allow "${VLESS_PORT}"/tcp
ufw allow "${TROJAN_PORT}"/tcp
ufw allow "${VMESS_PORT}"/tcp
ufw allow "${HY2_PORT}"/udp
ufw --force enable
ok "[OK] UFW 已启用。放行端口：80/tcp, 443/tcp, 443/udp, ${VLESS_PORT}/tcp, ${TROJAN_PORT}/tcp, ${VMESS_PORT}/tcp, ${HY2_PORT}/udp"

#========================== 2) 安装 Caddy（带 GPG 修复 & 回退） ==========================#
log "安装 Caddy（优先 APT，失败则 .deb 回退）"
install_caddy_by_apt(){
  install -d /usr/share/keyrings
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    | tee /etc/apt/sources.list.d/caddy.list
  apt-get update -y
  apt-get install -y caddy
}
if ! command -v caddy >/dev/null 2>&1; then
  if ! install_caddy_by_apt; then
    log "APT 安装失败，尝试 .deb 直装回退"
    TMPD="$(mktemp -d)"
    cd "$TMPD"
    DEB_URL="https://github.com/caddyserver/caddy/releases/download/v2.7.6/caddy_2.7.6_linux_amd64.deb"
    curl -fL --retry 3 -o caddy.deb "$DEB_URL"
    apt-get install -y ./caddy.deb
    cd /root && rm -rf "$TMPD"
  fi
fi
ok "Caddy 已安装：$(caddy version || echo unknown)"

#========================== 3) 配置 Caddy 静态站 ==========================#
install -d "$WEBROOT" "$SUB_DIR"
cat > /etc/caddy/Caddyfile <<EOF
${DOMAIN} {
    encode zstd gzip
    root * ${WEBROOT}
    file_server
}
EOF

# 放一个最简单的首页与订阅占位
cat > "${WEBROOT}/index.html" <<'HTML'
<!doctype html><meta charset="utf-8"><title>OK</title>
<h1>Caddy OK</h1>
<p>订阅地址：<a href="/sub/source.txt">/sub/source.txt</a></p>
HTML

cat > "${SUB_DIR}/source.txt" <<'SUB'
# 脚本稍后会覆盖此文件为四合一订阅
SUB

chown -R www-data:www-data "$WEBROOT" || true
caddy validate --config /etc/caddy/Caddyfile
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

if ! command -v sing-box >/dev/null 2>&1; then
  VER="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)"
  FILE_VER="${VER#v}"
  URL="https://github.com/SagerNet/sing-box/releases/download/${VER}/sing-box-${FILE_VER}-linux-${SB_ARCH}.tar.gz"
  TMP_DIR="$(mktemp -d)"; cd "$TMP_DIR"
  curl -fL --retry 3 -o sb.tgz "$URL"
  tar -xzf sb.tgz
  install -m0755 sing-box-*/sing-box /usr/local/bin/sing-box
  cd /root && rm -rf "$TMP_DIR"
fi
ok "$($SB_BIN version | head -n1 || echo sing-box)"

#========================== 5) 生成密钥 & 环境变量 ==========================#
log "生成凭据"
KP="$($SB_BIN generate reality-keypair)"
REALITY_PRIV="$(echo "$KP" | awk '/PrivateKey/{print $2}')"
REALITY_PUB="$(echo "$KP"  | awk '/PublicKey/{print $2}')"
UUID="$($SB_BIN generate uuid)"
REALITY_SID="$(openssl rand -hex 8)"
HY2_PASS="$(openssl rand -hex 16)"
HY2_OBFS="$(openssl rand -hex 16)"
TROJAN_PASS="$(openssl rand -hex 16)"

cat > "$ENV_FILE" <<EOF
DOMAIN="${DOMAIN}"
EMAIL="${EMAIL}"
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

#========================== 6) 写入 sing-box 配置（证书路径稍后回填） ==========================#
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
        "certificate_path": "/__caddy_cert_placeholder__/fullchain.crt",
        "key_path": "/__caddy_cert_placeholder__/private.key"
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
        "certificate_path": "/__caddy_cert_placeholder__/fullchain.crt",
        "key_path": "/__caddy_cert_placeholder__/private.key"
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
        "certificate_path": "/__caddy_cert_placeholder__/fullchain.crt",
        "key_path": "/__caddy_cert_placeholder__/private.key"
      }
    }
  ],

  "outbounds": [
    { "type": "direct" },
    { "type": "block" }
  ]
}
JSON

cat > /etc/systemd/system/sing-box.service <<'UNIT'
[Unit]
Description=Sing-box
After=network.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=2s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

#========================== 7) 等证书并回填路径 ==========================#
log "定位 Caddy 证书"
CERT_BASE="/var/lib/caddy/.local/share/caddy"
CRT_PATH=""
KEY_PATH=""

for i in {1..18}; do
  CRT_PATH="$(find "$CERT_BASE" -type f -path "*/${DOMAIN}/${DOMAIN}.crt" 2>/dev/null | head -n1 || true)"
  KEY_PATH="$(find "$CERT_BASE" -type f -path "*/${DOMAIN}/${DOMAIN}.key" 2>/dev/null | head -n1 || true)"
  [[ -z "$KEY_PATH" ]] && KEY_PATH="$(find "$CERT_BASE/keys" -type f -path "*/${DOMAIN}/${DOMAIN}.key" 2>/dev/null | head -n1 || true)"
  if [[ -f "$CRT_PATH" && -f "$KEY_PATH" ]]; then break; fi
  sleep 10
done

if [[ ! -f "$CRT_PATH" || ! -f "$KEY_PATH" ]]; then
  die "仍未找到证书：/var/lib/caddy/.local/share/caddy/.../${DOMAIN}/{.crt,.key}。请确认 DNS 已生效且为灰云。查看：journalctl -u caddy -n 100 --no-pager"
fi
ok "证书已就绪"

# 回填配置中的证书占位路径
jq \
  --arg crt "$CRT_PATH" \
  --arg key "$KEY_PATH" \
  '(.inbounds[] | select(has("tls") and .tls.enabled==true) | .tls.certificate_path) |= $crt
   | (.inbounds[] | select(has("tls") and .tls.enabled==true) | .tls.key_path) |= $key' \
  /etc/sing-box/config.json > /etc/sing-box/config.json.new
mv /etc/sing-box/config.json.new /etc/sing-box/config.json

# 校验并启动
$SB_BIN check -c /etc/sing-box/config.json
systemctl daemon-reload
systemctl enable --now sing-box

#========================== 8) 生成四合一订阅 ==========================#
log "生成订阅链接"
VMESS_JSON=$(cat <<JSON
{"v":"2","ps":"VMess-WS-TLS","add":"${DOMAIN}","port":"${VMESS_PORT}","id":"${UUID}","aid":"0","net":"ws","type":"","host":"${DOMAIN}","path":"/vmess","tls":"tls","sni":"${DOMAIN}"}
JSON
)
VMESS_B64="$(echo -n "$VMESS_JSON" | base64 -w 0)"
HY2="hysteria2://${HY2_PASS}@${DOMAIN}:${HY2_PORT}/?obfs=salamander&obfsParam=${HY2_OBFS}&peer=${DOMAIN}&alpn=h3#HY2"
TROJAN="trojan://${TROJAN_PASS}@${DOMAIN}:${TROJAN_PORT}?peer=${DOMAIN}&alpn=h2,http/1.1#Trojan"
VLESS="vless://${UUID}@${DOMAIN}:${VLESS_PORT}?encryption=none&flow=&type=tcp&security=reality&pbk=${REALITY_PUB}&sid=${REALITY_SID}&sni=www.cloudflare.com#VLESS-REALITY"
VMESS="vmess://${VMESS_B64}"

install -d "$SUB_DIR"
cat > "${SUB_DIR}/source.txt" <<EOF
$HY2
$TROJAN
$VLESS
$VMESS
EOF

chown -R www-data:www-data "$WEBROOT" || true
systemctl reload caddy || true

#========================== 9) 完成 & 输出 ==========================#
ok "部署完成！"
echo "——————————————————————————————"
echo "订阅地址： https://${DOMAIN}/sub/source.txt"
echo "HY2:     $HY2"
echo "Trojan:  $TROJAN"
echo "VLESS:   $VLESS"
echo "VMess:   $VMESS"
echo
echo "Sing-box 日志：journalctl -u sing-box -n 50 --no-pager"
echo "Caddy   日志：journalctl -u caddy -n 50 --no-pager"
echo "环境变量保存在：$ENV_FILE"
