#!/usr/bin/env bash
# quick-airport.sh
# 4 合 1：VLESS Reality / Trojan / VMess-WS+TLS / Hysteria2
# 订阅以静态文件 /sub/source.txt 提供；证书交给 Caddy 自动签发
# 运行前传入：DOMAIN=你的域名.com（EMAIL 可选）
# 例：DOMAIN="vpn.example.com" EMAIL="me@example.com" bash quick-airport.sh

set -euo pipefail

#======================= 基础变量 =======================#
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"                  # 可留空
HY2_PORT="${HY2_PORT:-8445}"        # UDP
VLESS_PORT="${VLESS_PORT:-8442}"    # TCP
TROJAN_PORT="${TROJAN_PORT:-8443}"  # TCP
VMESS_PORT="${VMESS_PORT:-8444}"    # TCP

SB_BIN="/usr/local/bin/sing-box"
CADDYFILE="/etc/caddy/Caddyfile"
WEBROOT="/var/www"
SUB_DIR="$WEBROOT/sub"
ENV_FILE="/root/airport.env"
LOG="/root/quick-airport.log"

log(){ echo -e "[$(date +'%F %T')] $*" | tee -a "$LOG" >&2; }
die(){ echo -e "✖ $*" | tee -a "$LOG" >&2; exit 1; }
ok(){  echo -e "✔ $*" | tee -a "$LOG" >&2; }

trap 'die "脚本异常中止。详见日志：$LOG"' ERR

[[ -z "$DOMAIN" ]] && die '未传入 DOMAIN。示例：DOMAIN="vpn.example.com" bash quick-airport.sh'

#======================= 1) 基础环境 =======================#
log "安装基础软件 & 设置时区/时间同步/BBR/UFW"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl wget jq tar unzip ufw chrony gpg lsb-release software-properties-common net-tools dnsutils

# 时区与时间同步
timedatectl set-timezone Asia/Shanghai || true
systemctl enable --now chrony || systemctl enable --now chrony.service || true

# 开启 BBR
if ! sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
  echo "net.core.default_qdisc=fq"    >> /etc/sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  sysctl -p || true
fi

# UFW：放行端口
ufw --force reset || true
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw allow ${VLESS_PORT}/tcp
ufw allow ${TROJAN_PORT}/tcp
ufw allow ${VMESS_PORT}/tcp
ufw allow ${HY2_PORT}/udp
ufw --force enable
ok "[OK] UFW 已启用。放行端口：80/tcp, 443/tcp, 443/udp, ${VLESS_PORT}/tcp, ${TROJAN_PORT}/tcp, ${VMESS_PORT}/tcp, ${HY2_PORT}/udp"

#======================= 2) 安装 Caddy (APT + GPG 修复) =======================#
log "安装 / 修复 Caddy APT 源与 GPG key"
install -d /usr/share/keyrings /etc/apt/sources.list.d
curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
  | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

cat >/etc/apt/sources.list.d/caddy.list <<'EOF'
# Caddy stable repo
deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main
deb-src [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main
EOF

apt-get update -y || true
if ! dpkg -s caddy >/dev/null 2>&1; then
  apt-get install -y caddy || die "Caddy 安装失败（APT）。"
fi

#======================= 3) 配置 Caddy（静态站点 + 订阅） =======================#
log "写入 Caddy 配置（最简静态站点）"
install -d /etc/caddy "$WEBROOT" "$SUB_DIR"

cat >"$CADDYFILE" <<EOF
${DOMAIN} {
    encode zstd gzip
    root * ${WEBROOT}
    file_server
}
EOF

# 简单首页与订阅占位
cat > "${WEBROOT}/index.html" <<'HTML'
<!doctype html><meta charset="utf-8"><title>OK</title>
<h1>Caddy OK</h1>
<p>订阅：<a href="/sub/source.txt">/sub/source.txt</a></p>
HTML

echo -e "# 将由脚本生成四协议链接\n" > "${SUB_DIR}/source.txt"

chown -R www-data:www-data "${WEBROOT}" || true
caddy validate --config "$CADDYFILE"
systemctl reload caddy || systemctl restart caddy

log "等待 Let's Encrypt 证书颁发…"
sleep 3
ok "Caddy 已运行"

#======================= 4) 安装 sing-box（最新发布） =======================#
log "安装 sing-box"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64) SB_ARCH="amd64" ;;
  aarch64|arm64) SB_ARCH="arm64" ;;
  armv7l) SB_ARCH="armv7" ;;
  *) die "不支持的架构: $ARCH_RAW" ;;
esac

TMP_DIR="$(mktemp -d)"
pushd "$TMP_DIR" >/dev/null
VER="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)" || die "获取 sing-box 版本失败"
FILE_VER="${VER#v}"
URL="https://github.com/SagerNet/sing-box/releases/download/${VER}/sing-box-${FILE_VER}-linux-${SB_ARCH}.tar.gz"
curl -fL --retry 3 -o sb.tgz "$URL"
tar -xzf sb.tgz
install -m 0755 sing-box-*/sing-box /usr/local/bin/sing-box
popd >/dev/null
rm -rf "$TMP_DIR"
$SB_BIN version | tee -a "$LOG" || die "sing-box 校验失败"
ok "$($SB_BIN version | head -n1)"

#======================= 5) 生成凭据 & 保存 =======================#
log "生成凭据"
KP="$($SB_BIN generate reality-keypair)"
REALITY_PRIV="$(awk '/PrivateKey/ {print $2}' <<<"$KP")"
REALITY_PUB="$(awk '/PublicKey/ {print $2}' <<<"$KP")"
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

#======================= 6) 定位证书路径 =======================#
log "定位 Caddy 证书"
CERT_BASE="/var/lib/caddy/.local/share/caddy"
CRT_PATH=""
KEY_PATH=""
for i in {1..18}; do
  CRT_PATH="$(find "$CERT_BASE" -type f -path "*/${DOMAIN}/${DOMAIN}.crt" 2>/dev/null | head -n1 || true)"
  KEY_PATH="$(find "$CERT_BASE" -type f -path "*/${DOMAIN}/${DOMAIN}.key" 2>/dev/null | head -n1 || true)"
  [[ -z "$KEY_PATH" ]] && KEY_PATH="$(find /var/lib/caddy/.local/share/caddy/keys -type f -path "*/${DOMAIN}/${DOMAIN}.key" 2>/dev/null | head -n1 || true)"
  [[ -f "$CRT_PATH" && -f "$KEY_PATH" ]] && break
  sleep 10
done
[[ -f "$CRT_PATH" && -f "$KEY_PATH" ]] || {
  journalctl -u caddy -n 100 --no-pager | tee -a "$LOG"
  die "仍未找到证书：${DOMAIN}.crt / ${DOMAIN}.key。请确认 A 记录指向本机且 Cloudflare 为灰云。"
}
ok "证书 OK：$CRT_PATH / $KEY_PATH"

#======================= 7) 写入 sing-box 配置 & 服务 =======================#
log "写入 sing-box 配置并启动"
install -d /etc/sing-box

cat > /etc/sing-box/config.json <<EOF
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
EOF

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

$SB_BIN check -c /etc/sing-box/config.json
systemctl daemon-reload
systemctl enable --now sing-box

#======================= 8) 生成四协议订阅 =======================#
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

#======================= 9) 完成 & 输出 =======================#
ok "部署完成！"
echo "——————————————————————————————————"
echo "订阅地址： https://${DOMAIN}/sub/source.txt"
echo "HY2:     $HY2"
echo "Trojan:  $TROJAN"
echo "VLESS:   $VLESS"
echo "VMess:   $VMESS"
echo
echo "Sing-box 日志：journalctl -u sing-box -n 50 --no-pager"
echo "Caddy   日志：journalctl -u caddy -n 50 --no-pager"
echo "环境变量保存在：$ENV_FILE"
add quick-airport script
