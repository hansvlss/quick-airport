## 快速开始

```bash
# 一台全新的 Ubuntu 20.04/22.04
apt update && apt install -y curl git

# 拉脚本
git clone https://github.com/<你的账号>/quick-airport.git
cd quick-airport
chmod +x quick-airport.sh

# 运行（EMAIL 可留空）
DOMAIN="你的域名.com" EMAIL="你@邮箱.com" bash quick-airport.sh

# Quick Airport 一键部署脚本

本项目提供一键脚本，快速在 VPS 上部署四合一节点：

- Hysteria2
- Trojan
- VLESS Reality
- VMess-WS+TLS

支持自动签发证书（Caddy），生成订阅链接，开箱即用。

---

## 🚀 使用方法

### 1. 准备环境

```
apt update && apt install -y curl wget git

```

### 2. 下载脚本
```
curl -fsSL https://raw.githubusercontent.com/hansvlss/quick-airport/main/quick-airport.sh -o /root/quick-airport.sh
chmod +x /root/quick-airport.sh
```
### 3. 执行脚本

请替换为你自己的域名和邮箱（邮箱可留空）：
```
DOMAIN="你的域名.com" EMAIL="你的邮箱" bash /root/quick-airport.sh
```
📡 成功后信息
	•	订阅地址：
```
https://你的域名.com/sub/source.txt
```
	•	终端会输出四个协议的节点信息：
	•	Hysteria2
	•	Trojan
	•	VLESS Reality
	•	VMess-WS+TLS

可直接导入 v2rayN、Clash、Shadowrocket 等客户端。
