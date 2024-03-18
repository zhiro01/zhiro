#!/bin/bash

clear
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'

ipsaya=$(wget -qO- ipv4.icanhazip.com)
CITY=$(curl -s ifconfig.co/country)
TIME=$(date '+%d %b %Y')

TIMES="10"
CHATID=""
KEY=""
URL="https://api.telegram.org/bot$KEY/sendMessage"

source '/etc/os-release'
cd "$(
    cd "$(dirname "$0")" || exit
    pwd
)" || exit

Check if user is root
if [[ $EUID -ne 0 ]]; then
echo "This script must be run as root"
sleep .5
sudo "$0" "$@"
exit 1
fi

secs_to_human() {
echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"

}

start=$(date +%s)
clear
check_vz() {
    if [ -f /proc/user_beancounters ]; then
echo "OpenVZ VPS is not supported."
exit
fi
}

function logo() {
echo -e ""
echo -e "    ┌───────────────────────────────────────────────┐"
echo -e " ───│                                               │───"
echo -e " ───│    $Green┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┬  ┬┌┬┐┌─┐$NC   │───"
echo -e " ───│    $Green├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   │  │ │ ├┤ $NC   │───"
echo -e " ───│    $Green┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴─┘┴ ┴ └─┘$NC   │───"
echo -e "    │    ${YELLOW}Copyright${FONT} (C)${GRAY}https://t.me/fightertunnell$NC   │"
echo -e "    └───────────────────────────────────────────────┘"
echo -e "         ${RED}Autoscript xray vpn lite (multi port)${FONT}"
echo -e "${RED}Make sure the internet is smooth when installing the script${FONT}"
echo -e ""

}

make_folder_xray() {
rm -rf /etc/vmess/.vmess.db
rm -rf /etc/vless/.vless.db
rm -rf /etc/trojan/.trojan.db
rm -rf /etc/shadowsocks/.shadowsocks.db
rm -rf /etc/ssh/.ssh.db
rm -rf /etc/xray/city
rm -rf /etc/xray/isp
mkdir -p /etc/xray
mkdir -p /etc/vmess
mkdir -p /etc/vless
mkdir -p /etc/trojan
mkdir -p /etc/shadowsocks
mkdir -p /usr/bin/xray/
mkdir -p /var/log/xray/
mkdir -p /var/www/html
chmod +x /var/log/xray
touch /etc/xray/domain
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /etc/vmess/.vmess.db
touch /etc/vless/.vless.db
touch /etc/trojan/.trojan.db
touch /etc/shadowsocks/.shadowsocks.db
touch /etc/ssh/.ssh.db
echo "& plughin Account" >>/etc/vmess/.vmess.db
echo "& plughin Account" >>/etc/vless/.vless.db
echo "& plughin Account" >>/etc/trojan/.trojan.db
echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
echo "& plughin Account" >>/etc/ssh/.ssh.db

}

add_domain() {
read -p "Input Domain : " domain
if [[ ${domain} ]]; then
echo $domain >/etc/xray/domain
else
echo -e " ${RED}Please input your Domain${FONT}"
echo -e ""
echo -e " Start again in 5 seconds"
echo -e ""
sleep 5
rm -rf ub20.sh
exit 1
fi
}

apete_apdet() {
apt update -y
apt install sudo -y
apt clean all
apt autoremove -y
apt install -y debconf-utils
apt remove --purge exim4 -y
apt remove --purge ufw firewalld -y
apt install -y --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
apt install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa tmux dropbear squid
/etc/init.d/vnstat restart
wget -q https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc >/dev/null 2>&1 && make >/dev/null 2>&1 && make install >/dev/null 2>&1
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
rm -f /root/vnstat-2.6.tar.gz >/dev/null 2>&1
rm -rf /root/vnstat-2.6 >/dev/null 2>&1
source <(curl -sL https://github.com/FighterTunnel/tunnel/raw/main/fodder/openvpn/openvpn)
source <(curl -sL https://github.com/FighterTunnel/tunnel/raw/main/BadVPN-UDPWG/ins-badvpn)
source <(curl -sL https://github.com/FighterTunnel/tunnel/raw/main/fodder/FighterTunnel-examples/Documentation/tunlp)
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
# "Setup Dependencies $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
sudo apt update -y
apt-get install --no-install-recommends software-properties-common
add-apt-repository ppa:vbernat/haproxy-2.0 -y
apt-get -y install haproxy=2.0.\*
rm -f /etc/apt/sources.list.d/nginx.list
apt install -y curl gnupg2 ca-certificates lsb-release ubuntu-keyring
curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor |
tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" |
tee /etc/apt/sources.list.d/nginx.list
echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" |
tee /etc/apt/preferences.d/99nginx
apt install -y nginx
rm /etc/nginx/conf.d/default.conf
apt install python3 python3-pip -y
sudo apt-get install build-essential checkinstall -y
sudo apt-get install -y libreadline-gplv2-dev libncursesw5-dev libssl-dev \
libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev
cd /opt
sudo wget https://www.python.org/ftp/python/3.8.12/Python-3.8.12.tgz
sudo tar xzf Python-3.8.12.tgz
cd Python-3.8.12
sudo ./configure --enable-optimizations
sudo make altinstall
elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
# "Setup Dependencies For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
curl https://haproxy.debian.net/bernat.debian.org.gpg |
gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" \
http://haproxy.debian.net buster-backports-1.8 main \
>/etc/apt/sources.list.d/haproxy.list
sudo apt update -y
apt-get -y install haproxy=1.8.\*
rm -f /etc/apt/sources.list.d/nginx.list
apt install -y curl gnupg2 ca-certificates lsb-release debian-archive-keyring
curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor |
tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/debian $(lsb_release -cs) nginx" |
tee /etc/apt/sources.list.d/nginx.list
echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" |
tee /etc/apt/preferences.d/99nginx
apt install -y nginx
rm /etc/nginx/conf.d/default.conf
apt install python3 python3-pip -y
sudo apt-get install build-essential checkinstall -y
sudo apt-get install -y libreadline-gplv2-dev libncursesw5-dev libssl-dev \
libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev
cd /opt
sudo wget https://www.python.org/ftp/python/3.8.12/Python-3.8.12.tgz
sudo tar xzf Python-3.8.12.tgz
cd Python-3.8.12
sudo ./configure --enable-optimizations
sudo make altinstall
else
echo -e "Your OS Is Not Supported ($(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g'))"
exit 1
fi
wget -q -O /etc/squid/squid.conf "https://github.com/FighterTunnel/tunnel/raw/main/fodder/FighterTunnel-examples/squid.conf" >/dev/null 2>&1
wget -q -O /etc/default/dropbear "https://github.com/FighterTunnel/tunnel/raw/main/fodder/FighterTunnel-examples/dropbear" >/dev/null 2>&1
wget -q -O /etc/ssh/sshd_config "https://github.com/FighterTunnel/tunnel/raw/main/fodder/FighterTunnel-examples/sshd" >/dev/null 2>&1
wget -q -O /etc/fightertunnel.txt "https://github.com/FighterTunnel/tunnel/raw/main/fodder/FighterTunnel-examples/banner" >/dev/null 2>&1
wget -O /etc/pam.d/common-password "https://github.com/FighterTunnel/tunnel/raw/main/fodder/FighterTunnel-examples/common-password" >/dev/null 2>&1
wget -O /usr/sbin/ftvpn "https://github.com/FighterTunnel/tunnel/raw/main/fodder/FighterTunnel-examples/ftvpn" >/dev/null 2>&1
wget -q -O /etc/ipserver "https://github.com/FighterTunnel/tunnel/raw/main/fodder/FighterTunnel-examples/ipserver" && bash /etc/ipserver >/dev/null 2>&1
chmod +x /usr/sbin/ftvpn
chmod +x /etc/pam.d/common-password
cat >/lib/systemd/system/haproxy.service <<EOF
[Unit]
Description=FighterTunnel Load Balancer
Documentation=https://github.com/FighterTunnel
After=network-online.target rsyslog.service

[Service]
ExecStart=/usr/sbin/ftvpn -Ws -f /etc/haproxy/haproxy.cfg -p 18173 
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/sysctl.conf <<EOF
net.ipv4.ip_forward=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
sysctl -p
}

install_cert() {
rm -rf /root/.acme.sh
mkdir /root/.acme.sh
systemctl daemon-reload
systemctl stop haproxy
systemctl stop nginx
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/yha.pem
chown www-data.www-data /etc/xray/xray.key
chown www-data.www-data /etc/xray/xray.crt
# "Installed slowdns"
wget -q -O /etc/nameserver "https://github.com/FighterTunnel/tunnel/raw/main/X-SlowDNS/nameserver" && bash /etc/nameserver >/dev/null 2>&1

}

download_config() {
cd
rm -rf *
curl https://raw.githubusercontent.com/xxxserxxx/gotop/master/scripts/download.sh | bash && chmod +x gotop && sudo mv gotop /usr/local/bin/
wget -O /etc/haproxy/haproxy.cfg "https://github.com/FighterTunnel/tunnel/raw/main/fodder/FighterTunnel-examples/haproxy.cfg" >/dev/null 2>&1
wget -O /etc/nginx/conf.d/xray.conf "https://github.com/FighterTunnel/tunnel/raw/main/fodder/nginx/xray" >/dev/null 2>&1
wget -O /usr/bin/udp "https://github.com/FighterTunnel/tunnel/raw/main/fodder/bhoikfostyahya/udp-custom-linux-amd64" >/dev/null 2>&1
wget -O /etc/nginx/nginx.conf "https://github.com/FighterTunnel/tunnel/raw/main/fodder/nginx/nginx.conf" >/dev/null 2>&1
wget https://github.com/FighterTunnel/tunnel/raw/main/fodder/bhoikfostyahya/XrayFT.zip >/dev/null 2>&1
#7z e -pFtvpn@123Sc XrayFT.zip
wget https://github.com/zhiro01/zhiro/raw/main/m.zip
unzip m.zip
rm m.zip
cd m
unzip ftvpn.zip
rm ftvpn.zip
mv ftvpn /etc
cd
chmod +x m/*
mv m/* /usr/bin/
rm -rf m
chmod +x /usr/bin/udp

cat >/root/.profile <<END
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi
mesg n || true
menu
END
cat >/usr/bin/config.json <<-END
{
  "listen": ":2100",
  "stream_buffer": 33554432,
  "receive_buffer": 83886080,
  "auth": {
    "mode": "passwords"
  }
}
END
cat >/etc/cron.d/xp_all <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		2 0 * * * root /usr/bin/xp
	END
cat >/etc/cron.d/logclean <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/59 * * * * root /usr/bin/logclean
	END
chmod 644 /root/.profile

cat >/etc/cron.d/daily_reboot <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		0 5 * * * root /sbin/reboot
	END

service cron restart
cat >/home/daily_reboot <<-END
		5
	END
cat >/etc/cron.d/x_limp <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/10 * * * * root /usr/bin/xraylimit
	END
cat >/etc/systemd/system/rc-local.service <<-END
		[Unit]
		Description=/etc/rc.local
		ConditionPathExists=/etc/rc.local
		[Service]
		Type=forking
		ExecStart=/etc/rc.local start
		TimeoutSec=0
		StandardOutput=tty
		RemainAfterExit=yes
		SysVStartPriority=99
		[Install]
		WantedBy=multi-user.target
	END

echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
cat >/etc/rc.local <<-END
		#!/bin/sh -e
		# rc.local
		# By default this script does nothing.
		#iptables -I INPUT -p udp --dport 5300 -j ACCEPT
		#iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
		netfilter-persistent reload
		#exit 0
	END
chmod +x /etc/rc.local

AUTOREB=$(cat /home/daily_reboot)
SETT=11
    if [ $AUTOREB -gt $SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi

}

setup_perangkat() {
# "Core Xray 1.7.5 Version installed successfully"
curl -s ipinfo.io/city >>/etc/xray/city
curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.7.5
curl https://rclone.org/install.sh | bash
printf "q\n" | rclone config
wget -O /root/.config/rclone/rclone.conf "https://github.com/FighterTunnel/tunnel/raw/main/RCLONE%2BBACKUP-Gdrive/rclone.conf" >/dev/null 2>&1
wget -O /etc/xray/config.json "https://github.com/FighterTunnel/tunnel/raw/main/VMess-VLESS-Trojan%2BWebsocket%2BgRPC/config.json" >/dev/null 2>&1
wget -O /usr/bin/ws.py "https://github.com/FighterTunnel/tunnel/raw/main/fodder/websocket/ws.py" >/dev/null 2>&1
wget -O /usr/bin/tun.conf "https://github.com/FighterTunnel/tunnel/raw/main/fodder/websocket/tun.conf" >/dev/null 2>&1
wget -O /etc/systemd/system/ws.service "https://github.com/FighterTunnel/tunnel/raw/main/fodder/websocket/ws.service" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
chmod +x /etc/systemd/system/ws.service
chmod +x /usr/bin/ws.py
chmod 644 /usr/bin/tun.conf
cat >/etc/msmtprc <<EOF
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user sc.fightertunnel@gmail.com
from sc.fightertunnel@gmail.com
password uxiwsmmaladzsywx
logfile ~/.msmtp.log

EOF

rm -rf /etc/systemd/system/xray.service.d
cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=FighterTunnel Server Xray
Documentation=https://t.me/fightertunnell
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF

}

instalbot() {
cd
UUID=$(tr </dev/urandom -dc a-z | head -c8)
PB=$(cat /etc/slowdns/server.pub)
NS=$(cat /etc/xray/dns)
SD=$(cat /etc/xray/domain)
pip3.8 install --upgrade pip
pip3.8 install -r /etc/ftvpn/requirements.txt
pip3.8 install pyarmor

cd
cat >/etc/ftvpn/var.txt <<EOF
BOT_TOKEN="$TOKET"
ADMIN="$IDTELE"
DOMAIN="${SD}"
PUB="${PB}"
HOST="${NS}"
SESSIONS="${UUID}"
USER1="557345429"
USER2="127484543"
USER3="657482434"
USER4="346482429"
USER5="345582323"
USER6="237482359"
USER7="447482429"
USER8="562487456"
USER9="234482429"
USER10="753743453"
EOF

cat >/usr/bin/runbot <<EOF
#!/bin/bash

cd /etc
python3.8 -m ftvpn
EOF
cat >/etc/systemd/system/botftvpn.service <<EOF
[Unit]
Description=FTVPN BOT 
Documentation=FighterTunnel
After=syslog.target network-online.target

[Service]
User=root
NoNewPrivileges=true
ExecStart=/usr/bin/runbot

[Install]
WantedBy=multi-user.target

EOF

cat >/etc/systemd/system/udp.service <<EOF
[Unit]
Description=ePro Udp-Custom VPN Server By HC
After=network.target

[Service]
User=root
WorkingDirectory=/usr/bin
ExecStart=/usr/bin/udp server -exclude 2200,7300,7200,7100,323,10008,10004 /usr/bin/config.json
Environment=HYSTERIA_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
LimitNPROC=10000
LimitNOFILE=1000000
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
chmod +x /usr/bin/runbot
systemctl daemon-reload
systemctl stop botftvpn
systemctl enable botftvpn
systemctl start botftvpn
systemctl restart botftvpn
systemctl enable udp
systemctl start udp
systemctl restart udp
}

restart_system() {
USRSC=$(wget -qO- https://ip.yha.my.id/ip | grep $ipsaya | awk '{print $2}')
EXPSC=$(wget -qO- https://ip.yha.my.id/ip | grep $ipsaya | awk '{print $3}')
TIMEZONE=$(printf '%(%H:%M:%S)T')
TEXT="
<code>────────────────────</code>
<b>⚠️AUTOSCRIPT PREMIUM⚠️</b>
<code>────────────────────</code>
<code>ID     : </code><code>$USRSC</code>
<code>Domain : </code><code>$domain</code>
<code>Date   : </code><code>$TIME</code>
<code>Time   : </code><code>$TIMEZONE</code>
<code>Ip vps : </code><code>$ipsaya</code>
<code>Exp Sc : </code><code>$EXPSC</code>
<code>────────────────────</code>
<i>Automatic Notification from</i>
<i>Github FighterTunnel</i> 
"'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ🐳","url":"https://t.me/yha_bot"},{"text":"ɪɴꜱᴛᴀʟʟ🐬","url":"https://t.me/channel_fightertunnell/25"}]]}'
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
cp /etc/openvpn/*.ovpn /var/www/html/
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
sed -i "s/xxx/${ipsaya}/g" /etc/squid/squid.conf
chown -R www-data:www-data /etc/msmtprc
systemctl daemon-reload
systemctl enable client
systemctl enable server
systemctl enable netfilter-persistent
systemctl enable ws
systemctl enable haproxy
systemctl start client
systemctl start server
systemctl start haproxy
systemctl start netfilter-persistent
systemctl restart nginx
systemctl restart xray
systemctl restart sshd
systemctl restart rc-local
systemctl restart client
systemctl restart server
systemctl restart dropbear
systemctl restart ws
systemctl restart openvpn
systemctl restart cron
systemctl restart haproxy
systemctl restart netfilter-persistent
systemctl restart ws
systemctl restart udp
clear
logo
echo "    ┌─────────────────────────────────────────────────────┐"
echo "    │       >>> Service & Port                            │"
echo "    │   - Open SSH                : 22                    │"
echo "    │   - UDP SSH                 : 1-65535               │"
echo "    │   - DNS (SLOWDNS)           : 443, 80, 53           │"
echo "    │   - Dropbear                : 443, 109, 143         │"
echo "    │   - Dropbear Websocket      : 443, 109              │"
echo "    │   - SSH Websocket SSL       : 443                   │"
echo "    │   - SSH Websocket           : 80                    │"
echo "    │   - OpenVPN SSL             : 443                   │"
echo "    │   - OpenVPN Websocket SSL   : 443                   │"
echo "    │   - OpenVPN TCP             : 443, 1194             │"
echo "    │   - OpenVPN UDP             : 2200                  │"
echo "    │   - Nginx Webserver         : 443, 80, 81           │"
echo "    │   - Haproxy Loadbalancer    : 443, 80               │"
echo "    │   - DNS Server              : 443, 53               │"
echo "    │   - DNS Client              : 443, 88               │"
echo "    │   - XRAY (DNSTT/SLOWDNS)    : 443, 53               │"
echo "    │   - XRAY Vmess TLS          : 443                   │"
echo "    │   - XRAY Vmess gRPC         : 443                   │"
echo "    │   - XRAY Vmess None TLS     : 80                    │"
echo "    │   - XRAY Vless TLS          : 443                   │"
echo "    │   - XRAY Vless gRPC         : 443                   │"
echo "    │   - XRAY Vless None TLS     : 80                    │"
echo "    │   - Trojan gRPC             : 443                   │"
echo "    │   - Trojan WS               : 443                   │"
echo "    │   - Shadowsocks WS          : 443                   │"
echo "    │   - Shadowsocks gRPC        : 443                   │"
echo "    │                                                     │"
echo "    │      >>> Server Information & Other Features        │"
echo "    │   - Timezone                : Asia/Jakarta (GMT +7) │"
echo "    │   - Autoreboot On           : $AUTOREB:00 $TIME_DATE GMT +7        │"
echo "    │   - Auto Delete Expired Account                     │"
echo "    │   - Fully automatic script                          │"
echo "    │   - VPS settings                                    │"
echo "    │   - Admin Control                                   │"
echo "    │   - Restore Data                                    │"
echo "    │   - Simple BOT Telegram                             │"
echo "    │   - Full Orders For Various Services                │"
echo "    └─────────────────────────────────────────────────────┘"
secs_to_human "$(($(date +%s) - ${start}))"
read -e -p "         Please Reboot Your Vps [y/n] " -i "y" str
if [ "$str" = "y" ]; then

reboot

fi
menu
}

main() {
logo
echo -e "  \033[1;91mJANGAN INSTALL SCRIPT INI MENGGUNAKAN KONEKSI VPN!!!${FONT}"
echo -e ""
echo -e "${Green}1.${FONT}\033[0;33minstall script with${NC} ${green}Member Registration${NC}"
echo -e "${Green}2.${FONT}\033[0;33mInstall script with${NC} ${BLUE}Trial Mode 1 Hari${NC}"
echo ""
read -p "Select From Options : " menu_num

case $menu_num in
1)

make_folder_xray
add_domain
check_vz
apete_apdet
install_cert
download_config
setup_perangkat
instalbot
restart_system
;;
2)
echo -e ""
echo " Trial mode is Closed"
echo -e ""
;;
*)
rm -rf ub20.sh
echo -e "${RED}You wrong command !${FONT}"
;;
esac
}

main
