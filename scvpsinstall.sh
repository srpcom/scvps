#!/bin/bash

# ==============================================================================
# Skrip Auto-Installer VPN Xray (Trojan, VLESS, VMESS) untuk Ubuntu 24.04
# Deskripsi: Menginstal Xray-core, mengkonfigurasinya, dan menyediakan
#            manajemen akun klien dengan fitur kedaluwarsa.
# ==============================================================================

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variabel Global
DOMAIN=""
EMAIL=""
MAIN_UUID="" # UUID untuk akun admin/utama yang dibuat saat instalasi awal
VLESS_WS_PATH="/vless" 
VMESS_WS_PATH="/vmess"   
CERT_DIR="/etc/xray/certs"
XRAY_CONFIG_FILE="/etc/xray/config.json"
INSTALL_INFO_FILE="/etc/xray/install_info.txt" # Menyimpan info domain, path, dll.
USER_MANAGEMENT_FILE="/etc/xray/user_management.csv" # Format: uuid,account_name,type,creation_date_unix,expiry_date_unix,email_for_client
NGINX_AVAILABLE_SITES="/etc/nginx/sites-available"
NGINX_ENABLED_SITES="/etc/nginx/sites-enabled"
SCRIPT_ABSOLUTE_PATH="" # Akan diisi oleh skrip itu sendiri

# Fungsi untuk mendapatkan path absolut skrip
get_script_path() {
    local source="${BASH_SOURCE[0]}"
    while [ -h "$source" ]; do # resolve $source until the file is no longer a symlink
        SCRIPT_DIR="$( cd -P "$( dirname "$source" )" &> /dev/null && pwd )"
        source="$(readlink "$source")"
        [[ $source != /* ]] && source="$SCRIPT_DIR/$source" # if $source was a relative symlink, we need to resolve it relative to the path where the symlink file was located
    done
    SCRIPT_DIR="$( cd -P "$( dirname "$source" )" &> /dev/null && pwd )"
    SCRIPT_ABSOLUTE_PATH="$SCRIPT_DIR/$(basename "$source")"
}

# Fungsi untuk menampilkan pesan error dan keluar
error_exit() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

# Fungsi untuk menampilkan pesan sukses
success_msg() {
    echo -e "${GREEN}$1${NC}"
}

# Fungsi untuk menampilkan pesan informasi
info_msg() {
    echo -e "${BLUE}$1${NC}"
}

# Fungsi untuk menampilkan pesan peringatan
warning_msg() {
    echo -e "${YELLOW}$1${NC}"
}

# Memeriksa apakah skrip dijalankan sebagai root
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error_exit "Skrip ini harus dijalankan sebagai root. Coba 'sudo $SCRIPT_ABSOLUTE_PATH'."
    fi
}

# Memeriksa dependensi dasar
check_dependencies() {
    local missing_deps=()
    # jq sangat penting untuk manipulasi JSON
    local deps=("curl" "wget" "socat" "unzip" "cron" "qrencode" "nginx" "jq" "dig")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        info_msg "Beberapa dependensi hilang. Menginstal: ${missing_deps[*]}..."
        apt update &>/dev/null
        apt install -y "${missing_deps[@]}" &>/dev/null || error_exit "Gagal menginstal dependensi dasar (${missing_deps[*]})."
        success_msg "Dependensi berhasil diinstal."
    fi
}

# Menghentikan layanan yang mungkin bentrok port
stop_conflicting_services() {
    info_msg "Mencoba menghentikan layanan yang mungkin bentrok port (80, 443)..."
    systemctl stop nginx &>/dev/null
    systemctl stop apache2 &>/dev/null 
}

# Meminta input dari pengguna untuk instalasi awal
get_user_input_for_install() {
    clear
    info_msg "Selamat datang di Skrip Auto-Installer VPN Xray untuk Ubuntu 24.04"
    echo "------------------------------------------------------------------"
    
    while true; do
        read -rp "Masukkan nama domain Anda (contoh: vpn.domainku.com): " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            warning_msg "Nama domain tidak boleh kosong."
        elif ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            warning_msg "Format domain tidak valid."
        else
            info_msg "Memverifikasi resolusi DNS untuk $DOMAIN..."
            local resolved_ip
            resolved_ip=$(dig +short "$DOMAIN" A @8.8.8.8) 
            local server_ip
            server_ip=$(curl -s --max-time 5 ifconfig.me || curl -s --max-time 5 api.ipify.org)

            if [[ -z "$server_ip" ]]; then
                warning_msg "Tidak dapat mengambil IP server. Periksa koneksi internet."
                read -rp "Lanjutkan tanpa verifikasi IP? (y/n): " force_continue
                if [[ ! "$force_continue" =~ ^[Yy]$ ]]; then continue; fi
            fi

            if [[ -z "$resolved_ip" ]]; then
                warning_msg "Domain '$DOMAIN' tidak dapat diresolve. Pastikan A record sudah benar dan propagasi DNS selesai."
            elif [[ -n "$server_ip" && "$resolved_ip" != "$server_ip" ]]; then
                 warning_msg "Domain '$DOMAIN' mengarah ke IP ($resolved_ip), yang berbeda dari IP server ini ($server_ip)."
                 read -rp "Apakah Anda yakin ingin melanjutkan? (y/n): " continue_anyway
                 if [[ ! "$continue_anyway" =~ ^[Yy]$ ]]; then continue; fi
            elif [[ -n "$server_ip" ]]; then
                success_msg "Domain '$DOMAIN' berhasil diresolve ke IP server ini ($server_ip)."
            fi
            break 
        fi
    done

    while true; do
        read -rp "Masukkan alamat email Anda (untuk notifikasi SSL Let's Encrypt): " EMAIL
        if [[ -z "$EMAIL" ]]; then
            warning_msg "Alamat email tidak boleh kosong."
        elif ! [[ "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            warning_msg "Format email tidak valid."
        else
            break
        fi
    done
    
    MAIN_UUID=$(cat /proc/sys/kernel/random/uuid)
    success_msg "UUID utama untuk admin akan dibuat: $MAIN_UUID"
    
    read -rp "Tekan [Enter] untuk memulai instalasi atau [Ctrl+C] untuk membatalkan..."
}

# Instalasi Xray-core
install_xray() {
    info_msg "Menginstal Xray-core..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version 1.8.4 
    if [ $? -ne 0 ]; then
        error_exit "Gagal menginstal Xray-core."
    fi
    systemctl enable xray &>/dev/null
    success_msg "Xray-core berhasil diinstal."
}

# Instalasi acme.sh dan penerbitan sertifikat SSL
setup_ssl() {
    info_msg "Mengkonfigurasi sertifikat SSL menggunakan acme.sh..."
    systemctl stop nginx &>/dev/null

    if [ ! -d "$HOME/.acme.sh" ]; then
        curl https://get.acme.sh | sh -s email="$EMAIL"
        if [ $? -ne 0 ]; then error_exit "Gagal menginstal acme.sh."; fi
        export PATH="$HOME/.acme.sh:$PATH" # Pastikan acme.sh ada di PATH untuk sesi ini
        "$HOME/.acme.sh/acme.sh" --upgrade --auto-upgrade 
    fi
    
    "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt
    
    info_msg "Menerbitkan sertifikat untuk domain: $DOMAIN (mungkin perlu beberapa saat)..."
    if "$HOME/.acme.sh/acme.sh" --issue -d "$DOMAIN" --standalone -k ec-256 --force; then
        success_msg "Sertifikat SSL berhasil diterbitkan (standalone)."
    else
        info_msg "Metode standalone gagal, mencoba dengan Nginx webroot..."
        mkdir -p /var/www/html/.well-known/acme-challenge
        chown -R www-data:www-data /var/www/html
        # Pastikan Nginx dikonfigurasi untuk melayani dari /var/www/html untuk challenge
        # Konfigurasi Nginx sementara untuk challenge HTTP jika perlu
        cat > "${NGINX_AVAILABLE_SITES}/default-ssl-challenge.conf" << EOF
server {
    listen 80;
    server_name ${DOMAIN};
    location /.well-known/acme-challenge/ {
        root /var/www/html/;
    }
    location / {
        return 404; # Atau redirect ke https jika sudah ada cert
    }
}
EOF
        if [ ! -L "${NGINX_ENABLED_SITES}/default-ssl-challenge.conf" ]; then
            ln -s "${NGINX_AVAILABLE_SITES}/default-ssl-challenge.conf" "${NGINX_ENABLED_SITES}/default-ssl-challenge.conf" &>/dev/null
        fi
        systemctl restart nginx # Restart nginx dengan config challenge

        if "$HOME/.acme.sh/acme.sh" --issue -d "$DOMAIN" --webroot /var/www/html/ -k ec-256 --force; then
             success_msg "Sertifikat SSL berhasil diterbitkan menggunakan Nginx webroot."
        else
            rm -f "${NGINX_ENABLED_SITES}/default-ssl-challenge.conf"
            rm -f "${NGINX_AVAILABLE_SITES}/default-ssl-challenge.conf"
            systemctl reload nginx &>/dev/null
            error_exit "Gagal menerbitkan sertifikat SSL. Pastikan domain Anda mengarah ke IP server ini dan port 80 (HTTP) dapat diakses dari luar."
        fi
        # Hapus config Nginx sementara untuk challenge
        rm -f "${NGINX_ENABLED_SITES}/default-ssl-challenge.conf"
        rm -f "${NGINX_AVAILABLE_SITES}/default-ssl-challenge.conf"
        systemctl reload nginx &>/dev/null
    fi

    mkdir -p "$CERT_DIR"
    if "$HOME/.acme.sh/acme.sh" --install-cert -d "$DOMAIN" --ecc \
        --key-file       "$CERT_DIR/private.key" \
        --fullchain-file "$CERT_DIR/fullchain.crt" \
        --reloadcmd     "systemctl restart xray; systemctl reload nginx"; then 
        success_msg "Sertifikat SSL berhasil diinstal ke $CERT_DIR."
    else
        error_exit "Gagal menginstal sertifikat SSL ke direktori Xray."
    fi
    
    chown -R nobody:nogroup "$CERT_DIR"
    chmod -R 600 "$CERT_DIR" 
}

# Konfigurasi Nginx
configure_nginx() {
    info_msg "Mengkonfigurasi Nginx sebagai reverse proxy..."
    cat > "${NGINX_AVAILABLE_SITES}/${DOMAIN}.conf" << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    # Untuk ACME challenge jika webroot digunakan saat perpanjangan
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate ${CERT_DIR}/fullchain.crt;
    ssl_certificate_key ${CERT_DIR}/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d; # Tingkatkan timeout sesi
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    # add_header Referrer-Policy "strict-origin-when-cross-origin";

    location ${VLESS_WS_PATH} {
        if (\$request_method != 'GET') { return 403; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10001; 
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    location ${VMESS_WS_PATH} {
        if (\$request_method != 'GET') { return 403; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10002; 
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    # Opsional: tambahkan halaman web statis sederhana di root
    location / {
        root /var/www/html; # Atau path lain ke website Anda
        index index.html index.htm;
        # try_files \$uri \$uri/ =404; # Jika Anda memiliki SPA
    }
}
EOF
    # Buat halaman index default jika tidak ada
    if [ ! -f /var/www/html/index.html ]; then
        mkdir -p /var/www/html
        echo "<!DOCTYPE html><html><head><title>Welcome to ${DOMAIN}</title></head><body><h1>Powered by Xray</h1><p>Your service is up and running.</p></body></html>" > /var/www/html/index.html
        chown -R www-data:www-data /var/www/html
    fi

    if [ -L "${NGINX_ENABLED_SITES}/${DOMAIN}.conf" ]; then
        rm "${NGINX_ENABLED_SITES}/${DOMAIN}.conf"
    fi
    ln -s "${NGINX_AVAILABLE_SITES}/${DOMAIN}.conf" "${NGINX_ENABLED_SITES}/${DOMAIN}.conf"
    # Hapus konfigurasi default jika ada dan aktif untuk menghindari konflik
    if [ -L "${NGINX_ENABLED_SITES}/default" ]; then
        rm "${NGINX_ENABLED_SITES}/default"
    fi

    if nginx -t; then
        systemctl restart nginx
        systemctl enable nginx &>/dev/null
        success_msg "Nginx berhasil dikonfigurasi dan direstart."
    else
        error_exit "Konfigurasi Nginx error. Periksa: ${NGINX_AVAILABLE_SITES}/${DOMAIN}.conf dan 'journalctl -u nginx'."
    fi
}

# Konfigurasi Xray
configure_xray() {
    info_msg "Mengkonfigurasi Xray..."
    mkdir -p /etc/xray
    cat > "$XRAY_CONFIG_FILE" << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "api": {
    "tag": "api",
    "services": ["HandlerService", "LoggerService", "StatsService"]
  },
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
      {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"}
    ]
  },
  "policy": {
    "levels": { "0": {"handshake": 4, "connIdle": 300, "uplinkOnly": 1, "downlinkOnly": 1, "bufferSize": 10240}},
    "system": {"statsInboundUplink": true, "statsInboundDownlink": true, "statsOutboundUplink": true, "statsOutboundDownlink": true}
  },
  "inbounds": [
    {
      "listen": "127.0.0.1", "port": 10001, "protocol": "vless",
      "settings": {"clients": [{"id": "${MAIN_UUID}", "level": 0, "email": "admin@${DOMAIN}"}], "decryption": "none"},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "${VLESS_WS_PATH}"}},
      "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}, "tag": "vless-in"
    },
    {
      "listen": "127.0.0.1", "port": 10002, "protocol": "vmess",
      "settings": {"clients": [{"id": "${MAIN_UUID}", "alterId": 0, "level": 0, "email": "admin@${DOMAIN}"}]},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "${VMESS_WS_PATH}"}},
      "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}, "tag": "vmess-in"
    },
    {
      "listen": "0.0.0.0", "port": 443, "protocol": "trojan",
      "settings": {
        "clients": [{"password": "${MAIN_UUID}", "level": 0, "email": "admin@${DOMAIN}"}],
        "fallbacks": [
             {"alpn": "http/1.1", "dest": 80}, // HTTP Nginx
             {"alpn": "h2", "dest": 80}       // HTTP/2 Nginx
        ]
      },
      "streamSettings": {
        "network": "tcp", "security": "tls",
        "tlsSettings": {
          "serverName": "${DOMAIN}", "alpn": ["h2", "http/1.1"],
          "certificates": [{"certificateFile": "${CERT_DIR}/fullchain.crt", "keyFile": "${CERT_DIR}/private.key"}]
        }
      },
      "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}, "tag": "trojan-in"
    },
    {"listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}, "tag": "api"}
  ],
  "outbounds": [
    {"protocol": "freedom", "settings": {}, "tag": "direct"},
    {"protocol": "blackhole", "settings": {}, "tag": "blocked"}
  ],
  "stats": {}, "reverse": {}
}
EOF
    mkdir -p /var/log/xray
    chown -R nobody:nogroup /var/log/xray

    if /usr/local/bin/xray run -test -config "$XRAY_CONFIG_FILE" &>/dev/null; then
        success_msg "Konfigurasi Xray valid."
        systemctl restart xray
        if systemctl is-active --quiet xray; then
            success_msg "Layanan Xray berhasil direstart dan aktif."
        else
            error_exit "Layanan Xray gagal direstart. Cek 'journalctl -u xray' atau '$XRAY_CONFIG_FILE'."
        fi
    else
        error_exit "Konfigurasi Xray tidak valid. Silakan periksa '$XRAY_CONFIG_FILE'."
    fi
}

# Konfigurasi firewall
configure_firewall() {
    info_msg "Mengkonfigurasi firewall (UFW)..."
    if command -v ufw &> /dev/null; then
        ufw allow 22/tcp    # SSH
        ufw allow 80/tcp    # HTTP 
        ufw allow 443/tcp   # HTTPS (Nginx) dan Trojan (Xray)
        # ufw allow 443/udp   # Untuk QUIC jika diaktifkan (tidak default di config ini)
        ufw disable &>/dev/null 
        echo "y" | ufw enable &>/dev/null
        if ufw status | grep -qw active; then
            success_msg "Firewall UFW berhasil dikonfigurasi dan diaktifkan."
        else
            warning_msg "Gagal mengaktifkan UFW. Silakan periksa secara manual."
        fi
    else
        warning_msg "UFW tidak terinstal. Pertimbangkan untuk menginstal dan mengkonfigurasi firewall."
    fi
}

# Menyimpan informasi instalasi
save_install_info() {
    info_msg "Menyimpan informasi instalasi ke $INSTALL_INFO_FILE..."
    # Pastikan direktori ada
    mkdir -p "$(dirname "$INSTALL_INFO_FILE")"
    cat > "$INSTALL_INFO_FILE" << EOF
DOMAIN=${DOMAIN}
EMAIL=${EMAIL}
MAIN_UUID=${MAIN_UUID}
VLESS_WS_PATH=${VLESS_WS_PATH}
VMESS_WS_PATH=${VMESS_WS_PATH}
CERT_DIR=${CERT_DIR}
XRAY_CONFIG_FILE=${XRAY_CONFIG_FILE}
NGINX_CONFIG_FILE=${NGINX_AVAILABLE_SITES}/${DOMAIN}.conf
USER_MANAGEMENT_FILE=${USER_MANAGEMENT_FILE}
INSTALL_DATE=$(date)
EOF
    success_msg "Informasi instalasi disimpan."
}

# Menampilkan informasi koneksi untuk pengguna tertentu
display_specific_user_connection_info() {
    local client_uuid="$1"
    local client_name="$2"
    local client_type="$3" # vless, vmess, trojan
    local client_email # Opsional

    # Muat DOMAIN, VLESS_WS_PATH, VMESS_WS_PATH dari info instalasi
    # shellcheck source=/dev/null
    source "$INSTALL_INFO_FILE"

    echo "-------------------------------------------------------------------"
    info_msg "Detail Koneksi untuk Akun: ${client_name} (Tipe: ${client_type})"
    echo "UUID/Password: ${client_uuid}"
    echo "-------------------------------------------------------------------"

    case "$client_type" in
        vless)
            local link="vless://${client_uuid}@${DOMAIN}:443?type=ws&security=tls&path=${VLESS_WS_PATH}&host=${DOMAIN}&sni=${DOMAIN}#${client_name// /_}-VLESS"
            echo "Protokol: VLESS (WebSocket + TLS)"
            echo "Alamat (Address):   ${DOMAIN}"
            echo "Port:               443"
            echo "ID (UUID):          ${client_uuid}"
            echo "Path:               ${VLESS_WS_PATH}"
            echo "SNI/Host:           ${DOMAIN}"
            echo "Link: ${link}"
            qrencode -t ANSIUTF8 "${link}"
            ;;
        vmess)
            local vmess_json
            vmess_json=$(jq -n \
                --arg ps "${client_name// /_}-VMESS" \
                --arg add "$DOMAIN" \
                --arg port "443" \
                --arg id "$client_uuid" \
                --arg aid "0" \
                --arg net "ws" \
                --arg type "none" \
                --arg host "$DOMAIN" \
                --arg path "$VMESS_WS_PATH" \
                --arg tls "tls" \
                --arg sni "$DOMAIN" \
                '{v: "2", ps: $ps, add: $add, port: $port, id: $id, aid: $aid, net: $net, type: $type, host: $host, path: $path, tls: $tls, sni: $sni}')
            local link="vmess://$(echo -n "$vmess_json" | base64 -w 0)"
            echo "Protokol: VMESS (WebSocket + TLS)"
            echo "Alamat (Address):   ${DOMAIN}"
            echo "Port:               443"
            echo "ID (UUID):          ${client_uuid}"
            echo "AlterID:            0"
            echo "Path:               ${VMESS_WS_PATH}"
            echo "SNI/Host:           ${DOMAIN}"
            echo "Link: ${link}"
            qrencode -t ANSIUTF8 "${link}"
            ;;
        trojan)
            local link="trojan://${client_uuid}@${DOMAIN}:443?sni=${DOMAIN}&peer=${DOMAIN}#${client_name// /_}-Trojan"
            echo "Protokol: Trojan (TCP + TLS)"
            echo "Alamat (Address):   ${DOMAIN}"
            echo "Port:               443"
            echo "Password:           ${client_uuid}"
            echo "SNI:                ${DOMAIN}"
            echo "Link: ${link}"
            qrencode -t ANSIUTF8 "${link}"
            ;;
        *)
            warning_msg "Tipe akun tidak dikenal: $client_type"
            ;;
    esac
    echo "-------------------------------------------------------------------"
}


# Menampilkan informasi koneksi untuk akun admin/utama
display_main_connection_info() {
    clear
    load_install_info || return 1
    success_msg "==================================================================="
    success_msg "         Informasi Akun Admin/Utama"
    success_msg "==================================================================="
    echo ""
    info_msg "Domain Anda: ${DOMAIN}"
    info_msg "UUID Utama / Password Trojan Utama: ${MAIN_UUID}"
    echo ""
    display_specific_user_connection_info "$MAIN_UUID" "Admin-Utama" "vless"
    display_specific_user_connection_info "$MAIN_UUID" "Admin-Utama" "vmess"
    display_specific_user_connection_info "$MAIN_UUID" "Admin-Utama" "trojan"
    echo "==================================================================="
    warning_msg "Informasi instalasi utama disimpan di: ${INSTALL_INFO_FILE}"
    warning_msg "Informasi akun klien disimpan di: ${USER_MANAGEMENT_FILE}"
}

# Fungsi instalasi utama
install_vpn() {
    get_user_input_for_install
    stop_conflicting_services
    install_xray
    setup_ssl
    configure_nginx 
    configure_xray 
    configure_firewall
    save_install_info
    # Buat file manajemen pengguna jika belum ada
    if [ ! -f "$USER_MANAGEMENT_FILE" ]; then
        touch "$USER_MANAGEMENT_FILE"
        # Tambahkan header CSV
        echo "uuid,account_name,type,creation_date_unix,expiry_date_unix,client_email" > "$USER_MANAGEMENT_FILE"
        success_msg "File manajemen pengguna dibuat: $USER_MANAGEMENT_FILE"
    fi
    display_main_connection_info

    read -rp "Apakah Anda ingin mengatur cron job untuk pemeriksaan kedaluwarsa akun otomatis? (y/n): " setup_cron
    if [[ "$setup_cron" =~ ^[Yy]$ ]]; then
        setup_expiry_cron_job
    fi

    success_msg "Instalasi selesai. Disarankan untuk mereboot server Anda."
    read -rp "Apakah Anda ingin mereboot server sekarang? (y/n): " reboot_choice
    if [[ "$reboot_choice" =~ ^[Yy]$ ]]; then
        info_msg "Mereboot server..."
        reboot
    fi
}

# Fungsi untuk memuat info instalasi
load_install_info() {
    if [ -f "$INSTALL_INFO_FILE" ]; then
        # shellcheck source=/dev/null
        source "$INSTALL_INFO_FILE"
        return 0
    else
        # error_exit "File informasi instalasi ($INSTALL_INFO_FILE) tidak ditemukan. Apakah VPN sudah terinstal dengan benar?"
        return 1 # Jangan keluar, mungkin user mau instal
    fi
}

# Membuat akun klien baru
create_client_account() {
    check_root
    load_install_info || { error_exit "Info instalasi tidak ditemukan. Jalankan instalasi dulu."; return 1; }

    local account_name client_type duration_days client_email
    while true; do
        read -rp "Masukkan nama untuk akun klien ini (misal: user_andi): " account_name
        if [[ -z "$account_name" ]]; then
            warning_msg "Nama akun tidak boleh kosong."
        elif grep -q -E "^[^,]+,${account_name}," "$USER_MANAGEMENT_FILE"; then # Cek apakah nama akun sudah ada
            warning_msg "Nama akun '$account_name' sudah digunakan. Pilih nama lain."
        else
            break
        fi
    done
    
    echo "Pilih jenis akun klien:"
    echo "1. VLESS (WebSocket)"
    echo "2. VMESS (WebSocket)"
    echo "3. Trojan (TCP)"
    read -rp "Jenis akun (1-3): " type_choice
    case "$type_choice" in
        1) client_type="vless" ;;
        2) client_type="vmess" ;;
        3) client_type="trojan" ;;
        *) error_exit "Pilihan tidak valid." ;;
    esac

    while true; do
        read -rp "Masukkan durasi masa aktif akun (dalam hari, misal: 7, 30, 365): " duration_days
        if [[ "$duration_days" =~ ^[0-9]+$ && "$duration_days" -gt 0 ]]; then
            break
        else
            warning_msg "Masukkan angka positif untuk durasi."
        fi
    done
    
    read -rp "Masukkan email untuk klien ini (opsional, untuk referensi): " client_email
    [[ -z "$client_email" ]] && client_email="-" # Default jika kosong

    local new_uuid client_json_path client_jq_filter temp_config
    new_uuid=$(cat /proc/sys/kernel/random/uuid)
    temp_config=$(mktemp)

    info_msg "Menambahkan klien '${account_name}' tipe '${client_type}' dengan UUID: ${new_uuid}..."

    # Buat JSON untuk klien baru
    local client_obj_json
    case "$client_type" in
        vless)
            client_obj_json=$(jq -n --arg id "$new_uuid" --arg email "$client_email" \
                '{"id": $id, "level": 0, "email": $email}')
            client_jq_filter='.inbounds[] | select(.tag == "vless-in") | .settings.clients += [$client_obj]'
            ;;
        vmess)
            client_obj_json=$(jq -n --arg id "$new_uuid" --arg aid "0" --arg email "$client_email" \
                '{"id": $id, "alterId": $aid | tonumber, "level": 0, "email": $email}')
            client_jq_filter='.inbounds[] | select(.tag == "vmess-in") | .settings.clients += [$client_obj]'
            ;;
        trojan)
            client_obj_json=$(jq -n --arg password "$new_uuid" --arg email "$client_email" \
                '{"password": $password, "level": 0, "email": $email}')
            client_jq_filter='.inbounds[] | select(.tag == "trojan-in") | .settings.clients += [$client_obj]'
            ;;
    esac
    
    # Update config.json menggunakan jq
    if jq --argjson client_obj "$client_obj_json" "$client_jq_filter" "$XRAY_CONFIG_FILE" > "$temp_config"; then
        mv "$temp_config" "$XRAY_CONFIG_FILE"
        success_msg "Klien berhasil ditambahkan ke konfigurasi Xray."

        local creation_date_unix expiry_date_unix
        creation_date_unix=$(date +%s)
        expiry_date_unix=$(date -d "+${duration_days} days" +%s)
        
        # Simpan info klien ke file manajemen
        echo "${new_uuid},${account_name},${client_type},${creation_date_unix},${expiry_date_unix},${client_email}" >> "$USER_MANAGEMENT_FILE"
        success_msg "Informasi klien disimpan di $USER_MANAGEMENT_FILE."
        
        systemctl restart xray
        success_msg "Layanan Xray direstart."
        
        display_specific_user_connection_info "$new_uuid" "$account_name" "$client_type"
    else
        rm -f "$temp_config"
        error_exit "Gagal memodifikasi konfigurasi Xray dengan jq. Perubahan dibatalkan."
    fi
}

# Memeriksa dan menghapus akun yang sudah kedaluwarsa
check_expired_accounts() {
    # Fungsi ini sebaiknya dijalankan oleh root (misalnya via cron)
    # Tidak perlu check_root() di sini jika dipanggil oleh root dari cron
    if [ ! -f "$INSTALL_INFO_FILE" ]; then
        echo "$(date): Error - File info instalasi tidak ditemukan. Tidak dapat memeriksa akun kedaluwarsa." >> /var/log/xray_expiry.log
        return 1
    fi
    # shellcheck source=/dev/null
    source "$INSTALL_INFO_FILE" # Muat variabel seperti XRAY_CONFIG_FILE

    if [ ! -f "$USER_MANAGEMENT_FILE" ]; then
        echo "$(date): Info - File manajemen pengguna ($USER_MANAGEMENT_FILE) tidak ditemukan. Tidak ada akun untuk diperiksa." >> /var/log/xray_expiry.log
        return 0
    fi

    local current_date_unix temp_user_file config_changed=false
    current_date_unix=$(date +%s)
    temp_user_file=$(mktemp)
    
    # Salin header ke file temp
    head -n 1 "$USER_MANAGEMENT_FILE" > "$temp_user_file"

    echo "$(date): Memulai pemeriksaan akun kedaluwarsa..." >> /var/log/xray_expiry.log

    # Baca file manajemen pengguna, lewati header
    tail -n +2 "$USER_MANAGEMENT_FILE" | while IFS=, read -r uuid name type creation_ts expiry_ts email_ref; do
        if [[ -z "$uuid" || -z "$expiry_ts" ]]; then # Lewati baris yang tidak valid
            echo "$(date): Warning - Baris tidak valid di $USER_MANAGEMENT_FILE: $uuid,$name,$type,$creation_ts,$expiry_ts,$email_ref" >> /var/log/xray_expiry.log
            continue
        fi

        if [[ "$current_date_unix" -gt "$expiry_ts" ]]; then
            info_msg "Akun '${name}' (UUID: ${uuid}, Tipe: ${type}) telah kedaluwarsa. Menghapus..."
            echo "$(date): Akun '${name}' (UUID: ${uuid}, Tipe: ${type}) telah kedaluwarsa. Menghapus..." >> /var/log/xray_expiry.log
            
            local temp_config_jq=$(mktemp)
            local jq_delete_filter client_id_field

            case "$type" in
                vless|vmess) client_id_field="id" ;;
                trojan) client_id_field="password" ;; # Di config trojan, uuid adalah password
                *)
                    warning_msg "Tipe akun tidak dikenal untuk penghapusan: ${type} pada akun ${name}"
                    echo "$(date): Error - Tipe akun tidak dikenal '${type}' untuk UUID ${uuid}" >> /var/log/xray_expiry.log
                    # Salin kembali ke file temp jika tipe tidak dikenal agar tidak hilang
                    echo "${uuid},${name},${type},${creation_ts},${expiry_ts},${email_ref}" >> "$temp_user_file"
                    continue 
                    ;;
            esac
            
            # Filter untuk menghapus klien dari array `clients`
            jq_delete_filter="(.inbounds[] | select(.tag == \"${type}-in\") | .settings.clients) |= map(select(.${client_id_field} != \"${uuid}\"))"

            if jq "$jq_delete_filter" "$XRAY_CONFIG_FILE" > "$temp_config_jq"; then
                mv "$temp_config_jq" "$XRAY_CONFIG_FILE"
                success_msg "Akun '${name}' berhasil dihapus dari konfigurasi Xray."
                echo "$(date): Akun '${name}' berhasil dihapus dari config Xray." >> /var/log/xray_expiry.log
                config_changed=true
            else
                rm -f "$temp_config_jq"
                error_msg "Gagal menghapus akun '${name}' dari konfigurasi Xray. Jaga entri di file pengguna."
                echo "$(date): Error - Gagal menghapus UUID ${uuid} dari config Xray. Jaga entri di file pengguna." >> /var/log/xray_expiry.log
                # Jika gagal hapus dari config, jangan hapus dari file user
                echo "${uuid},${name},${type},${creation_ts},${expiry_ts},${email_ref}" >> "$temp_user_file"
            fi
        else
            # Akun belum kedaluwarsa, salin kembali ke file temp
            echo "${uuid},${name},${type},${creation_ts},${expiry_ts},${email_ref}" >> "$temp_user_file"
        fi
    done
    
    mv "$temp_user_file" "$USER_MANAGEMENT_FILE"
    
    if [[ "$config_changed" == true ]]; then
        info_msg "Beberapa akun kedaluwarsa telah dihapus. Merestart Xray..."
        systemctl restart xray
        echo "$(date): Layanan Xray direstart setelah penghapusan akun kedaluwarsa." >> /var/log/xray_expiry.log
    else
        info_msg "Tidak ada akun kedaluwarsa yang ditemukan atau tidak ada perubahan konfigurasi."
        echo "$(date): Tidak ada akun kedaluwarsa atau tidak ada perubahan config." >> /var/log/xray_expiry.log
    fi
     echo "$(date): Pemeriksaan akun kedaluwarsa selesai." >> /var/log/xray_expiry.log
}

# Pengaturan cron job untuk pemeriksaan kedaluwarsa
setup_expiry_cron_job() {
    check_root
    load_install_info || { error_exit "Info instalasi tidak ditemukan."; return 1; }

    local cron_file="/etc/cron.d/xray_account_expiry_check"
    local cron_log_file="/var/log/xray_expiry.log" # Log khusus untuk cron job
    
    # Path ke skrip ini harus absolut dalam cron job
    # SCRIPT_ABSOLUTE_PATH sudah diisi di awal skrip
    if [[ -z "$SCRIPT_ABSOLUTE_PATH" ]]; then
        error_exit "Tidak dapat menentukan path absolut skrip. Tidak dapat membuat cron job."
    fi

    # Buat file cron job
    cat > "$cron_file" << EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# Jalankan setiap hari pukul 02:00
0 2 * * * root $SCRIPT_ABSOLUTE_PATH checkexpired >> $cron_log_file 2>&1
EOF
    chmod 0644 "$cron_file" # Atur izin yang benar
    
    # Buat file log jika belum ada dan atur izin agar root bisa menulis
    touch "$cron_log_file"
    chown root:root "$cron_log_file"
    chmod 0640 "$cron_log_file" # Hanya root yang bisa baca/tulis

    if systemctl list-timers | grep -q 'cron.service'; then # Cek apakah cron service ada
        systemctl restart cron # Atau reload, tergantung distro
        success_msg "Cron job untuk pemeriksaan kedaluwarsa akun telah diatur."
        info_msg "Akan berjalan setiap hari pukul 02:00. Log di $cron_log_file"
    elif systemctl list-timers | grep -q 'crond.service'; then
        systemctl restart crond
        success_msg "Cron job untuk pemeriksaan kedaluwarsa akun telah diatur."
        info_msg "Akan berjalan setiap hari pukul 02:00. Log di $cron_log_file"
    else
        warning_msg "Layanan cron tidak terdeteksi aktif. Cron job mungkin tidak berjalan. Silakan periksa status layanan cron Anda."
    fi
}

# Menampilkan daftar akun klien
list_client_accounts() {
    check_root
    load_install_info || { error_exit "Info instalasi tidak ditemukan."; return 1; }

    if [ ! -s "$USER_MANAGEMENT_FILE" ] || ! tail -n +2 "$USER_MANAGEMENT_FILE" | grep -q '.'; then
        info_msg "Tidak ada akun klien yang ditemukan di $USER_MANAGEMENT_FILE."
        return
    fi

    info_msg "Daftar Akun Klien VPN:"
    echo "-----------------------------------------------------------------------------------------------------------------"
    printf "%-38s | %-20s | %-10s | %-25s | %-25s\n" "UUID" "Nama Akun" "Tipe" "Tanggal Dibuat" "Tanggal Kedaluwarsa"
    echo "-----------------------------------------------------------------------------------------------------------------"
    
    local current_ts
    current_ts=$(date +%s)

    tail -n +2 "$USER_MANAGEMENT_FILE" | while IFS=, read -r uuid name type creation_ts expiry_ts email_ref; do
        if [[ -z "$uuid" ]]; then continue; fi # Lewati baris kosong potensial di akhir
        local creation_date expiry_date status_color
        creation_date=$(date -d "@${creation_ts}" +"%Y-%m-%d %H:%M:%S")
        expiry_date=$(date -d "@${expiry_ts}" +"%Y-%m-%d %H:%M:%S")
        
        if [[ "$current_ts" -gt "$expiry_ts" ]]; then
            status_color="${RED}" # Merah untuk kedaluwarsa
        else
            status_color="${GREEN}" # Hijau untuk aktif
        fi
        printf "${status_color}%-38s${NC} | %-20s | %-10s | %-25s | ${status_color}%-25s${NC}\n" "$uuid" "$name" "$type" "$creation_date" "$expiry_date"
    done
    echo "-----------------------------------------------------------------------------------------------------------------"
}

# Menghapus akun klien secara manual
delete_client_account_manual() {
    check_root
    load_install_info || { error_exit "Info instalasi tidak ditemukan."; return 1; }
    
    list_client_accounts
    if [ ! -s "$USER_MANAGEMENT_FILE" ] || ! tail -n +2 "$USER_MANAGEMENT_FILE" | grep -q '.'; then
        return # list_client_accounts sudah menampilkan pesan
    fi

    read -rp "Masukkan UUID atau Nama Akun yang ingin dihapus: " identifier
    if [[ -z "$identifier" ]]; then
        warning_msg "Tidak ada input. Pembatalan."
        return
    fi

    local found_line temp_user_file account_to_delete_uuid account_to_delete_type account_to_delete_name
    temp_user_file=$(mktemp)
    
    # Salin header
    head -n 1 "$USER_MANAGEMENT_FILE" > "$temp_user_file"
    
    # Cari berdasarkan UUID atau Nama Akun
    found_line=$(tail -n +2 "$USER_MANAGEMENT_FILE" | grep -E "^${identifier},|,${identifier},")

    if [[ -z "$found_line" ]]; then
        error_exit "Akun dengan UUID/Nama '${identifier}' tidak ditemukan."
        rm -f "$temp_user_file"
        return
    fi
    
    # Jika ada lebih dari satu hasil (misal nama akun tidak unik, meskipun skrip mencoba mencegahnya)
    if [[ $(echo "$found_line" | wc -l) -gt 1 ]]; then
        warning_msg "Ditemukan beberapa akun yang cocok. Harap gunakan UUID yang unik."
        echo "$found_line"
        rm -f "$temp_user_file"
        return
    fi

    IFS=, read -r account_to_delete_uuid account_to_delete_name account_to_delete_type _ _ _ <<< "$found_line"

    read -rp "Anda yakin ingin menghapus akun '${account_to_delete_name}' (UUID: ${account_to_delete_uuid})? (y/n): " confirm_delete
    if [[ ! "$confirm_delete" =~ ^[Yy]$ ]]; then
        info_msg "Penghapusan dibatalkan."
        rm -f "$temp_user_file"
        return
    fi

    local config_changed_manual=false temp_config_jq_manual client_id_field_manual jq_delete_filter_manual

    # Hapus dari konfigurasi Xray
    temp_config_jq_manual=$(mktemp)
    case "$account_to_delete_type" in
        vless|vmess) client_id_field_manual="id" ;;
        trojan) client_id_field_manual="password" ;;
        *) 
            warning_msg "Tipe akun tidak dikenal: ${account_to_delete_type}."
            rm -f "$temp_user_file" "$temp_config_jq_manual"
            return 
            ;;
    esac
    jq_delete_filter_manual="(.inbounds[] | select(.tag == \"${account_to_delete_type}-in\") | .settings.clients) |= map(select(.${client_id_field_manual} != \"${account_to_delete_uuid}\"))"

    if jq "$jq_delete_filter_manual" "$XRAY_CONFIG_FILE" > "$temp_config_jq_manual"; then
        mv "$temp_config_jq_manual" "$XRAY_CONFIG_FILE"
        success_msg "Akun '${account_to_delete_name}' berhasil dihapus dari konfigurasi Xray."
        config_changed_manual=true
    else
        rm -f "$temp_config_jq_manual"
        error_msg "Gagal menghapus akun '${account_to_delete_name}' dari konfigurasi Xray."
    fi

    # Hapus dari file manajemen pengguna
    # Salin semua baris KECUALI yang cocok dengan UUID yang akan dihapus
    tail -n +2 "$USER_MANAGEMENT_FILE" | grep -v "^${account_to_delete_uuid}," >> "$temp_user_file"
    mv "$temp_user_file" "$USER_MANAGEMENT_FILE"
    success_msg "Akun '${account_to_delete_name}' berhasil dihapus dari file manajemen pengguna."

    if [[ "$config_changed_manual" == true ]]; then
        systemctl restart xray
        success_msg "Layanan Xray direstart."
    fi
}


# Fungsi untuk menampilkan konfigurasi akun admin/utama
view_main_config() {
    check_root
    load_install_info || { error_exit "Info instalasi tidak ditemukan. Jalankan instalasi dulu."; return 1; }
    display_main_connection_info 
}

# Fungsi untuk mengelola layanan Xray
manage_xray_service() {
    check_root
    echo "Pilih tindakan untuk layanan Xray:"
    echo "1. Status"
    echo "2. Start"
    echo "3. Stop"
    echo "4. Restart"
    echo "5. Lihat Log Xray (100 baris terakhir)"
    echo "6. Lihat Log Pemeriksaan Kedaluwarsa (100 baris terakhir)"
    read -rp "Masukkan pilihan (1-6): " xray_action

    case "$xray_action" in
        1) systemctl status xray ;;
        2) systemctl start xray && success_msg "Xray dimulai." ;;
        3) systemctl stop xray && success_msg "Xray dihentikan." ;;
        4) systemctl restart xray && success_msg "Xray direstart." ;;
        5) journalctl -u xray -n 100 --no-pager ;;
        6) 
            if [ -f /var/log/xray_expiry.log ]; then
                tail -n 100 /var/log/xray_expiry.log
            else
                info_msg "File log pemeriksaan kedaluwarsa (/var/log/xray_expiry.log) tidak ditemukan."
            fi
            ;;
        *) warning_msg "Pilihan tidak valid." ;;
    esac
}

# Fungsi untuk memperbarui sertifikat SSL secara manual
renew_ssl_manual() {
    check_root
    load_install_info || { error_exit "Info instalasi tidak ditemukan."; return 1; }
    info_msg "Mencoba memperbarui sertifikat SSL untuk domain $DOMAIN..."
    
    # Pastikan path acme.sh benar
    local acme_cmd="$HOME/.acme.sh/acme.sh"
    if [ ! -f "$acme_cmd" ]; then
        acme_cmd="acme.sh" # Coba jika sudah ada di PATH global (misal diinstal sebagai root)
        if ! command -v $acme_cmd &> /dev/null; then
             error_exit "Perintah acme.sh tidak ditemukan. Pastikan sudah terinstal dengan benar."
        fi
    fi
    
    # Hentikan Nginx sementara untuk mode standalone jika diperlukan, atau pastikan webroot dapat diakses
    systemctl stop nginx
    "$acme_cmd" --renew -d "$DOMAIN" --ecc --force
    local renew_status=$?
    # Restart Nginx dan Xray setelah selesai
    systemctl start nginx # Pastikan Nginx selalu dijalankan kembali
    if systemctl is-active --quiet xray; then # Hanya restart Xray jika aktif
        systemctl restart xray 
    fi

    if [ $renew_status -eq 0 ]; then
        success_msg "Sertifikat SSL berhasil diperbarui (atau belum perlu diperbarui)."
    else
        error_exit "Gagal memperbarui sertifikat SSL. Cek log acme.sh di $HOME/.acme.sh/"
    fi
}

# Fungsi uninstall
uninstall_vpn() {
    check_root
    warning_msg "PERINGATAN: Ini akan menghapus Xray, Nginx (konfigurasi domain), sertifikat SSL, dan semua file terkait (termasuk data pengguna)!"
    read -rp "Apakah Anda yakin ingin melanjutkan uninstall? (ketik 'yes' untuk konfirmasi): " confirmation
    if [[ "$confirmation" != "yes" ]]; then
        info_msg "Uninstall dibatalkan."
        return
    fi

    info_msg "Menghentikan layanan..."
    systemctl stop xray &>/dev/null
    systemctl disable xray &>/dev/null
    systemctl stop nginx &>/dev/null
    
    info_msg "Menghapus cron job pemeriksaan kedaluwarsa..."
    rm -f "/etc/cron.d/xray_account_expiry_check"
    systemctl restart cron &>/dev/null || systemctl restart crond &>/dev/null

    info_msg "Menghapus Xray-core..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge &>/dev/null
    # Hapus sisa file Xray secara manual jika perlu
    rm -rf /usr/local/etc/xray 
    rm -rf /var/log/xray
    rm -f /etc/systemd/system/xray.service
    rm -f /etc/systemd/system/xray@.service
    systemctl daemon-reload

    info_msg "Menghapus konfigurasi Nginx untuk domain..."
    local domain_to_remove # Akan diisi dari install_info jika ada
    if [ -f "$INSTALL_INFO_FILE" ]; then
        # shellcheck source=/dev/null
        source "$INSTALL_INFO_FILE"
        domain_to_remove="$DOMAIN" # Gunakan DOMAIN dari file info
        if [ -n "$NGINX_CONFIG_FILE" ] && [ -f "$NGINX_CONFIG_FILE" ]; then
             rm "$NGINX_CONFIG_FILE"
        elif [ -n "$domain_to_remove" ] && [ -f "${NGINX_AVAILABLE_SITES}/${domain_to_remove}.conf" ]; then
             rm "${NGINX_AVAILABLE_SITES}/${domain_to_remove}.conf"
        fi
        if [ -n "$domain_to_remove" ] && [ -L "${NGINX_ENABLED_SITES}/${domain_to_remove}.conf" ]; then 
             rm "${NGINX_ENABLED_SITES}/${domain_to_remove}.conf"
        fi
    else 
        warning_msg "Tidak dapat memuat info domain dari $INSTALL_INFO_FILE. Penghapusan config Nginx mungkin tidak lengkap."
    fi
    systemctl reload nginx &>/dev/null

    info_msg "Menghapus sertifikat SSL dan acme.sh..."
    if [ -n "$domain_to_remove" ] && [ -d "$HOME/.acme.sh" ]; then
        "$HOME/.acme.sh/acme.sh" --remove -d "$domain_to_remove" --ecc &>/dev/null
    fi
    rm -rf "$HOME/.acme.sh"
    rm -rf "$CERT_DIR" 

    info_msg "Menghapus file data dan informasi..."
    rm -f "$INSTALL_INFO_FILE"
    rm -f "$USER_MANAGEMENT_FILE"
    rm -f "/var/log/xray_expiry.log"

    success_msg "Proses uninstall selesai."
}

# Menu Utama
main_menu() {
    clear
    echo "========================================================"
    echo "     SKRIP MANAJEMEN VPN XRAY (Ubuntu 24.04)"
    echo "========================================================"
    echo "Pilih Opsi:"
    echo "--------------------------------------------------------"
    if ! load_install_info || [ ! -f "$XRAY_CONFIG_FILE" ]; then
        echo -e "${GREEN} 1. Instal VPN Xray (Trojan, VLESS, VMESS)${NC}"
    else
        echo -e "${YELLOW} 1. Reinstal VPN Xray (Data lama akan hilang!)${NC}"
        echo "--------------------------------------------------------"
        echo -e "${BLUE}--- Manajemen Akun Klien ---${NC}"
        echo " 2. Buat Akun Klien VPN Baru"
        echo " 3. Daftar Akun Klien & Status Kedaluwarsa"
        echo " 4. Hapus Akun Klien (Manual)"
        echo "--------------------------------------------------------"
        echo -e "${BLUE}--- Utilitas & Info ---${NC}"
        echo " 5. Lihat Konfigurasi Akun Admin/Utama"
        echo " 6. Kelola Layanan Xray & Lihat Log"
        echo " 7. Perbarui Sertifikat SSL (Manual)"
        echo " 8. Atur/Perbarui Cron Job Pemeriksaan Kedaluwarsa"
        echo " 9. Jalankan Pemeriksaan Kedaluwarsa Akun Sekarang"
        echo "--------------------------------------------------------"
        echo -e "${RED}10. Uninstall VPN Xray${NC}"
    fi
    echo "--------------------------------------------------------"
    echo " 0. Keluar"
    echo "========================================================"
    read -rp "Masukkan pilihan Anda: " choice

    case "$choice" in
        1) install_vpn ;;
        2) if load_install_info && [ -f "$XRAY_CONFIG_FILE" ]; then create_client_account; else info_msg "Silakan instal VPN terlebih dahulu."; fi ;;
        3) if load_install_info && [ -f "$XRAY_CONFIG_FILE" ]; then list_client_accounts; else info_msg "Silakan instal VPN terlebih dahulu."; fi ;;
        4) if load_install_info && [ -f "$XRAY_CONFIG_FILE" ]; then delete_client_account_manual; else info_msg "Silakan instal VPN terlebih dahulu."; fi ;;
        5) if load_install_info && [ -f "$XRAY_CONFIG_FILE" ]; then view_main_config; else info_msg "Silakan instal VPN terlebih dahulu."; fi ;;
        6) if load_install_info && [ -f "$XRAY_CONFIG_FILE" ]; then manage_xray_service; else info_msg "Silakan instal VPN terlebih dahulu."; fi ;;
        7) if load_install_info && [ -f "$XRAY_CONFIG_FILE" ]; then renew_ssl_manual; else info_msg "Silakan instal VPN terlebih dahulu."; fi ;;
        8) if load_install_info && [ -f "$XRAY_CONFIG_FILE" ]; then setup_expiry_cron_job; else info_msg "Silakan instal VPN terlebih dahulu."; fi ;;
        9) if load_install_info && [ -f "$XRAY_CONFIG_FILE" ]; then check_expired_accounts; else info_msg "Silakan instal VPN terlebih dahulu."; fi ;;
        10) if load_install_info || [ -d "/usr/local/etc/xray" ]; then uninstall_vpn; else info_msg "Tidak ada instalasi VPN yang terdeteksi untuk di-uninstall."; fi ;; # Cek direktori xray juga
        0) exit 0 ;;
        *) error_exit "Pilihan tidak valid." ;;
    esac
    echo ""
    read -rp "Tekan [Enter] untuk kembali ke menu utama..."
    main_menu
}

# --- MAIN EXECUTION ---
get_script_path # Dapatkan path absolut skrip di awal

if [ "$#" -eq 0 ]; then
    check_root 
    main_menu
else
    # Argumen command line (untuk cron atau pemanggilan langsung fungsi tertentu)
    case "$1" in
        install) check_root; install_vpn ;;
        # adduser) check_root; create_client_account ;; # Mungkin lebih baik via menu
        checkexpired) check_root; check_expired_accounts ;; # Panggil ini dari cron
        uninstall) check_root; uninstall_vpn ;;
        *) 
            echo "Penggunaan non-interaktif:"
            echo "  sudo $SCRIPT_ABSOLUTE_PATH install"
            echo "  sudo $SCRIPT_ABSOLUTE_PATH checkexpired  (untuk cron)"
            echo "  sudo $SCRIPT_ABSOLUTE_PATH uninstall"
            ;;
    esac
fi

exit 0
