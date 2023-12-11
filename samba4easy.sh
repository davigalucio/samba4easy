#!/bin/sh
clear
echo
echo "Carregando as variavéis do ambiente de Domínio"
echo "-------------------------------------------------"
dc_domain=SKY.NET
dc_domain_realm=$(echo $dc_domain | sed -e 's/\(.*\)/\L\1/')
domain=$(echo $dc_domain | cut -d '.' -f 1)
pass='Passw0rd$2'
gateway=192.168.0.1
sleep 2
echo "Dominio OK!"

echo
echo "Coletando Dados do IP Atual"
echo "-------------------------------------------------"
ip4=$(hostname -I | cut -d '.' -f 4 | cut -d ' ' -f 1)
ip3=$(hostname -I | cut -d '.' -f 3 | cut -d ' ' -f 1)
ip2=$(hostname -I | cut -d '.' -f 2 | cut -d ' ' -f 1)
ip1=$(hostname -I | cut -d '.' -f 1 | cut -d ' ' -f 1)
sleep 2
echo "IP OK!"

echo
echo "Interface da placa de rede"
echo "-------------------------------------------------"
nic=$(ip -4 a | grep "$ip1" | grep -o '[^ ]*$')
sleep 2
echo "Interface Ok!"

echo
echo "Hostname do Servidor"
echo "-------------------------------------------------"
hostname=$(echo $(hostname).$dc_domain)
hostname=$(echo $hostname | sed -e 's/\(.*\)/\L\1/')
hostnamectl set-hostname $hostname
HOSTNAME=$(echo $hostname | cut -d '.' -f 1 )
sleep 2
echo "Hostname OK!"

echo
echo "Definindo IPv4 como prioridade"
echo "-------------------------------------------------"
echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
sleep 2
echo "OK!"

echo
echo "Resumo das informações coletadas"
echo "-------------------------------------------------"
echo "Dominio FQDN: $dc_domain"
echo "Dominio Realm: $dc_domain_realm"
echo "Dominio: $domain"
echo "Senha: $pass"
echo "Interface: $nic"
echo "IP: $ip1.$ip2.$ip3.$ip4"
echo "Gateway: $gateway"
echo "Hostname FQDN: $hostname"
echo "Hostname: $HOSTNAME"
echo "-------------------------------------------------"
sleep 15

echo
echo "Instalando pacotes do SAMBA e dependências"
echo "-------------------------------------------------"
echo
sleep 2
apt install -y samba wget net-tools dnsutils sudo smbclient ntpsec ntpdate cifs-utils libnss-winbind libpam-winbind acl ldap-utils attr ldb-tools smbldap-tools smbios-utils bind9 quota
echo
echo "Pacotes OK!"
echo
sleep 2
echo "Instalando o krb5"
echo
sudo DEBIAN_FRONTEND=noninteractive apt install -y krb5-user libpam-krb5
echo
echo "Pacotes OK!"

echo
echo "Definindo configurações de rede"
echo
echo "---- Arquivo /etc/network/interfaces ------------"
mv /etc/network/interfaces /etc/network/interfaces.bkp
cat >> /etc/network/interfaces << EOL
source /etc/network/interfaces.d/*
EOL
sleep 2
cat /etc/network/interfaces
echo "-------------------------------------------------"
echo "OK!"

echo
echo "Definindo IP estático na interface $nic"
echo
echo "---- Arquivo /etc/network/interfaces.d/$nic -----"
cat >> /etc/network/interfaces.d/$nic << EOL
auto $nic
iface $nic inet static
address $ip1.$ip2.$ip3.$ip4
netmask 255.255.255.0
broadcast $ip1.$ip2.$ip3.255
gateway $gateway
dns-search $dc_domain_realm
dns-nameservers $ip1.$ip2.$ip3.$ip4
dns-nameservers 8.8.8.8
EOL
sleep 2
cat /etc/network/interfaces.d/$nic
echo "-------------------------------------------------"
echo "IP OK!"

echo
echo "Alterando /etc/resolv.conf"
echo
echo "---------Arquivo /etc/resolv.conf ---------------"
mv /etc/resolv.conf /etc/resolv.conf.bkp
cat >> /etc/resolv.conf << EOF
nameserver $ip1.$ip2.$ip3.$ip4
#nameserver $gateway
nameserver 8.8.8.8
domain $domain
search $dc_domain.
EOF
sleep 2
cat /etc/resolv.conf
echo "-------------------------------------------------"
echo "OK!"

echo
echo "Desativando IPv6"
echo "-------------------------------------------------"
cat >> /etc/sysctl.conf << EOL
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.eth0.disable_ipv6 = 1
EOL
sleep 2
echo "IPv6 Desativado"

echo
echo "Alterando o arquivo hosts"
echo
echo "--------------- Arquivo /etc/hosts --------------"
mv /etc/hosts /etc/hosts.bkp
cat >> /etc/hosts << EOL
127.0.0.1 localhost
$ip1.$ip2.$ip3.$ip4 $hostname $host localhost
#::1     ip6-localhost ip6-loopback
#fe00::0 ip6-localnet
#ff00::0 ip6-mcastprefix
#ff02::1 ip6-allnodes
#ff02::2 ip6-allrouters
EOL
sleep 2
cat /etc/hosts
echo "-------------------------------------------------"
echo "Arquivo hosts OK!"

echo
echo "Iniciando Configuração do SAMBA"
echo "-------------------------------------------------"
mv /etc/samba/smb.conf /etc/samba/smb.conf.bkp
sleep 2
echo "Backup do arquivo padrão smb.conf OK!"
sleep 2
echo
echo "Provisionando o Samba"
echo "-------------------------------------------------"
echo
samba-tool domain provision --use-rfc2307 --server-role=dc --dns-backend=BIND9_DLZ --realm=$dc_domain_realm --domain=$domain --adminpass=$pass --option="interfaces=lo $nic" --option="bind interfaces only=yes"
echo
sleep 2
echo "Samba instalado..."

echo
echo "Iniciando configuração!"

echo
sleep 2

echo "-------------------------------------------------"
echo "Desativando os serviços smbd nmbd winbind"
echo
sudo systemctl unmask smbd nmbd winbind
echo "..."
sudo systemctl stop smbd nmbd winbind
echo "..."
sudo systemctl disable smbd nmbd winbind
echo
echo "Serviços parados ok!"
echo "-------------------------------------------------"

echo
sleep 2

echo "Ajustando Arquivos ..."

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Arquivo named.conf"
echo
bind_named=$(sudo named -v | cut -d ' ' -f 2 | cut -d '.' -f2)
sed -i 's/    #/#/' /var/lib/samba/bind-dns/named.conf
sed -i '/18.so/s/^# //' /var/lib/samba/bind-dns/named.conf
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Arquivo named.local"
echo
cp /etc/bind/named.conf.local /etc/bind/named.conf.local.bkp
cat >> /etc/bind/named.conf.local << EOL
include "/var/lib/samba/bind-dns/named.conf";
EOL
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Arquivo named.options"
echo
cp /etc/bind/named.conf.options /etc/bind/named.conf.options.bkp
sed -i 's/any; };/any; };\
	bindkeys-file "\/etc\/bind\/bind.keys";\
	tkey-gssapi-keytab "\/var\/lib\/samba\/bind-dns\/dns.keytab"; \
/g' /etc/bind/named.conf.options
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Arquivo usr.sbin.named"
echo
mkdir /var/cache/bind/bkp
cp /var/cache/bind/managed-keys.bind* /var/cache/bind/bkp
cp /etc/apparmor.d/usr.sbin.named /etc/apparmor.d/usr.sbin.named.bkp
sed -i 's/# Samba DLZ/# Samba DLZ\n\
  \/var\/lib\/samba\/bind-dns\/named.conf r,\
  \/var\/lib\/samba\/private\/named.conf r,\
  \/usr\/lib\/x86_64-linux-gnu\/samba\/\*\* mlr,\
  \/usr\/lib\/x86_64-linux-gnu\/samba\/bind9\/\*\* mlr,\
  \/usr\/lib\/x86_64-linux-gnu\/samba\/bind9\/dlz_bind9.so mlr,\
  \/usr\/lib\/x86_64-linux-gnu\/samba\/bind9\/dlz_bind9_9.so mlr,\
  \/usr\/lib\/x86_64-linux-gnu\/samba\/bind9\/dlz_bind9_10.so mlr,\
  \/usr\/lib\/x86_64-linux-gnu\/samba\/bind9\/dlz_bind9_11.so mlr,\
  \/usr\/lib\/x86_64-linux-gnu\/ldb\/modules\/ldb\/\*\* mlrwk,\
  \/var\/lib\/samba\/private\/\*\* mlrwk,\
  \/var\/lib\/samba\/ntpsec_signd\/\*\* rwlkix,\
/g' /etc/apparmor.d/usr.sbin.named
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Reiniciando apparmor e bind9"
echo
chmod 777 -R /var/lib/samba/private/sam.ldb.d/
systemctl restart apparmor
systemctl restart bind9
named-checkconf
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Arquivo krb5.conf"
echo
mv /etc/krb5.conf /etc/krb5.conf.initial
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
cp /etc/krb5.conf /etc/krb5.conf.bkp.samba
echo
#echo "Sem alteração"
#echo
#cat /etc/krb5.conf
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Primeira Alteração"
echo
sudo sed -i 's/\[libdefaults\]/\[libdefaults\]\
	rdns = false\
	default_tgs_enctypes = rc4-hmac des3-hmac-sha1\
	default_tkt_enctypes = rc4-hmac des3-hmac-sha1\
	permitted_enctypes = des-cbc-md5 des-cbc-crc des3-cbc-sha1\
	#ticket_lifetime = 24h\
	ticket_lifetime = 86400\
	forwardable = true\
	udp_preference_limit = 1000000\
	#renew_lifetime = 7d\
	renew_lifetime = 604800\
	default_ccache_name = \/etc\/samba\/krb5cc_%\{uid\}\
	udp_preference_limit = 1\
	kdc_timeout = 3000\
/g' /etc/krb5.conf

#cat /etc/krb5.conf
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Segunda Alteração"
echo
sudo sed -i 's/\dns_lookup_kdc = true/dns_lookup_kdc = false/g' /etc/krb5.conf
#cat /etc/krb5.conf
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Terceira Alteração"
echo
sudo sed -i "s/$dc_domain = {/$dc_domain = {\n\
	kdc = $hostname\n\
	admin_server = $hostname\
/g" /etc/krb5.conf
#cat /etc/krb5.conf
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Quarta Alteração"
echo
sudo sed -i "s/$HOSTNAME = $dc_domain/\
.$dc_domain_realm = $dc_domain\n\
	$dc_domain_realm = $dc_domain\n\
/g" /etc/krb5.conf
echo
#cat /etc/krb5.conf
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Quinta Alteração"
echo
cat >> /etc/krb5.conf << EOL
[logging]
	kdc = FILE:/var/log/krb5kdc.log
	admin_server = FILE:/var/log/kadmin.log
	default = FILE:/var/log/krb5lib.log
EOL
echo
cat /etc/krb5.conf
echo
echo "OK!"

echo
sleep 2
echo
echo "Fim das Alterações do krb5.conf!"
echo

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Arquivo nsswitch.conf"
echo
sudo sed -i "s/passwd:         files/passwd:         compat files systemd/g" /etc/nsswitch.conf
echo "..."
sudo sed -i "s/group:          files/group:          compat files systemd/g" /etc/nsswitch.conf
echo
cat /etc/nsswitch.conf
echo
echo "OK"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Arquivo user.map"
echo
cat >> /etc/samba/user.map << EOL
!root = $domain\Administrator $domain\administrator Administrator administrator
EOL
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Arquivo smb.conf"
echo
cp /etc/samba/smb.conf /etc/samba/smb.conf.bkp.provision
echo "-------------------------------------------------"
echo "OK"

echo
sleep 2

echo "-------------------------------------------------"
echo "Primeira Alteração"
echo
sudo sed -i "s/\[global\]/\[global\]\n\
	dns forwarder = 8.8.8.8\n\
	dns forwarder = $ip1.$ip2.$ip3.$ip4\
/g" /etc/samba/smb.conf
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Segunda Alteração"
echo
cp /etc/samba/smb.conf /etc/samba/smb.conf.initial
sudo sed -i "s/\[sysvol\]/\
	password server = $ip1.$ip2.$ip3.$ip4\n\
	#winbind enum users = yes\n\
	#winbind enum groups = yes\n\
	#winbind nss info = rfc2307\n\
\n\
	template homedir = \/home\/%U\n\
	template shell = \/bin\/bash\n\
        create mask = 0664\n\
        directory mask = 0775\n\
\n\
	logging = file\n\
	max log size = 1000\n\
	log file = \/var\/log\/samba\/log.%m\n\
	log level = 1\n\
\n\
	passdb backend = tdbsam\n\
	kerberos method = secrets and keytab\n\
	ldap server require strong auth = no\n\
	map to guest = Bad User\n\
\n\
	vfs objects = dfs_samba4 acl_xattr recycle\n\
	#vfs objects = acl_xattr\n\
	#vfs objects = dfs_samba4 acl_xattr audit\n\
\n\
	map acl inherit = yes\n\
	acl allow execute always = yes\n\
	store dos attributes = yes\n\
	username map = \/etc\/samba\/user.map\n\
	#enable privileges = yes\n\
	preferred master = yes\n\
	case sensitive = No\n\
\n\
	wins support = yes\n\
	hosts allow = ALL\n\
	name resolve order = lmhosts host wins bcast\n\
\n\
	## Desabilita compartilhamento de impressoras\n\
	printcap name = \/dev\/null\n\
	load printers = no\n\
	disable spoolss = yes\n\
	printing = bsd\n\
\n\
	#security = user \n\
	idmap config $domain : unix_nss_info = no\n\
	idmap config $domain : backend = ad  \n\
	#idmap config $domain : range = 10000-59999 \n\
	idmap config * : backend = tdb \n\
        idmap config * : range = 3000-7999 \n\
\n\[sysvol\]/" /etc/samba/smb.conf
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Terceira Alteração"
echo
sudo sed -i "s/interfaces = lo $nic/interfaces = lo $nic $ip1.$ip2.$ip3.$ip4\/24/g" /etc/samba/smb.conf
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Quarta Alteração"
echo
sudo sed -i 's/winbindd/winbind/g' /etc/samba/smb.conf
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------- Arquivo /etc/samba/smb.conf  ------------"
echo
cat /etc/samba/smb.conf
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Reiniciando os Serviços bind9 e samba"
echo
sudo systemctl restart bind9
echo "..."
sudo smbcontrol all reload-config
echo "..."
sudo systemctl restart samba-ad-dc
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Habilitando mkhomedir"
echo
sudo pam-auth-update --enable mkhomedir
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Reiniciando os serviços do samba"
echo
sudo systemctl unmask samba-ad-dc 
sudo systemctl enable samba-ad-dc 
sudo systemctl start samba-ad-dc
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Arquivo ntpsec"
echo
sudo systemctl stop ntpsec
echo "..."
sudo sed -i "s/pool /#pool/g" /etc/ntpsec/ntp.conf
echo "..."
sudo sed -i '23p' /etc/ntpsec/ntp.conf
echo "..."
sed -i '23s/^/server a.ntp.br iburst\n/g' /etc/ntpsec/ntp.conf
sed -i '23s/^/server b.ntp.br iburst\n/g' /etc/ntpsec/ntp.conf
sed -i '23s/^/server c.ntp.br iburst\n/g' /etc/ntpsec/ntp.conf
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Arquivo ntp.conf"
echo
cat >> /etc/ntpsec/ntp.conf << EOL
# Relogio Local
server 127.127.1.0
fudge 127.127.1.0 stratum 10
# Configurações adicionais para o Samba 4
ntpsigndsocket /var/lib/samba/ntp_signd/
restrict default mssntp
disable monitor
EOL
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Ajustando permissões "
echo
sudo chown -v root:ntpsec /var/lib/samba/ntp_signd/ 
echo "..."
sudo chmod -v 750 /var/lib/samba/ntp_signd/ 
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Configurando NTP no cron"
echo
cat >> /etc/cron.d/server.conf << EOF
bindaddress $ip1.$ip2.$ip3.$ip4
allow $ip1.$ip2.$ip3.1/24
ntpsigndsocket  /var/lib/samba/ntp_signd
EOF
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Arquivo /etc/cron.d/cmd.conf"
echo
cat >> /etc/cron.d/cmd.conf << EOF
bindcmdaddress /var/run/crond.pid
cmdport 0
EOF
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Habilitando e atualizando os serviços ntp"
echo
sudo systemctl enable --now cron
echo "..."
sudo ntpdate pool.ntp.br
echo "..."
sudo service ntpsec start
echo "..."
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Configurando o SPN"
echo
samba-tool spn add ldap/$dc_domain_realm Administrator
samba-tool spn add cifs/$dc_domain_realm Administrator
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Exportando o krb5.keytab"
echo
samba-tool domain exportkeytab /etc/krb5.keytab
echo "..."
ls -l /etc/krb5.keytab
echo "..."
chmod 755 /etc/krb5.keytab
echo "..."
ls -l /etc/krb5.keytab
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Atualizando o klist"
echo
kinit -kt /etc/krb5.keytab Administrator@$dc_domain
echo
klist
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo " Reiniciando todos os serviços"
echo
#/etc/init.d/networking restart
sudo systemctl daemon-reload
sudo systemctl daemon-reexec
sudo systemctl restart ntpsec
sudo systemctl restart sshd
sudo systemctl restart bind9
sudo smbcontrol all reload-config
sudo systemctl restart samba-ad-dc
sleep 2
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo
echo "-------------------------------------------------"
echo "Fim da instalação"
echo "-------------------------------------------------"

echo
echo
echo "Iniciando Verificação Geral do Sistema..."
echo
echo
sleep 2

echo "-------------------------------------------------"
echo " Cadastrando ZONA REVERSA..."
echo
echo $pass | samba-tool dns zonecreate $hostname $ip3.$ip2.$ip1.in-addr.arpa -U administrator
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------------------"
echo " Cadastrando PTR..."
echo
echo $pass | samba-tool dns add $hostname $ip3.$ip2.$ip1.in-addr.arpa $ip4 PTR $hostname -U administrator
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------------------"
echo "Informações do SID..."
echo
ldbsearch -H /var/lib/samba/private/sam.ldb DC=$domain | grep objectSid
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------------------"
echo " Teste do SMBClient..."
echo
smbclient -L localhost -N
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------------------"
echo "Teste SMBCliente com Login"
echo
echo "$pass" | smbclient //localhost/netlogon -U Administrator -c 'ls'
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------------------"
echo "Teste de Descoberta Kerberos..."
echo
host -t SRV _kerberos._udp.$dc_domain_realm.
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------------------"
echo "Teste de Descoberta LDAP..."
echo
host -t SRV _ldap._tcp.$dc_domain_realm.
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------------------"
echo " Teste DNS Reverso Dominio: $dc_domain_realm..."
echo
nslookup $dc_domain_realm
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------------------"
echo " Teste DNS Reverso IP: $ip1.$ip2.$ip3.$ip4 ..."
echo
nslookup $ip1.$ip2.$ip3.$ip4
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------------------"
echo " Teste DNS Reverso Host $ip1.$ip2.$ip3.$ip4"
echo
host $ip1.$ip2.$ip3.$ip4
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------------------"
echo " Nivel do Dominio ao Windows "
echo
sudo samba-tool domain level show
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------------------"
echo " Sincronização ntpsec ..."
echo
sudo ntpq -p
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------------------"
echo " Teste do GETENT                     "
echo
getent passwd administrator
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------------------"
echo " Conceder privilégios para configurar ACLs pelo Windows "
echo
echo $pass | net rpc rights grant "$domain\Administrator" SeDiskOperatorPrivilege -U "$domain\Administrator"
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------------------"
echo " Definindo senha "nunca expira" para administrator"
echo
samba-tool user setexpiry administrator --noexpiry
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------------------"
echo "Informações SPN ..."
echo
samba-tool spn list Administrator
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------"
echo "Verificando erros ..."
echo
samba-tool dbcheck --cross-ncs
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "-------------------------------------"
echo "Verificando conexão com a internet ..."
echo
ping -c4 google.com
echo
echo "OK!"
echo "-------------------------------------------------"

echo
sleep 2

echo "Sistema verificado com Sucesso "

echo
sleep 2

echo "-------------------------------------------------"
echo " O Dominio do sistema é $dc_domain"
echo " O usuário é administrator, e a senha é $pass"
echo "-------------------------------------------------"
