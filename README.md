# Instalação do Samba4 no Debian 12
# Instale o Debian 12 minimal
# Atualize o Sistema

apt update && apt-upgrade

# Baixe o pacote do git

apt install -y git

# Clone o repositório

git clone https://github.com/davigalucio/linux.git

# Execute o arquivos .sh na pasta Linux clonado do repositório

 sh linux/samba4easy.sh

# Atenção:
# Edite o arquivo para DEFINIR o nome do seu Dominio preferêncial, e altere a senha do "Administrator"
# Dominio padrão: SKY.NET
# Usuário padrão: administrator
# Senha: Passw0rd$2
