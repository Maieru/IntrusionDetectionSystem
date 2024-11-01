# Intrusion Detection System (IDS)

Este é um sistema de detecção de intrusão (IDS) simples que monitora pacotes de rede e bloqueia IPs que enviam mais de 5 pacotes SYN em menos de um segundo usando `iptables`.

## Requisitos

- Python 3.x
- Permissões de superusuário (root)
- `iptables` instalado e configurado

## Instalação

1. Clone este repositório:

    ```sh
    git clone https://github.com/seu-usuario/ids.git
    cd ids
    ```

2. Certifique-se de que você tem as permissões necessárias para executar comandos `iptables`:

    ```sh
    sudo iptables -L
    ```

## Uso

1. Execute o script IDS com permissões de superusuário:

    ```sh
    sudo python3 ids.py
    ```

2. O script começará a monitorar pacotes de rede na interface especificada (`enp0s3` por padrão). Ele bloqueará qualquer IP que enviar mais de 5 pacotes SYN em menos de um segundo.

## Funções

- `listar_ips_bloqueados()`: Lista os IPs atualmente bloqueados pelo `iptables`.
- `limpar_iptables()`: Limpa todas as regras do `iptables`.

## Detalhes do Funcionamento

### Monitoramento de Pacotes

O script cria um socket raw para capturar pacotes de rede na interface especificada. Ele analisa os cabeçalhos Ethernet, IP e TCP para identificar pacotes SYN.

### Contagem de Pacotes SYN

O script mantém um dicionário `syn_timestamps` para armazenar os timestamps dos pacotes SYN recebidos de cada IP. Se um IP enviar mais de 5 pacotes SYN em menos de um segundo, ele será considerado como um possível ataque SYN.

### Bloqueio de IPs

Se um IP for identificado como um possível atacante, ele será adicionado ao `iptables` para bloquear todas as comunicações futuras. O IP é adicionado ao conjunto `ipsBloqueados` para garantir que não seja bloqueado novamente.

### Funções Auxiliares

- **listar_ips_bloqueados()**: Executa o comando `iptables -L -n -v` para listar todas as regras do `iptables` e imprime a saída.
- **limpar_iptables()**: Executa o comando `iptables -F` para limpar todas as regras do `iptables`.