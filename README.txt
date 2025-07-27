# Analisador de Rede

Este projeto é um analisador simples de conexões de rede em Python. Ele verifica as conexões de rede ativas no seu computador, identifica possíveis conexões suspeitas com base no país de origem do IP remoto e no nome do processo, e gera um relatório detalhado em formato de tabela.

## Funcionalidades

- Lista todas as conexões de rede ativas.
- Consulta informações de IP externo usando o serviço [ipinfo.io](https://ipinfo.io/).
- Destaca conexões com países considerados suspeitos.
- Alerta para nomes de processos potencialmente maliciosos.
- Gera um relatório em `log_rede.txt`.

## Como usar

1. **Instale as dependências:**
   ```bash
   pip install psutil requests tabulate
   ```

2. **Execute o script:**
   ```bash
   python analisador_rede.py
   ```

3. **Verifique o relatório:**  
   O resultado será salvo no arquivo `log_rede.txt` na mesma pasta do script.

## Arquivos importantes

- `analisador_rede.py`: Script principal do analisador.
- `log_rede.txt`: Relatório gerado após a execução.

## O que não incluir no repositório

- Não inclua arquivos como `log_rede.txt`, pastas de ambiente virtual (`venv/`), ou arquivos temporários.

## Exemplo de uso

```
Relatório salvo em log_rede.txt!
```

Abra o arquivo `log_rede.txt` para ver o resultado detalhado.

---

**Atenção:**  
Este script é apenas para fins educacionais e pode gerar falsos positivos. Sempre revise manualmente os alertas antes de tomar