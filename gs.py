import json
from datetime import datetime
import paho.mqtt.client as mqtt
import threading
import time
import os
import matplotlib.pyplot as plt
import csv
import bcrypt


log = 0  # Definindo a variável que registra se o login foi feito ou não
contador = 5  # Definindo contador de tentativas de login
usuario = {}  # Inicializando a variável do usuário

nome = None  # Inicializando a variável do nome
'''------Iniciando programa------'''
def init():
    print("Seja bem-vindo!")
    global log, contador, usuario
    log = 0  # Deslogando o usuário anterior
    contador = 5  # Resetando o número de tentativas
    usuario = None  # Resetando o usuário


'''Sessão de verificação/validação'''
def validar_cpf(cpf):
    if not cpf.isdigit() or len(cpf) != 11: #conferindo tamanho do cpf
        raise ValueError("CPF inválido. Certifique-se de digitar apenas números e 11 dígitos.")
    


def validar_data_nascimento(nasc): #verificando formatação da data
    if not nasc.count('/') == 2 or not all(part.isdigit() for part in nasc.split('/')):
        raise ValueError("Data de nascimento inválida. Digite no formato DD/MM/AAAA.")

def validar_senha(senha, senha1): #verificando se a senha está forte e confirmada
    if senha != senha1 or not any(c.isupper() for c in senha) or not any(c.isdigit() for c in senha):
        raise ValueError('As senhas não coincidem ou não atendem um ou mais requisitos. Tente novamente.')

def verificar_credenciais(email, cpf):
    try:
        with open("cadastros.json", "r", encoding="utf8") as arquivo:
            usuarios = json.loads(arquivo.read())
    except Exception as e:
        # Registra o erro em um arquivo de log
        with open("error_log.txt", "a", encoding="utf8") as log_file:
            log_file.write(f"Erro ao verificar credenciais: {str(e)}\n")

        print(f"Erro ao verificar credenciais: {e}")
        return False

    for user in usuarios:
        if user.get("Email") == email and user.get("cpf") == cpf:
            return True

    return False


def atualizar_senha(nome, nova_senha):
    try:
        with open("cadastros.json", "r", encoding="utf8") as arquivo:
            usuarios = json.load(arquivo)
    except Exception as e:
        # Registra o erro em um arquivo de log
        with open("error_log.txt", "a", encoding="utf8") as log_file:
            log_file.write(f"Erro ao atualizar senha: {str(e)}\n")

        print(f"Erro ao atualizar senha: {e}")
        return

    for user in usuarios:
        if user.get("user") == nome:
            # Usa bcrypt para hashear a nova senha
            nova_senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt())
            # Atualiza a senha no registro
            user["senha"] = nova_senha_hash.decode('utf-8')  # Converte bytes para string antes de armazenar

            print(f"Nova senha fornecida: {nova_senha}")
            print(f"Nova senha hasheada: {nova_senha_hash.decode('utf-8')}")

    # Reescreve a lista no arquivo "cadastros.json"
    with open("cadastros.json", "w", encoding="utf8") as arquivo:
        json.dump(usuarios, arquivo, indent=2, ensure_ascii=False)

'''----------------------------------'''

'''-------Cadastrando usuário---------'''
def cadastrar_usuario():
    nome = input("Digite o seu nome completo: ")
    email = input("Por favor, digite o seu Email: ")
    user = input("Digite o seu nome de usuário (utilizado no login): ")
    nasc = input("Por favor, digite sua data de nascimento (DD/MM/AAAA): ")
    cpf = input("Digite seu CPF (apenas números): ")
    senha = input("Escolha uma senha (deve conter pelo menos um caractere maiúsculo e um número): ")
    senha1 = input("Por favor, confirme a senha: ")

    try:
        validar_cpf(cpf)
        validar_data_nascimento(nasc)
        validar_senha(senha, senha1)

        tipo_usuario = input("Você é um paciente ou médico? Digite 'paciente' ou 'medico': ").lower()
        if tipo_usuario not in ["paciente", "medico"]:
            raise ValueError("Tipo de usuário inválido. Escolha entre 'paciente' ou 'medico'.")

        # Carrega dados existentes de "cadastros.json"
        try:
            with open("cadastros.json", "r", encoding="utf8") as arquivo:
                usuarios = json.load(arquivo)
        except FileNotFoundError:
            usuarios = []

        # Use bcrypt para hashear a senha
        senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())

        # Da append do usuário novo para a lista
        dados_usuario = {
            "user": user,
            "nome": nome,
            "Email": email,
            "data de nascimento": nasc,
            "cpf": cpf,
            "senha": senha_hash.decode('utf-8'),  # Converta a senha hasheada para uma string antes de armazená-la
            "tipo": tipo_usuario,
        }
        usuarios.append(dados_usuario)

        # Reescreve a lista no arquivo "cadastros.json"
        with open("cadastros.json", "w", encoding="utf8") as arquivo:
            json.dump(usuarios, arquivo, indent=2)

        print("Cadastro realizado com sucesso!")

    except ValueError as e:
        # Registra o erro em um arquivo de log
        with open("error_log.txt", "a", encoding="utf8") as log_file:
            log_file.write(f"Erro ao cadastrar usuário: {str(e)}\n")

        print(e)

'''---------função de login-----------'''
def login():
    global log, contador, usuario, nome

    nome = input("Por favor, digite o usuário: ")
    senha = input("Por favor, digite a senha: ")

    try:
        with open("cadastros.json", "r", encoding="utf8") as arquivo:
            usuarios = json.loads(arquivo.read())
    except Exception as e:
        # Registra o erro em um arquivo de log
        with open("error_log.txt", "a", encoding="utf8") as log_file:
            log_file.write(f"Erro durante o login: {str(e)}\n")

        print(f"Erro durante o login: {e}")

    # Averiguando se o usuário e senha cadastrados existem no sistema
    for user in usuarios:
        if user["user"] == nome and bcrypt.checkpw(senha.encode('utf-8'), user["senha"].encode('utf-8')):
            print("Login bem sucedido!")
            usuario = user
            log = 1
            contador = 5  # Reseta o contador após um login bem-sucedido
            if log == 1:
                menu()
            return

    print("Usuário ou senha incorretos.")
    contador -= 1
    if contador == 0:
        print("Número máximo de tentativas atingido. Redefina a senha.")
        # Verifica se o usuário excedeu o número máximo de tentativas
        email = input("Digite o seu Email: ")
        cpf = input("Digite seu CPF (apenas números): ")

        # Verifica se as credenciais (email e cpf) estão corretas
        usuario_encontrado = False
        for user in usuarios:   #busca o usuário por email e cpf
            if user["cpf"] == cpf and user["Email"] == email:
                usuario_encontrado = True
                nome = user['user']  # Atualiza a variável global nome
                break

        if usuario_encontrado:
            nova_senha = input("Digite a nova senha: ")
            confirmar_senha = input("Confirme a nova senha: ")

            if nova_senha == confirmar_senha:
                # Atualiza a senha no registro
                atualizar_senha(nome, nova_senha)
                print("Senha redefinida com sucesso!")
            else:
                print("As senhas não coincidem. Tente novamente.")
        else:
            print("Credenciais inválidas. Não é possível redefinir a senha.")



'''----------Painel de entrada------------'''
def entrar():
    global contador, log, usuario
    while log != 1 and contador > 0:  #aparecendo caso não exista usuário logado
        try:                          
            opcao = int(input('1 - Login\n2 - Registrar\n'))
        except ValueError:
            print('Por favor digite uma opção válida')
            return

        if opcao == 1:
            login()         
        elif opcao == 2:
            cadastrar_usuario()

'''----------Marcar consultas-------------'''
def marcar_consulta():
    global usuario
    if not usuario:
        print("Você precisa fazer login para marcar uma consulta.")
        return

    nome_paciente = usuario["nome"]  # coleta nome do dicionário de dados paciente
    data_consulta_str = input("Digite a data da consulta (formato DD/MM/YYYY HH:MM): ")

    try:
        # Converte a string de data para um objeto datetime
        data_consulta = datetime.strptime(data_consulta_str, "%d/%m/%Y %H:%M")
    except Exception as e:
        # Registra o erro em um arquivo de log
        with open("error_log.txt", "a", encoding="utf8") as log_file:
            log_file.write(f"Erro ao marcar consulta: {str(e)}\n")

        print(f"Erro ao marcar consulta: {e}")
        return

    sintomas = input("Digite os sintomas: ")
    tempo_sintomas = input("Há quanto tempo os sintomas começaram? ")
    evolucao_sintomas = input("Os sintomas aumentaram, diminuíram ou se mantiveram os mesmos? ")
    medicamento_uso = input("Faz uso de algum medicamento? Se sim, qual? ")
    historico_enfermidade = input("Tem algum histórico de enfermidade na família? Se sim, explique: ")

    consulta = {
        "paciente": nome_paciente,
        "data": data_consulta.strftime("%Y-%m-%d %H:%M"),
        "sintomas": sintomas,
        "tempo_sintomas": tempo_sintomas,
        "evolucao_sintomas": evolucao_sintomas,
        "medicamento_uso": medicamento_uso,
        "historico_enfermidade": historico_enfermidade
    }

    # Carrega dados existentes do arquivo se existir, ou cria uma lista vazia
    try:
        with open("consultas.json", "r", encoding="utf8") as file:
            consultas = json.load(file)
    except FileNotFoundError:
        consultas = []

    # Adiciona a nova consulta à lista
    consultas.append(consulta)

    # Escreve a lista atualizada de consultas de volta ao arquivo
    with open("consultas.json", "w", encoding="utf8") as file:
        json.dump(consultas, file, ensure_ascii=False, indent=2)

    print("Consulta marcada com sucesso.")
'''---------Exibir consultas marcadas------'''
def mostrar_consultas():
    global usuario
    if not usuario:
        print("Você precisa fazer login para ver as consultas.")
        return

    try:
        with open("consultas.json", "r", encoding="utf8") as arquivo:
            consultas = json.load(arquivo)

        if not consultas:
            print("Nenhuma consulta marcada.")
        else:
            print("Consultas marcadas:")
            for idx, consulta in enumerate(consultas, start=1):
                # Convert both names to lowercase for case-insensitive comparison
                if consulta["paciente"].lower() == usuario["nome"].lower():
                    sintomas = consulta.get("sintomas", "Nenhum sintoma registrado")
                    print(f"{idx}. Paciente: {consulta['paciente']}, Data: {consulta['data']}, Sintomas: {sintomas}")

    except Exception as e:
        # Registra o erro em um arquivo de log
        with open("error_log.txt", "a", encoding="utf8") as log_file:
            log_file.write(f"Erro ao mostrar consultas: {str(e)}\n")

        print(f"Erro ao mostrar consultas: {e}")

def remarcar_consulta():
    global usuario
    if not usuario:
        print("Você precisa fazer login para remarcar uma consulta.")
        return

    try:
        with open("consultas.json", "r") as arquivo:
            consultas = json.load(arquivo)

        if not consultas:
            print("Nenhuma consulta marcada para remarcar.")
        else:
            mostrar_consultas()
            indice = int(input("Digite o número da consulta que deseja remarcar: ")) - 1

            if 0 <= indice < len(consultas):
                consulta = consultas[indice]

                # Verifica se o usuário atual é o paciente associado à consulta
                if consulta["paciente"] == usuario["nome"]:
                    nova_data = input("Digite a nova data da consulta (formato DD/MM/YYYY HH:MM): ")
                    try:
                        # Converte a string de data para um objeto datetime
                        consulta["data"] = datetime.strptime(nova_data, "%d/%m/%Y %H:%M").strftime("%Y-%m-%d %H:%M")

                        # Salva as consultas atualizadas no arquivo JSON
                        with open("consultas.json", "w") as arquivo:
                            json.dump(consultas, arquivo, indent=2)

                        print("Consulta remarcada com sucesso!")
                    except ValueError as e:
                        print(f"Erro ao converter a data: {e}")
                else:
                    print("Você não tem permissão para remarcar esta consulta.")
            else:
                print("Índice inválido.")
    except FileNotFoundError:
        print("Nenhuma consulta marcada para remarcar.")
    except Exception as e:
    # Registra o erro em um arquivo de log
        with open("error_log.txt", "a", encoding="utf8") as log_file:
            log_file.write(f"Erro ao remarcar consulta: {str(e)}\n")

        print(f"Erro ao remarcar consulta: {e}")

''''Trecho destinado às funções disponíveis apenas para médicos'''

#exibir consultas do paciente
def visualizar_consultas_paciente(paciente_nome):
    try:
        with open("consultas.json", "r") as arquivo:
            consultas = json.load(arquivo)   #abre arquivo das consultas

        if not consultas:
            print("Nenhuma consulta marcada.")
        else:
            print(f"Consultas marcadas para {paciente_nome}:")
            for consulta in consultas:
                if consulta["paciente"] == paciente_nome:   #mostra a consulta
                    print(f"Data: {consulta['data']}, Sintomas: {consulta.get('sintomas', 'Nenhum sintoma registrado')}")
    except FileNotFoundError:
        print("Nenhuma consulta marcada.")



#mostrar exames do paciente
def visualizar_exames_paciente(paciente_nome):

    try:
        paciente_dir = f"pacientes/{paciente_nome}"
        arquivo_csv = f"{paciente_dir}/dados_coletados.csv"

        with open(arquivo_csv, "r") as arquivo:
            dados_coletados = arquivo.readlines()

        if not dados_coletados:
            print("Nenhum resultado de exame disponível.")
        else:
            print(f"Resultados de exames para {paciente_nome}:")

            # convertendo o dado recebido do sensor para float
            numeric_data = [float(dado.strip()) for dado in dados_coletados]

            # Plotando os dados em um gráfico
            plt.figure(figsize=(10, 6))
            plt.plot(numeric_data, marker='o')
            plt.title(f"Resultados de Exames para {paciente_nome}")
            plt.xlabel("Índice do Exame")
            plt.ylabel("Resultado")
            plt.grid(True)
            plt.show()

    except FileNotFoundError:
        print("Nenhum resultado de exame disponível.")
    except Exception as e:
        print(f"Erro ao processar os dados: {e}")


'''Função para mostrar as consultas marcadas para o dia'''
def consultas_do_dia():
    global usuario

    if not usuario:
        print("Você precisa fazer login como médico para acessar essa opção.")
        return

    try:
        with open("consultas.json", "r") as arquivo:
            consultas = json.load(arquivo)

        if not consultas:
            print("Nenhuma consulta marcada.")
        else:
            data_hoje = datetime.now().strftime("%Y-%m-%d")
            consultas_hoje = [consulta for consulta in consultas if consulta["data"].startswith(data_hoje)]

            if not consultas_hoje:
                print("Nenhuma consulta marcada para hoje.")
            else:
                print("Consultas marcadas para hoje:")
                for consulta in consultas_hoje:
                    print(f"Paciente: {consulta['paciente']}, Data: {consulta['data']}, Sintomas: {consulta.get('sintomas', 'Nenhum sintoma registrado')}")

    except FileNotFoundError:
        print("Nenhuma consulta marcada.")


'''função que coleta dados do servidor onde o sensor está configurado'''

def mqttserver(paciente_nome):
    # Cria um diretório para cada paciente se não existir
    paciente_dir = f"pacientes/{paciente_nome}"
    os.makedirs(paciente_dir, exist_ok=True)

    # Define o nome do arquivo para os dados coletados do paciente
    arquivo_csv = f"{paciente_dir}/dados_coletados.csv"

    def on_connect(client, userdata, flags, rc):
        print("Conectado com o resultado: " + str(rc))
        client.subscribe("/TEF/lamp118/attrs")   # se inscreve no tópico

    def on_message(client, userdata, msg):
        print(msg.topic + " " + str(msg.payload)) # recebe a mensagem publicada

        try:
            # Split the string by tabs and convert each value to float
            dados_float = [float(value) for value in msg.payload.decode('utf-8').split('\t')]

            with open(arquivo_csv, "a", newline='') as csvfile:
                csv_writer = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                csv_writer.writerow(dados_float)
        except ValueError as e:
            print(f"Erro ao converter para float: {e}")
        except Exception as e:
        # Registra o erro em um arquivo de log
            with open("error_log.txt", "a", encoding="utf8") as log_file:
                log_file.write(f"Erro no servidor MQTT: {str(e)}\n")

            print(f"Erro no servidor MQTT: {e}")

    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect("46.17.108.113", 1883, 60)  # define o IP e a porta do docker

    # Tempo de execução da função mqttserver (em segundos)
    tempo_execucao = 30

    # Inicia a conexão MQTT em uma thread separada
    client_thread = threading.Thread(target=client.loop_start)
    client_thread.start()

    print("Recebendo informações_______________")

    # Espera o tempo de execução
    time.sleep(tempo_execucao)

    # Para a execução da thread após o tempo de execução
    client.loop_stop()

    print("Tempo de execução concluído. Encerrando a função mqttserver.")



'''------------menu principal-------------'''
def menu():
    global usuario, nome
    while True:
        print(f"Seja bem-vindo, {nome}!")
        print('Por favor, selecione uma opção')
        print("---------------------")
        print("1 - Marcar consulta")
        print("2 - Mostrar consultas")
        print("3 - Remarcar consulta")

        # Adicionando a nova opção para médicos
        if usuario.get("tipo") == "medico":
            print("4 - Consultas do dia")
            print("5 - Visualizar dados do paciente")

        print("6 - Importar exames do sensor")
        print("7 - Sair")
        print("---------------------")
        escolha = input("Escolha uma opção: ")

        if escolha == '1':
            marcar_consulta()
        elif escolha == '2':
            mostrar_consultas()
        elif escolha == '3':
            remarcar_consulta()
        elif escolha == '4':
            if usuario.get("tipo") == "medico":
                consultas_do_dia()
            else:
                print("Opção disponível apenas para médicos.")
        elif escolha == '5':
            if usuario.get("tipo") == "medico":
                paciente_nome = input("Digite o nome do paciente: ")
                visualizar_consultas_paciente(paciente_nome)
                visualizar_exames_paciente(paciente_nome)
            else:
                print("Opção disponível apenas para médicos.")
        elif escolha == '6':
            mqttserver(nome)
        elif escolha == '7':
            print("Saindo do programa. Até mais!")
            break
        else:
            print("Opção inválida.")



init()
entrar()

