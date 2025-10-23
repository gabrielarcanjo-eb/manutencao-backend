import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from sqlalchemy.orm import sessionmaker
from database import init_db, Base, Equipamento, Fornecedor, OrdemDeServico, Manutencao, Usuario, DocumentoPatrimonio
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
import datetime
from sqlalchemy import func

load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "supersecretkey_default")

# Configuração do CORS
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "*") # Permitir qualquer origem para depuração
CORS(app, resources={r"/*": {"origins": CORS_ORIGIN, "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization", "X-Access-Token"]}})


# Inicializar o banco de dados e criar uma sessão
engine, Session = init_db()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
        if not token:
            return jsonify({"message": "Token está faltando!"}), 401
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            session = Session()
            current_user = session.query(Usuario).filter_by(id=data["user_id"]).first()
	            session.close()
        except:
            return jsonify({"message": "Token é inválido!"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def permission_required(permission_level):
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user, *args, **kwargs):
            if current_user.permissao != permission_level and current_user.permissao != 'administrador':
                return jsonify({"message": "Permissão insuficiente"}), 403
            return f(current_user, *args, **kwargs)
        return decorated_function
    return decorator

@app.route("/init-admin", methods=["POST"])
def init_admin():
    """Endpoint para criar o primeiro usuário admin. Só funciona se não houver usuários."""
    session = Session()
    existing_users = session.query(Usuario).count()
    session.close()
    
    if existing_users > 0:
        return jsonify({"message": "Já existem usuários no sistema. Use o endpoint /register para criar novos usuários."}), 403
    
    data = request.json
    if not data or not data.get("nome_usuario") or not data.get("senha"):
        return jsonify({"message": "Nome de usuário e senha são obrigatórios"}), 400
    
    hashed_password = generate_password_hash(data["senha"], method="pbkdf2:sha256")
    
    session = Session()
    admin_user = Usuario(
        nome_usuario=data["nome_usuario"],
        senha_hash=hashed_password,
        email=data.get("email", "admin@clinic.com"),
        permissao="administrador"
    )
    session.add(admin_user)
    session.commit()
    session.close()
    
    return jsonify({"message": "Usuário administrador criado com sucesso!"}), 201

@app.route("/login", methods=["POST"])
def login_user():
    auth = request.json
    if not auth or not auth.get("nome_usuario") or not auth.get("senha"):
        return jsonify({"message": "Credenciais inválidas"}), 401

    session = Session()
    user = session.query(Usuario).filter_by(nome_usuario=auth["nome_usuario"]).first()
    session.close()

    if not user or not check_password_hash(user.senha_hash, auth["senha"]):
        return jsonify({"message": "Credenciais inválidas"}), 401

    token = jwt.encode({
        "user_id": user.id,
        "permissao": user.permissao,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }, app.config["SECRET_KEY"], algorithm="HS256")

    return jsonify({"token": token, "permissao": user.permissao})

@app.route("/usuarios", methods=["POST"])
@token_required
@permission_required("administrador")
def create_user(current_user):
    data = request.json
    hashed_password = generate_password_hash(data["senha"], method="pbkdf2:sha256")
    
    session = Session()
    new_user = Usuario(
        nome_usuario=data["nome_usuario"],
        senha_hash=hashed_password,
        email=data.get("email"),
        permissao=data.get("permissao", "visualizador")
    )
    session.add(new_user)
    session.commit()
    session.close()
    return jsonify({"message": "Usuário criado com sucesso!"}), 201

# Endpoints para Equipamentos
@app.route("/equipamentos", methods=["POST"])
@token_required
@permission_required("patrimonio")
def add_equipamento(current_user):
    data = request.json
    session = Session()
    new_equipamento = Equipamento(
        nome=data["nome"],
        marca=data["marca"],
        fornecedor_id=data.get("fornecedor_id"),
        valor_compra=data["valor_compra"],
        data_compra=datetime.datetime.strptime(data["data_compra"], "%Y-%m-%d").date(),
        data_garantia_fim=datetime.datetime.strptime(data["data_garantia_fim"], "%Y-%m-%d").date() if data.get("data_garantia_fim") else None,
        tipo_posse=data["tipo_posse"],
        numero_identificacao=data["numero_identificacao"],
        valor_atual=data.get("valor_atual"),
        total_reparos=data.get("total_reparos", 0.00),
        status_operacional=data.get("status_operacional", "Operacional"),
        tipo_equipamento=data.get("tipo_equipamento"),
        vida_util_anos=data.get("vida_util_anos")
    )
    session.add(new_equipamento)
    session.commit()
    session.close()
    return jsonify({"message": "Equipamento adicionado com sucesso!"}), 201

@app.route("/equipamentos", methods=["GET"])
@token_required
def get_equipamentos(current_user):
    session = Session()
    equipamentos = session.query(Equipamento).all()
    output = []
    for eq in equipamentos:
        output.append({
            "id": eq.id,
            "nome": eq.nome,
            "marca": eq.marca,
            "fornecedor_id": eq.fornecedor_id,
            "valor_compra": str(eq.valor_compra),
            "data_compra": eq.data_compra.isoformat(),
            "data_garantia_fim": eq.data_garantia_fim.isoformat() if eq.data_garantia_fim else None,
            "tipo_posse": eq.tipo_posse,
            "numero_identificacao": eq.numero_identificacao,
            "ativo": eq.ativo,
            "valor_atual": str(eq.valor_atual) if eq.valor_atual else None,
            "total_reparos": str(eq.total_reparos),
            "status_operacional": eq.status_operacional,
            "tipo_equipamento": eq.tipo_equipamento,
            "vida_util_anos": eq.vida_util_anos,
            "manutencoes_agendadas": [{"data_agendada": m.data_agendada.isoformat(), "tipo_manutencao": m.tipo_manutencao} for m in eq.manutencoes_agendadas]
        })
    session.close()
    return jsonify({"equipamentos": output})

@app.route("/equipamentos/<int:equipamento_id>", methods=["PUT"])
@token_required
@permission_required("patrimonio")
def update_equipamento(current_user, equipamento_id):
    data = request.json
    session = Session()
    equipamento = session.query(Equipamento).filter_by(id=equipamento_id).first()
    if not equipamento:
        session.close()
        return jsonify({"message": "Equipamento não encontrado"}), 404

    equipamento.nome = data.get("nome", equipamento.nome)
    equipamento.marca = data.get("marca", equipamento.marca)
    equipamento.fornecedor_id = data.get("fornecedor_id", equipamento.fornecedor_id)
    equipamento.valor_compra = data.get("valor_compra", equipamento.valor_compra)
    if data.get("data_compra"):
        equipamento.data_compra = datetime.datetime.strptime(data["data_compra"], "%Y-%m-%d").date()
    if data.get("data_garantia_fim"):
        equipamento.data_garantia_fim = datetime.datetime.strptime(data["data_garantia_fim"], "%Y-%m-%d").date()
    equipamento.tipo_posse = data.get("tipo_posse", equipamento.tipo_posse)
    equipamento.numero_identificacao = data.get("numero_identificacao", equipamento.numero_identificacao)
    equipamento.ativo = data.get("ativo", equipamento.ativo)
    equipamento.valor_atual = data.get("valor_atual", equipamento.valor_atual)
    equipamento.total_reparos = data.get("total_reparos", equipamento.total_reparos)
    equipamento.status_operacional = data.get("status_operacional", equipamento.status_operacional)
    equipamento.tipo_equipamento = data.get("tipo_equipamento", equipamento.tipo_equipamento)
    equipamento.vida_util_anos = data.get("vida_util_anos", equipamento.vida_util_anos)

    session.commit()
    session.close()
    return jsonify({"message": "Equipamento atualizado com sucesso!"})

@app.route("/equipamentos/<int:equipamento_id>", methods=["DELETE"])
@token_required
@permission_required("patrimonio")
def delete_equipamento(current_user, equipamento_id):
    session = Session()
    equipamento = session.query(Equipamento).filter_by(id=equipamento_id).first()
    if not equipamento:
        session.close()
        return jsonify({"message": "Equipamento não encontrado"}), 404
    
    session.delete(equipamento)
    session.commit()
	            session.close()
    return jsonify({"message": "Equipamento removido com sucesso!"})

@app.route("/equipamentos/dashboard", methods=["GET"])
@token_required
def get_equipamentos_dashboard(current_user):
    session = Session()
    
    # 1. Equipamentos parados (status 'Fora de Operação/Backup' ou 'Descartado/Baixado')
    equipamentos_parados = session.query(Equipamento).filter(
        Equipamento.status_operacional.in_(['Fora de Operação/Backup', 'Descartado/Baixado'])
    ).count()

    # 2. Equipamentos ativos (status 'Operacional')
    equipamentos_ativos = session.query(Equipamento).filter(
        Equipamento.status_operacional == 'Operacional'
    ).count()

    # 3. Anos desde data de aquisição dividido em intervalos (Ex: 0-1, 1-3, 3-5, >5)
    # Aqui, por simplicidade, vamos calcular a idade em anos
    equipamentos = session.query(Equipamento.data_compra).all()
    hoje = datetime.date.today()
    intervalos_idade = {"0-1 ano": 0, "1-3 anos": 0, "3-5 anos": 0, ">5 anos": 0}
    
    for eq_data_compra in equipamentos:
        idade_anos = (hoje - eq_data_compra[0]).days // 365
        if idade_anos <= 1:
            intervalos_idade["0-1 ano"] += 1
        elif idade_anos <= 3:
            intervalos_idade["1-3 anos"] += 1
        elif idade_anos <= 5:
            intervalos_idade["3-5 anos"] += 1
        else:
            intervalos_idade[">5 anos"] += 1

    # 4. Tipo de equipamento (contagem por tipo)
    tipos_equipamento = session.query(Equipamento.tipo_equipamento, func.count(Equipamento.tipo_equipamento)).group_by(Equipamento.tipo_equipamento).all()
    tipos_equipamento_dict = {tipo: count for tipo, count in tipos_equipamento}

    # 5. Manutenções Preventivas Próximas (próximos 30 dias)
    manutencoes_proximas = session.query(ManutencaoAgendada).filter(
        ManutencaoAgendada.data_agendada <= hoje + datetime.timedelta(days=30),
        ManutencaoAgendada.data_agendada >= hoje,
        ManutencaoAgendada.tipo_manutencao == 'preventiva'
    ).count()

    # 6. Top 5 Equipamentos com Mais Falhas (quantidades de Ordens de Serviço abertas por equipamento)
    from sqlalchemy import func
    top_falhas = session.query(
        Equipamento.nome, func.count(OrdemDeServico.id).label('total_os')
    ).join(OrdemDeServico).group_by(Equipamento.nome).order_by(func.count(OrdemDeServico.id).desc()).limit(5).all()
    
    top_falhas_list = [{"nome": nome, "total_os": total_os} for nome, total_os in top_falhas]

    # 7. Equipamentos Próximos do Fim da Vida Útil (ex: 80% da vida útil atingida)
    equipamentos_vida_util = session.query(Equipamento).filter(Equipamento.vida_util_anos.isnot(None)).all()
    proximos_fim_vida_util = []
    
    for eq in equipamentos_vida_util:
        idade_anos = (hoje - eq.data_compra).days / 365.25
        if eq.vida_util_anos and idade_anos / eq.vida_util_anos >= 0.8:
            proximos_fim_vida_util.append({
                "nome": eq.nome,
                "idade_anos": round(idade_anos, 2),
                "vida_util_anos": eq.vida_util_anos,
                "porcentagem_vida_util": round((idade_anos / eq.vida_util_anos) * 100, 2)
            })

    session.close()
    
    return jsonify({
        "equipamentos_parados": equipamentos_parados,
        "equipamentos_ativos": equipamentos_ativos,
        "intervalos_idade": intervalos_idade,
        "tipos_equipamento": tipos_equipamento_dict,
        "manutencoes_preventivas_proximas": manutencoes_proximas,
        "top_5_falhas": top_falhas_list,
        "proximos_fim_vida_util": proximos_fim_vida_util
    })

# Endpoints para Fornecedores
@app.route("/fornecedores", methods=["POST"])
@token_required
@permission_required("patrimonio")
def add_fornecedor(current_user):
    data = request.json
    session = Session()
    new_fornecedor = Fornecedor(
        nome=data["nome"],
        contato=data.get("contato"),
        telefone=data.get("telefone"),
        email=data.get("email")
    )
    session.add(new_fornecedor)
    session.commit()
    session.close()
    return jsonify({"message": "Fornecedor adicionado com sucesso!"}), 201

@app.route("/fornecedores", methods=["GET"])
@token_required
def get_fornecedores(current_user):
    session = Session()
    fornecedores = session.query(Fornecedor).all()
    output = []
    for f in fornecedores:
        output.append({
            "id": f.id,
            "nome": f.nome,
            "contato": f.contato,
            "telefone": f.telefone,
            "email": f.email
        })
    session.close()
    return jsonify({"fornecedores": output})

@app.route("/fornecedores/<int:fornecedor_id>", methods=["PUT"])
@token_required
@permission_required("patrimonio")
def update_fornecedor(current_user, fornecedor_id):
    data = request.json
    session = Session()
    fornecedor = session.query(Fornecedor).filter_by(id=fornecedor_id).first()
    if not fornecedor:
        session.close()
        return jsonify({"message": "Fornecedor não encontrado"}), 404

    fornecedor.nome = data.get("nome", fornecedor.nome)
    fornecedor.contato = data.get("contato", fornecedor.contato)
    fornecedor.telefone = data.get("telefone", fornecedor.telefone)
    fornecedor.email = data.get("email", fornecedor.email)

    session.commit()
    session.close()
    return jsonify({"message": "Fornecedor atualizado com sucesso!"})

@app.route("/fornecedores/<int:fornecedor_id>", methods=["DELETE"])
@token_required
@permission_required("patrimonio")
def delete_fornecedor(current_user, fornecedor_id):
    session = Session()
    fornecedor = session.query(Fornecedor).filter_by(id=fornecedor_id).first()
    if not fornecedor:
        session.close()
        return jsonify({"message": "Fornecedor não encontrado"}), 404
    
    session.delete(fornecedor)
    session.commit()
    session.close()
    return jsonify({"message": "Fornecedor removido com sucesso!"})

# Endpoints para Ordens de Serviço
@app.route("/ordens-servico", methods=["POST"])
@token_required
def add_ordem_servico(current_user): # Qualquer usuário pode abrir OS
    data = request.json
    session = Session()
    new_ordem = OrdemDeServico(
        equipamento_id=data["equipamento_id"],
        setor=data["setor"],
        descricao_problema=data["descricao_problema"],
        tipo_manutencao=data["tipo_manutencao"],
        responsavel_id=current_user.id, # Quem abriu a OS
        responsavel_tecnico_id=data.get("responsavel_tecnico_id"), # Quem foi designado pelo engenheiro clínico
        prazo_resolucao=datetime.datetime.strptime(data["prazo_resolucao"], "%Y-%m-%d").date() if data.get("prazo_resolucao") else None
    )
    session.add(new_ordem)
    session.commit()
    session.close()
    return jsonify({"message": "Ordem de serviço adicionada com sucesso!"}), 201

@app.route("/ordens-servico", methods=["GET"])
@token_required
def get_ordens_servico(current_user):
    session = Session()
    ordens = session.query(OrdemDeServico).all()
    output = []
    for o in ordens:
        output.append({
            "id": o.id,
            "equipamento_id": o.equipamento_id,
            "setor": o.setor,
            "descricao_problema": o.descricao_problema,
            "data_abertura": o.data_abertura.isoformat(),
            "data_fechamento": o.data_fechamento.isoformat() if o.data_fechamento else None,
            "status": o.status,
            "status_fechamento": o.status_fechamento,
            "tipo_manutencao": o.tipo_manutencao,
            "responsavel_tecnico_id": o.responsavel_tecnico_id,
            "prazo_resolucao": o.prazo_resolucao.isoformat() if o.prazo_resolucao else None,
            "equipamento_nome": o.equipamento.nome,
            "responsavel_nome": o.responsavel.nome_usuario
        })
    session.close()
    return jsonify({"ordens_servico": output})

@app.route("/ordens-servico/<int:ordem_id>", methods=["PUT"])
@token_required
@permission_required("tecnico")
def update_ordem_servico(current_user, ordem_id):
    data = request.json
    session = Session()
    ordem_servico = session.query(OrdemDeServico).filter_by(id=ordem_id).first()
    if not ordem_servico:
        session.close()
        return jsonify({"message": "Ordem de Serviço não encontrada"}), 404

    # Regra de negócio: Apenas administrador ou engenheiro clínico (que é o 'patrimônio' na nossa permissão) pode fechar a OS
    if data.get("status_fechamento") == "fechada" and current_user.permissao not in ['administrador', 'patrimonio']:
        return jsonify({"message": "Permissão insuficiente. Apenas administradores ou engenheiros clínicos podem fechar Ordens de Serviço."}), 403

    ordem_servico.setor = data.get("setor", ordem_servico.setor)
    ordem_servico.descricao_problema = data.get("descricao_problema", ordem_servico.descricao_problema)
    ordem_servico.status = data.get("status", ordem_servico.status)
    ordem_servico.responsavel_tecnico_id = data.get("responsavel_tecnico_id", ordem_servico.responsavel_tecnico_id)
    if data.get("prazo_resolucao"):
        ordem_servico.prazo_resolucao = datetime.datetime.strptime(data["prazo_resolucao"], "%Y-%m-%d").date()
    
    if data.get("status_fechamento") == "fechada" and ordem_servico.status_fechamento != "fechada":
        ordem_servico.data_fechamento = datetime.datetime.utcnow()
    
    ordem_servico.status_fechamento = data.get("status_fechamento", ordem_servico.status_fechamento)

    session.commit()
    session.close()
    return jsonify({"message": "Ordem de Serviço atualizada com sucesso!"})


# Endpoints para Usuários
@app.route("/ordens-servico/dashboard", methods=["GET"])
@token_required
def get_ordens_servico_dashboard(current_user):
    session = Session()
    
    # 1. Ordens de Serviço abertas por equipamento
    os_por_equipamento = session.query(
        Equipamento.nome, func.count(OrdemDeServico.id).label('total_os')
    ).join(OrdemDeServico).filter(OrdemDeServico.status_fechamento != 'fechada').group_by(Equipamento.nome).all()
    os_por_equipamento_list = [{"equipamento": nome, "total_os": total_os} for nome, total_os in os_por_equipamento]
    
    # 2. Tempo de fechamento de ordem de serviço (média)
    # Apenas OS fechadas
    os_fechadas = session.query(OrdemDeServico).filter(OrdemDeServico.status_fechamento == 'fechada', OrdemDeServico.data_fechamento.isnot(None)).all()
    
    tempo_total_fechamento = datetime.timedelta()
    for os in os_fechadas:
        tempo_total_fechamento += os.data_fechamento - os.data_abertura

    media_tempo_fechamento = str(tempo_total_fechamento / len(os_fechadas)) if os_fechadas else "N/A"

    # 3. Tipo de ordem de serviço aberta (contagem por tipo)
    os_por_tipo = session.query(
        OrdemDeServico.tipo_manutencao, func.count(OrdemDeServico.id).label('total_os')
    ).filter(OrdemDeServico.status_fechamento != 'fechada').group_by(OrdemDeServico.tipo_manutencao).all()
    os_por_tipo_dict = {tipo: count for tipo, count in os_por_tipo}

    # 4. Quantidade de ordem de serviço por responsável técnico
    os_por_responsavel = session.query(
        Usuario.nome_usuario, func.count(OrdemDeServico.id).label('total_os')
    ).join(OrdemDeServico, Usuario.id == OrdemDeServico.responsavel_tecnico_id).group_by(Usuario.nome_usuario).all()
    os_por_responsavel_list = [{"responsavel": nome, "total_os": total_os} for nome, total_os in os_por_responsavel]

    # 5. Ordens de serviço atrasadas (prazo_resolucao < hoje e status_fechamento != 'fechada')
    hoje = datetime.date.today()
    os_atrasadas = session.query(OrdemDeServico).filter(
        OrdemDeServico.prazo_resolucao < hoje,
        OrdemDeServico.status_fechamento != 'fechada'
    ).count()

    # 6. Últimas ordens de serviço (as 5 mais recentes)
    ultimas_os = session.query(OrdemDeServico).order_by(OrdemDeServico.data_abertura.desc()).limit(5).all()
    ultimas_os_list = [{
        "id": o.id,
        "equipamento": o.equipamento.nome,
        "status": o.status_fechamento,
        "data_abertura": o.data_abertura.isoformat()
    } for o in ultimas_os]

    # 7. Ordens de serviço fechadas (contagem total)
    os_fechadas_count = len(os_fechadas)

    session.close()
    
    return jsonify({
        "os_por_equipamento": os_por_equipamento_list,
        "media_tempo_fechamento": media_tempo_fechamento,
        "os_por_tipo": os_por_tipo_dict,
        "os_por_responsavel": os_por_responsavel_list,
        "os_atrasadas": os_atrasadas,
        "ultimas_os": ultimas_os_list,
        "os_fechadas_count": os_fechadas_count
    })


@app.route("/usuarios", methods=["GET"])
@token_required
@permission_required("administrador")
def get_usuarios(current_user):
    session = Session()
    usuarios = session.query(Usuario).all()
    output = []
    for u in usuarios:
        output.append({
            "id": u.id,
            "nome_usuario": u.nome_usuario,
            "email": u.email,
            "permissao": u.permissao
        })
    session.close()
    return jsonify({"usuarios": output})

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

