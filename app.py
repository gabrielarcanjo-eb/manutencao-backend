import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from sqlalchemy.orm import sessionmaker, joinedload
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
import datetime

# Importe todos os seus modelos e a inicialização do DB
from database import (
    init_db,
    Base,
    Equipamento,
    Fornecedor,
    OrdemDeServico,
    ManutencaoAgendada,  # Garanta que este nome está correto
    Usuario,
    DocumentoPatrimonio
)

load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "supersecretkey_default")

# Configuração do CORS
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "*")
CORS(app, resources={
    r"/*": {
        "origins": CORS_ORIGIN,
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Access-Token"]
    }
})

# Inicializar o banco de dados e criar uma sessão
engine, Session = init_db()


# ------------------------
# AUTENTICAÇÃO E PERMISSÕES
# ------------------------
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
        except Exception:
            return jsonify({"message": "Token é inválido!"}), 401
        
        session = Session()
        try:
            current_user = session.query(Usuario).filter_by(id=data["user_id"]).first()
            if not current_user:
                return jsonify({"message": "Usuário do token não encontrado"}), 401
        except Exception as e:
            return jsonify({"message": f"Erro de banco ao validar token: {e}"}), 500
        finally:
            session.close() 
            
        return f(current_user, *args, **kwargs)
    return decorated


def permission_required(permission_level):
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user, *args, **kwargs):
            if current_user.permissao != permission_level and current_user.permissao != "administrador":
                return jsonify({"message": "Permissão insuficiente"}), 403
            return f(current_user, *args, **kwargs)
        return decorated_function
    return decorator


# ------------------------
# USUÁRIOS E AUTENTICAÇÃO
# ------------------------
@app.route("/init-admin", methods=["POST"])
def init_admin():
    session = Session()
    try:
        existing_users = session.query(Usuario).count()
    except Exception as e:
        session.close()
        return jsonify({"message": f"Erro ao verificar usuários: {e}"}), 500
    
    if existing_users > 0:
        session.close()
        return jsonify({"message": "Já existem usuários no sistema. Use /register para criar novos."}), 403

    # Feche a sessão de contagem antes de abrir uma nova para escrita
    session.close() 
    data = request.json
    if not data or not data.get("nome_usuario") or not data.get("senha"):
        return jsonify({"message": "Nome de usuário e senha são obrigatórios"}), 400

    hashed_password = generate_password_hash(data["senha"], method="pbkdf2:sha256")

    session = Session()
    try:
        admin_user = Usuario(
            nome_usuario=data["nome_usuario"],
            senha_hash=hashed_password,
            email=data.get("email", "admin@clinic.com"),
            permissao="administrador"
        )
        session.add(admin_user)
        session.commit()
        return jsonify({"message": "Usuário administrador criado com sucesso!"}), 201
    except Exception as e:
        session.rollback()
        return jsonify({"message": f"Erro ao criar admin: {e}"}), 500
    finally:
        session.close()


@app.route("/login", methods=["POST"])
def login_user():
    auth = request.json
    if not auth or not auth.get("nome_usuario") or not auth.get("senha"):
        return jsonify({"message": "Credenciais inválidas"}), 401

    session = Session()
    try:
        user = session.query(Usuario).filter_by(nome_usuario=auth["nome_usuario"]).first()
    except Exception as e:
        return jsonify({"message": f"Erro de banco durante o login: {e}"}), 500
    finally:
        session.close()

    if not user or not check_password_hash(user.senha_hash, auth["senha"]):
        return jsonify({"message": "Credenciais inválidas"}), 401

    token = jwt.encode({
        "user_id": user.id,
        "permissao": user.permissao,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=8)
    }, app.config["SECRET_KEY"], algorithm="HS256")

    return jsonify({"token": token, "permissao": user.permissao})


@app.route("/usuarios", methods=["POST"])
@token_required
@permission_required("administrador")
def create_user(current_user):
    data = request.json
    session = Session()
    try:
        hashed_password = generate_password_hash(data["senha"], method="pbkdf2:sha256")
        new_user = Usuario(
            nome_usuario=data["nome_usuario"],
            senha_hash=hashed_password,
            email=data.get("email"),
            permissao=data.get("permissao", "visualizador")
        )
        session.add(new_user)
        session.commit()
        return jsonify({"message": "Usuário criado com sucesso!"}), 201
    except Exception as e:
        session.rollback()
        return jsonify({"message": f"Erro ao criar usuário: {e}"}), 500
    finally:
        session.close()


@app.route("/usuarios", methods=["GET"])
@token_required
@permission_required("administrador")
def get_usuarios(current_user):
    session = Session()
    try:
        usuarios = session.query(Usuario).all()
        output = [{
            "id": u.id,
            "nome_usuario": u.nome_usuario,
            "email": u.email,
            "permissao": u.permissao
        } for u in usuarios]
        return jsonify({"usuarios": output})
    except Exception as e:
        return jsonify({"message": f"Erro ao buscar usuários: {e}"}), 500
    finally:
        session.close()


# ------------------------
# EQUIPAMENTOS
# ------------------------
@app.route("/equipamentos", methods=["POST"])
@token_required
@permission_required("patrimonio")
def add_equipamento(current_user):
    data = request.json
    session = Session()
    try:
        new_equipamento = Equipamento(
            nome=data["nome"],
            marca=data["marca"],
            fornecedor_id=data.get("fornecedor_id"),
            valor_compra=data["valor_compra"],
            data_compra=datetime.datetime.strptime(data["data_compra"], "%Y-%m-%d").date(),
            data_garantia_fim=datetime.datetime.strptime(data["data_garantia_fim"], "%Y-%m-%d").date()
            if data.get("data_garantia_fim") else None,
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
        return jsonify({"message": "Equipamento adicionado com sucesso!"}), 201
    except Exception as e:
        session.rollback()
        return jsonify({"message": f"Erro ao adicionar equipamento: {e}"}), 500
    finally:
        session.close()


@app.route("/equipamentos", methods=["GET"])
@token_required
def get_equipamentos(current_user):
    session = Session()
    try:
        equipamentos = session.query(Equipamento).options(
            joinedload(Equipamento.manutencoes_agendadas), 
            joinedload(Equipamento.fornecedor)
        ).all()
        
        output = []
        for eq in equipamentos:
            output.append({
                "id": eq.id,
                "nome": eq.nome,
                "marca": eq.marca,
                "fornecedor_id": eq.fornecedor_id,
                "fornecedor_nome": eq.fornecedor.nome if eq.fornecedor else None,
                "valor_compra": str(eq.valor_compra),
                "data_compra": eq.data_compra.isoformat() if eq.data_compra else None,
                "data_garantia_fim": eq.data_garantia_fim.isoformat() if eq.data_garantia_fim else None,
                "tipo_posse": eq.tipo_posse,
                "numero_identificacao": eq.numero_identificacao,
                "ativo": eq.ativo,
                "valor_atual": str(eq.valor_atual) if eq.valor_atual else None,
                "total_reparos": str(eq.total_reparos),
                "status_operacional": eq.status_operacional,
                "tipo_equipamento": eq.tipo_equipamento,
                "vida_util_anos": eq.vida_util_anos,
                "manutencoes_agendadas": [
                    {"data_agendada": m.data_agendada.isoformat() if m.data_agendada else None, "tipo_manutencao": m.tipo_manutencao}
                    for m in getattr(eq, "manutencoes_agendadas", [])
                ]
            })
        return jsonify({"equipamentos": output})
    except Exception as e:
        return jsonify({"message": f"Erro ao buscar equipamentos: {e}"}), 500
    finally:
        session.close()

@app.route("/equipamentos/<int:equipamento_id>", methods=["PUT"])
@token_required
@permission_required("patrimonio")
def update_equipamento(current_user, equipamento_id):
    data = request.json
    session = Session()
    try:
        equipamento = session.query(Equipamento).filter_by(id=equipamento_id).first()
        if not equipamento:
            return jsonify({"message": "Equipamento não encontrado"}), 404

        # Atualiza todos os campos vindos do JSON
        for key, value in data.items():
            if key == 'data_compra' and value:
                setattr(equipamento, key, datetime.datetime.strptime(value, "%Y-%m-%d").date())
            elif key == 'data_garantia_fim' and value:
                setattr(equipamento, key, datetime.datetime.strptime(value, "%Y-%m-%d").date())
            elif key in ['valor_compra', 'valor_atual', 'total_reparos', 'vida_util_anos'] and value is None:
                 setattr(equipamento, key, None) # Permite setar nulo
            elif hasattr(equipamento, key):
                setattr(equipamento, key, value)

        session.commit()
        return jsonify({"message": "Equipamento atualizado com sucesso!"})
    except Exception as e:
        session.rollback()
        return jsonify({"message": f"Erro ao atualizar equipamento: {e}"}), 500
    finally:
        session.close()


@app.route("/equipamentos/<int:equipamento_id>", methods=["DELETE"])
@token_required
@permission_required("patrimonio")
def delete_equipamento(current_user, equipamento_id):
    session = Session()
    try:
        equipamento = session.query(Equipamento).filter_by(id=equipamento_id).first()
        if not equipamento:
            return jsonify({"message": "Equipamento não encontrado"}), 404
        
        session.delete(equipamento)
        session.commit()
        return jsonify({"message": "Equipamento removido com sucesso!"})
    except Exception as e:
        session.rollback()
        # Trata erro de Foreign Key (ex: OS ainda aberta para este equipamento)
        return jsonify({"message": f"Erro ao deletar equipamento. Verifique se existem ordens de serviço ou manutenções associadas. Erro: {e}"}), 500
    finally:
        session.close()


@app.route("/equipamentos/dashboard", methods=["GET"])
@token_required
def get_equipamentos_dashboard(current_user):
    session = Session()
    try:
        equipamentos_parados = session.query(Equipamento).filter(
            Equipamento.status_operacional.in_(['Fora de Operação/Backup', 'Descartado/Baixado'])
        ).count()

        equipamentos_ativos = session.query(Equipamento).filter(
            Equipamento.status_operacional == 'Operacional'
        ).count()

        hoje = datetime.date.today()
        
        equipamentos_datas = session.query(Equipamento.data_compra).all()
        intervalos_idade = {"0-1 ano": 0, "1-3 anos": 0, "3-5 anos": 0, ">5 anos": 0}
        
        for eq_data in equipamentos_datas:
            data_compra = eq_data[0]
            if data_compra: # <-- CHECAGEM DE SEGURANÇA
                try:
                    idade_anos = (hoje - data_compra).days // 365
                    if idade_anos <= 1:
                        intervalos_idade["0-1 ano"] += 1
                    elif idade_anos <= 3:
                        intervalos_idade["1-3 anos"] += 1
                    elif idade_anos <= 5:
                        intervalos_idade["3-5 anos"] += 1
                    else:
                        intervalos_idade[">5 anos"] += 1
                except Exception:
                    pass # Ignora datas inválidas

        tipos_equipamento = session.query(Equipamento.tipo_equipamento, func.count(Equipamento.tipo_equipamento)).group_by(Equipamento.tipo_equipamento).all()
        tipos_equipamento_dict = {tipo: count for tipo, count in tipos_equipamento}

        manutencoes_proximas = session.query(ManutencaoAgendada).filter(
            ManutencaoAgendada.data_agendada <= hoje + datetime.timedelta(days=30),
            ManutencaoAgendada.data_agendada >= hoje,
            ManutencaoAgendada.tipo_manutencao == 'preventiva'
        ).count()

        top_falhas = session.query(
            Equipamento.nome, func.count(OrdemDeServico.id).label('total_os')
        ).join(OrdemDeServico).group_by(Equipamento.nome).order_by(func.count(OrdemDeServico.id).desc()).limit(5).all()
        
        top_falhas_list = [{"nome": nome, "total_os": total_os} for nome, total_os in top_falhas]

        equipamentos_vida_util = session.query(Equipamento).filter(
            Equipamento.vida_util_anos.isnot(None), 
            Equipamento.data_compra.isnot(None)
        ).all()
        
        proximos_fim_vida_util = []
        
        for eq in equipamentos_vida_util:
            # CHECAGEM DE SEGURANÇA para evitar divisão por zero ou erro com None
            if eq.vida_util_anos and eq.vida_util_anos > 0 and eq.data_compra:
                try:
                    idade_anos = (hoje - eq.data_compra).days / 365.25
                    if (idade_anos / eq.vida_util_anos) >= 0.8:
                        proximos_fim_vida_util.append({
                            "nome": eq.nome,
                            "idade_anos": round(idade_anos, 2),
                            "vida_util_anos": eq.vida_util_anos,
                            "porcentagem_vida_util": round((idade_anos / eq.vida_util_anos) * 100, 2)
                        })
                except Exception:
                    pass # Ignora falhas de cálculo

        return jsonify({
            "equipamentos_parados": equipamentos_parados,
            "equipamentos_ativos": equipamentos_ativos,
            "intervalos_idade": intervalos_idade,
            "tipos_equipamento": tipos_equipamento_dict,
            "manutencoes_preventivas_proximas": manutencoes_proximas,
            "top_5_falhas": top_falhas_list,
            "proximos_fim_vida_util": proximos_fim_vida_util
        })

    except Exception as e:
        return jsonify({"message": f"Erro ao buscar dashboard de equipamentos: {e}"}), 500
    finally:
        session.close()

# ------------------------
# FORNECEDORES
# ------------------------
@app.route("/fornecedores", methods=["POST"])
@token_required
@permission_required("patrimonio")
def add_fornecedor(current_user):
    data = request.json
    session = Session()
    try:
        new_fornecedor = Fornecedor(
            nome=data["nome"],
            contato=data.get("contato"),
            telefone=data.get("telefone"),
            email=data.get("email")
        )
        session.add(new_fornecedor)
        session.commit()
        return jsonify({"message": "Fornecedor adicionado com sucesso!"}), 201
    except Exception as e:
        session.rollback()
        return jsonify({"message": f"Erro ao adicionar fornecedor: {e}"}), 500
    finally:
        session.close()


@app.route("/fornecedores", methods=["GET"])
@token_required
def get_fornecedores(current_user):
    session = Session()
    try:
        fornecedores = session.query(Fornecedor).all()
        output = [{
            "id": f.id,
            "nome": f.nome,
            "contato": f.contato,
            "telefone": f.telefone,
            "email": f.email
        } for f in fornecedores]
        return jsonify({"fornecedores": output})
    except Exception as e:
        return jsonify({"message": f"Erro ao buscar fornecedores: {e}"}), 500
    finally:
        session.close()

@app.route("/fornecedores/<int:fornecedor_id>", methods=["PUT"])
@token_required
@permission_required("patrimonio")
def update_fornecedor(current_user, fornecedor_id):
    data = request.json
    session = Session()
    try:
        fornecedor = session.query(Fornecedor).filter_by(id=fornecedor_id).first()
        if not fornecedor:
            return jsonify({"message": "Fornecedor não encontrado"}), 404

        fornecedor.nome = data.get("nome", fornecedor.nome)
        fornecedor.contato = data.get("contato", fornecedor.contato)
        fornecedor.telefone = data.get("telefone", fornecedor.telefone)
        fornecedor.email = data.get("email", fornecedor.email)

        session.commit()
        return jsonify({"message": "Fornecedor atualizado com sucesso!"})
    except Exception as e:
        session.rollback()
        return jsonify({"message": f"Erro ao atualizar fornecedor: {e}"}), 500
    finally:
        session.close()


@app.route("/fornecedores/<int:fornecedor_id>", methods=["DELETE"])
@token_required
@permission_required("patrimonio")
def delete_fornecedor(current_user, fornecedor_id):
    session = Session()
    try:
        fornecedor = session.query(Fornecedor).filter_by(id=fornecedor_id).first()
        if not fornecedor:
            return jsonify({"message": "Fornecedor não encontrado"}), 404
        
        session.delete(fornecedor)
        session.commit()
        return jsonify({"message": "Fornecedor removido com sucesso!"})
    except Exception as e:
        session.rollback()
        return jsonify({"message": f"Erro ao deletar fornecedor: {e}"}), 500
    finally:
        session.close()

# ------------------------
# ORDENS DE SERVIÇO
# ------------------------
@app.route("/ordens-servico", methods=["POST"])
@token_required
def add_ordem_servico(current_user):
    data = request.json
    session = Session()
    try:
        new_ordem = OrdemDeServico(
            equipamento_id=data["equipamento_id"],
            setor=data["setor"],
            descricao_problema=data["descricao_problema"],
            tipo_manutencao=data["tipo_manutencao"],
            responsavel_id=current_user.id,
            responsavel_tecnico_id=data.get("responsavel_tecnico_id"),
            prazo_resolucao=datetime.datetime.strptime(data["prazo_resolucao"], "%Y-%m-%d").date()
            if data.get("prazo_resolucao") else None
        )
        session.add(new_ordem)
        session.commit()
        return jsonify({"message": "Ordem de serviço adicionada com sucesso!"}), 201
    except Exception as e:
        session.rollback()
        return jsonify({"message": f"Erro ao adicionar ordem de serviço: {e}"}), 500
    finally:
        session.close()


@app.route("/ordens-servico", methods=["GET"])
@token_required
def get_ordens_servico(current_user):
    session = Session()
    try:
        ordens = session.query(OrdemDeServico).options(
            joinedload(OrdemDeServico.equipamento), 
            joinedload(OrdemDeServico.responsavel), 
            joinedload(OrdemDeServico.responsavel_tecnico)
        ).all()
        
        output = []
        for o in ordens:
            output.append({
                "id": o.id,
                "equipamento_id": o.equipamento_id,
                "setor": o.setor,
                "descricao_problema": o.descricao_problema,
                "data_abertura": o.data_abertura.isoformat() if o.data_abertura else None,
                "data_fechamento": o.data_fechamento.isoformat() if o.data_fechamento else None,
                "status": o.status,
                "status_fechamento": o.status_fechamento,
                "tipo_manutencao": o.tipo_manutencao,
                "responsavel_tecnico_id": o.responsavel_tecnico_id,
                "responsavel_tecnico_nome": o.responsavel_tecnico.nome_usuario if o.responsavel_tecnico else None,
                "prazo_resolucao": o.prazo_resolucao.isoformat() if o.prazo_resolucao else None,
                "equipamento_nome": o.equipamento.nome if o.equipamento else None,
                "responsavel_nome": o.responsavel.nome_usuario if o.responsavel else None
            })
        return jsonify({"ordens_servico": output})
    except Exception as e:
        return jsonify({"message": f"Erro ao buscar ordens de serviço: {e}"}), 500
    finally:
        session.close()


@app.route("/ordens-servico/<int:ordem_id>", methods=["PUT"])
@token_required
# Removida permissão específica da rota, pois o código já trata isso
def update_ordem_servico(current_user, ordem_id):
    data = request.json
    session = Session()
    try:
        ordem_servico = session.query(OrdemDeServico).filter_by(id=ordem_id).first()
        if not ordem_servico:
            return jsonify({"message": "Ordem de Serviço não encontrada"}), 404

        # Regra de negócio para fechar OS
        if data.get("status_fechamento") == "fechada":
             if current_user.permissao not in ['administrador', 'patrimonio']:
                return jsonify({"message": "Permissão insuficiente. Apenas administradores ou engenheiros clínicos podem fechar Ordens de Serviço."}), 403
             # Se está fechando, atualiza data de fechamento
             if ordem_servico.status_fechamento != "fechada":
                ordem_servico.data_fechamento = datetime.datetime.utcnow()
        
        # Usuários 'tecnico' podem editar, exceto fechar a OS
        if current_user.permissao not in ['administrador', 'patrimonio', 'tecnico']:
             return jsonify({"message": "Permissão insuficiente para editar OS."}), 403

        # Atualiza campos
        ordem_servico.setor = data.get("setor", ordem_servico.setor)
        ordem_servico.descricao_problema = data.get("descricao_problema", ordem_servico.descricao_problema)
        ordem_servico.status = data.get("status", ordem_servico.status)
        ordem_servico.responsavel_tecnico_id = data.get("responsavel_tecnico_id", ordem_servico.responsavel_tecnico_id)
        ordem_servico.status_fechamento = data.get("status_fechamento", ordem_servico.status_fechamento)
        
        if data.get("prazo_resolucao"):
            ordem_servico.prazo_resolucao = datetime.datetime.strptime(data["prazo_resolucao"], "%Y-%m-%d").date()
        else:
             ordem_servico.prazo_resolucao = None

        session.commit()
        return jsonify({"message": "Ordem de Serviço atualizada com sucesso!"})
    except Exception as e:
        session.rollback()
        return jsonify({"message": f"Erro ao atualizar OS: {e}"}), 500
    finally:
        session.close()


@app.route("/ordens-servico/dashboard", methods=["GET"])
@token_required
def get_ordens_servico_dashboard(current_user):
    session = Session()
    try:
        # 1. OS abertas por equipamento
        os_por_equipamento = session.query(
            Equipamento.nome, func.count(OrdemDeServico.id).label('total_os')
        ).join(OrdemDeServico).filter(OrdemDeServico.status_fechamento != 'fechada').group_by(Equipamento.nome).all()
        os_por_equipamento_list = [{"equipamento": nome, "total_os": total_os} for nome, total_os in os_por_equipamento]
        
        # 2. Tempo médio de fechamento
        os_fechadas = session.query(OrdemDeServico).filter(
            OrdemDeServico.status_fechamento == 'fechada', 
            OrdemDeServico.data_fechamento.isnot(None),
            OrdemDeServico.data_abertura.isnot(None) # Garante que ambos existam
        ).all()
        
        media_tempo_fechamento = "N/A"
        if os_fechadas:
            tempo_total_fechamento = datetime.timedelta()
            for os in os_fechadas:
                tempo_total_fechamento += os.data_fechamento - os.data_abertura
            if len(os_fechadas) > 0:
                 media_tempo_dias = (tempo_total_fechamento / len(os_fechadas)).days
                 media_tempo_fechamento = f"{media_tempo_dias} dias"

        # 3. Tipo de OS aberta
        os_por_tipo = session.query(
            OrdemDeServico.tipo_manutencao, func.count(OrdemDeServico.id).label('total_os')
        ).filter(OrdemDeServico.status_fechamento != 'fechada').group_by(OrdemDeServico.tipo_manutencao).all()
        os_por_tipo_dict = {tipo: count for tipo, count in os_por_tipo}

        # 4. OS por responsável técnico
        os_por_responsavel = session.query(
            Usuario.nome_usuario, func.count(OrdemDeServico.id).label('total_os')
        ).join(OrdemDeServico, Usuario.id == OrdemDeServico.responsavel_tecnico_id).group_by(Usuario.nome_usuario).all()
        os_por_responsavel_list = [{"responsavel": nome, "total_os": total_os} for nome, total_os in os_por_responsavel]

        # 5. OS atrasadas
        hoje = datetime.date.today()
        os_atrasadas = session.query(OrdemDeServico).filter(
            OrdemDeServico.prazo_resolucao < hoje,
            OrdemDeServico.prazo_resolucao.isnot(None), # Garante que prazo exista
            OrdemDeServico.status_fechamento != 'fechada'
        ).count()

        # 6. Últimas OS
        ultimas_os = session.query(OrdemDeServico).options(
            joinedload(OrdemDeServico.equipamento) # Carrega equipamento
        ).order_by(OrdemDeServico.data_abertura.desc()).limit(5).all()
        
        ultimas_os_list = []
        for o in ultimas_os:
            ultimas_os_list.append({
                "id": o.id,
                "equipamento": o.equipamento.nome if o.equipamento else "N/A", # <-- CORRIGIDO
                "status": o.status_fechamento,
                "data_abertura": o.data_abertura.isoformat() if o.data_abertura else None # <-- CORRIGIDO
            })

        # 7. OS fechadas (contagem)
        os_fechadas_count = len(os_fechadas)

        return jsonify({
            "os_por_equipamento": os_por_equipamento_list,
            "media_tempo_fechamento": media_tempo_fechamento,
            "os_por_tipo": os_por_tipo_dict,
            "os_por_responsavel": os_por_responsavel_list,
            "os_atrasadas": os_atrasadas,
            "ultimas_os": ultimas_os_list,
            "os_fechadas_count": os_fechadas_count
        })
    except Exception as e:
        return jsonify({"message": f"Erro ao buscar dashboard de OS: {e}"}), 500
    finally:
        session.close()


# ------------------------
# INICIALIZAÇÃO
# ------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True) # Adicionado debug=True para facilitar
