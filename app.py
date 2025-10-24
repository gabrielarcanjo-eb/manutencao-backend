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

from database import (
    ManutencaoAgendada,
    init_db,
    Base,
    Equipamento,
    Fornecedor,
    OrdemDeServico,
    Manutencao,  # ou ManutencaoAgendada se existir
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
            session = Session()
            current_user = session.query(Usuario).filter_by(id=data["user_id"]).first()
            session.close()
        except Exception:
            return jsonify({"message": "Token é inválido!"}), 401
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
    """Cria o primeiro usuário administrador se não existir nenhum."""
    session = Session()
    existing_users = session.query(Usuario).count()
    session.close()

    if existing_users > 0:
        return jsonify({"message": "Já existem usuários no sistema. Use /register para criar novos."}), 403

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


@app.route("/usuarios", methods=["GET"])
@token_required
@permission_required("administrador")
def get_usuarios(current_user):
    session = Session()
    usuarios = session.query(Usuario).all()
    output = [{
        "id": u.id,
        "nome_usuario": u.nome_usuario,
        "email": u.email,
        "permissao": u.permissao
    } for u in usuarios]
    session.close()
    return jsonify({"usuarios": output})


# ------------------------
# EQUIPAMENTOS
# ------------------------
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
    session.close()
    return jsonify({"message": "Equipamento adicionado com sucesso!"}), 201


@app.route("/equipamentos", methods=["GET"])
@token_required
def get_equipamentos(current_user):
    session = Session()
    equipamentos = session.query(Equipamento).options(joinedload(Equipamento.manutencoes_agendadas)).all()
    output = []
    for eq in equipamentos:
        output.append({
            "id": eq.id,
            "nome": eq.nome,
            "marca": eq.marca,
            "fornecedor_id": eq.fornecedor_id,
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
                {"data_agendada": m.data_agendada.isoformat(), "tipo_manutencao": m.tipo_manutencao}
                for m in getattr(eq, "manutencoes_agendadas", [])
            ]
        })
    session.close()
    return jsonify({"equipamentos": output})


# ------------------------
# FORNECEDORES
# ------------------------
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
    output = [{
        "id": f.id,
        "nome": f.nome,
        "contato": f.contato,
        "telefone": f.telefone,
        "email": f.email
    } for f in fornecedores]
    session.close()
    return jsonify({"fornecedores": output})


# ------------------------
# ORDENS DE SERVIÇO
# ------------------------
@app.route("/ordens-servico", methods=["POST"])
@token_required
def add_ordem_servico(current_user):
    data = request.json
    session = Session()
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
    session.close()
    return jsonify({"message": "Ordem de serviço adicionada com sucesso!"}), 201


@app.route("/ordens-servico", methods=["GET"])
@token_required
def get_ordens_servico(current_user):
    session = Session()
    ordens = session.query(OrdemDeServico).options(joinedload(OrdemDeServico.equipamento), joinedload(OrdemDeServico.responsavel)).all()
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
            "prazo_resolucao": o.prazo_resolucao.isoformat() if o.prazo_resolucao else None,
            "equipamento_nome": o.equipamento.nome if o.equipamento else None,
            "responsavel_nome": o.responsavel.nome_usuario if o.responsavel else None
        })
    session.close()
    return jsonify({"ordens_servico": output})


# ------------------------
# INICIALIZAÇÃO
# ------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
