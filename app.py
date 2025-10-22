
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

load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "supersecretkey_default")

# Configuração do CORS
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "http://localhost:5173") # Frontend URL
CORS(app, resources={r"/*": {"origins": CORS_ORIGIN}})


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

@app.route("/register", methods=["POST"])
@token_required
@permission_required("administrador")
def register_user(current_user):
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
    return jsonify({"message": "Usuário registrado com sucesso!"}), 201

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
        total_reparos=data.get("total_reparos", 0.00)
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
            "total_reparos": str(eq.total_reparos)
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
@app.route("/ordens_servico", methods=["POST"])
@token_required
@permission_required("tecnico")
def add_ordem_servico(current_user):
    data = request.json
    session = Session()
    new_os = OrdemDeServico(
        equipamento_id=data["equipamento_id"],
        setor=data["setor"],
        descricao_problema=data["descricao_problema"],
        tipo_manutencao=data["tipo_manutencao"],
        responsavel_id=current_user.id # O usuário logado é o responsável
    )
    session.add(new_os)
    session.commit()
    session.close()
    return jsonify({"message": "Ordem de Serviço criada com sucesso!"}), 201

@app.route("/ordens_servico", methods=["GET"])
@token_required
def get_ordens_servico(current_user):
    session = Session()
    ordens_servico = session.query(OrdemDeServico).all()
    output = []
    for os in ordens_servico:
        output.append({
            "id": os.id,
            "equipamento_id": os.equipamento_id,
            "setor": os.setor,
            "descricao_problema": os.descricao_problema,
            "data_abertura": os.data_abertura.isoformat(),
            "data_fechamento": os.data_fechamento.isoformat() if os.data_fechamento else None,
            "status": os.status,
            "tipo_manutencao": os.tipo_manutencao,
            "custo_total": str(os.custo_total),
            "responsavel_id": os.responsavel_id
        })
    session.close()
    return jsonify({"ordens_servico": output})

@app.route("/ordens_servico/<int:os_id>", methods=["PUT"])
@token_required
@permission_required("tecnico")
def update_ordem_servico(current_user, os_id):
    data = request.json
    session = Session()
    os = session.query(OrdemDeServico).filter_by(id=os_id).first()
    if not os:
        session.close()
        return jsonify({"message": "Ordem de Serviço não encontrada"}), 404

    os.setor = data.get("setor", os.setor)
    os.descricao_problema = data.get("descricao_problema", os.descricao_problema)
    if data.get("data_fechamento"):
        os.data_fechamento = datetime.datetime.strptime(data["data_fechamento"], "%Y-%m-%d %H:%M:%S")
    os.status = data.get("status", os.status)
    os.tipo_manutencao = data.get("tipo_manutencao", os.tipo_manutencao)
    os.custo_total = data.get("custo_total", os.custo_total)
    os.responsavel_id = data.get("responsavel_id", os.responsavel_id)

    session.commit()
    session.close()
    return jsonify({"message": "Ordem de Serviço atualizada com sucesso!"})

@app.route("/ordens_servico/<int:os_id>", methods=["DELETE"])
@token_required
@permission_required("administrador") # Apenas administradores podem deletar OS
def delete_ordem_servico(current_user, os_id):
    session = Session()
    os = session.query(OrdemDeServico).filter_by(id=os_id).first()
    if not os:
        session.close()
        return jsonify({"message": "Ordem de Serviço não encontrada"}), 404
    
    session.delete(os)
    session.commit()
    session.close()
    return jsonify({"message": "Ordem de Serviço removida com sucesso!"})


# Endpoints para Manutenções
@app.route("/manutencoes", methods=["POST"])
@token_required
@permission_required("tecnico")
def add_manutencao(current_user):
    data = request.json
    session = Session()
    new_manutencao = Manutencao(
        ordem_servico_id=data["ordem_servico_id"],
        data_manutencao=datetime.datetime.strptime(data["data_manutencao"], "%Y-%m-%d %H:%M:%S"),
        descricao=data.get("descricao"),
        custo=data.get("custo", 0.00),
        realizada_por=data.get("realizada_por")
    )
    session.add(new_manutencao)
    session.commit()
    session.close()
    return jsonify({"message": "Manutenção adicionada com sucesso!"}), 201

@app.route("/manutencoes", methods=["GET"])
@token_required
def get_manutencoes(current_user):
    session = Session()
    manutencoes = session.query(Manutencao).all()
    output = []
    for m in manutencoes:
        output.append({
            "id": m.id,
            "ordem_servico_id": m.ordem_servico_id,
            "data_manutencao": m.data_manutencao.isoformat(),
            "descricao": m.descricao,
            "custo": str(m.custo),
            "realizada_por": m.realizada_por
        })
    session.close()
    return jsonify({"manutencoes": output})


# Endpoints para Documentos de Patrimônio
@app.route("/documentos_patrimonio", methods=["POST"])
@token_required
@permission_required("patrimonio")
def add_documento_patrimonio(current_user):
    data = request.json
    session = Session()
    new_doc = DocumentoPatrimonio(
        equipamento_id=data["equipamento_id"],
        nome_documento=data["nome_documento"],
        caminho_arquivo=data["caminho_arquivo"],
        tipo_documento=data.get("tipo_documento")
    )
    session.add(new_doc)
    session.commit()
    session.close()
    return jsonify({"message": "Documento de patrimônio adicionado com sucesso!"}), 201

@app.route("/documentos_patrimonio", methods=["GET"])
@token_required
def get_documentos_patrimonio(current_user):
    session = Session()
    documentos = session.query(DocumentoPatrimonio).all()
    output = []
    for d in documentos:
        output.append({
            "id": d.id,
            "equipamento_id": d.equipamento_id,
            "nome_documento": d.nome_documento,
            "caminho_arquivo": d.caminho_arquivo,
            "data_upload": d.data_upload.isoformat(),
            "tipo_documento": d.tipo_documento
        })
    session.close()
    return jsonify({"documentos_patrimonio": output})


# Endpoint para indicadores de obsolescência (exemplo simplificado)
@app.route("/equipamentos/<int:equipamento_id>/obsolescencia", methods=["GET"])
@token_required
def get_obsolescencia(current_user, equipamento_id):
    session = Session()
    equipamento = session.query(Equipamento).filter_by(id=equipamento_id).first()
    if not equipamento:
        session.close()
        return jsonify({"message": "Equipamento não encontrado"}), 404
    
    manutencoes_count = session.query(Manutencao).join(OrdemDeServico).filter(OrdemDeServico.equipamento_id == equipamento_id).count()
    
    session.close()

    # Lógica simplificada para cálculo de obsolescência
    # Pode ser mais complexa com base em idade, valor de mercado, etc.
    obsolescencia_score = 0
    if equipamento.valor_atual and equipamento.valor_compra:
        if equipamento.valor_atual < (equipamento.valor_compra * 0.5):
            obsolescencia_score += 1
    
    if manutencoes_count > 5: # Mais de 5 manutenções indicam alta obsolescência
        obsolescencia_score += 1

    return jsonify({
        "equipamento_id": equipamento.id,
        "nome": equipamento.nome,
        "valor_atual": str(equipamento.valor_atual) if equipamento.valor_atual else "N/A",
        "total_reparos": str(equipamento.total_reparos),
        "manutencoes_realizadas": manutencoes_count,
        "obsolescencia_score": obsolescencia_score,
        "status_obsolescencia": "Alto" if obsolescencia_score >= 2 else ("Médio" if obsolescencia_score == 1 else "Baixo")
    })


# Endpoint para indicadores de eficiência (exemplo simplificado)
@app.route("/indicadores", methods=["GET"])
@token_required
def get_indicadores(current_user):
    session = Session()
    
    equipamentos_adquiridos = session.query(Equipamento).count()
    equipamentos_ativos = session.query(Equipamento).filter_by(ativo=True).count()
    
    manutencoes_corretivas = session.query(Manutencao).join(OrdemDeServico).filter(OrdemDeServico.tipo_manutencao == 'corretiva').count()
    manutencoes_programadas = session.query(Manutencao).join(OrdemDeServico).filter(OrdemDeServico.tipo_manutencao == 'programada').count()
    
    ordens_servico_abertas = session.query(OrdemDeServico).filter(OrdemDeServico.status.in_(['aberta', 'em_andamento'])).count()
    ordens_servico_fechadas = session.query(OrdemDeServico).filter_by(status='fechada').count()

    # Índice de quebra: (COUNT de OS tipo 'corretiva' / COUNT de Equipamentos ativos) * 100
    indice_quebra = (manutencoes_corretivas / equipamentos_ativos * 100) if equipamentos_ativos > 0 else 0

    session.close()

    return jsonify({
        "equipamentos_adquiridos": equipamentos_adquiridos,
        "equipamentos_ativos": equipamentos_ativos,
        "indice_quebra": round(indice_quebra, 2),
        "manutencoes_corretivas": manutencoes_corretivas,
        "manutencoes_programadas": manutencoes_programadas,
        "ordens_servico_abertas": ordens_servico_abertas,
        "ordens_servico_fechadas": ordens_servico_fechadas
    })


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)



from flask_cors import CORS

CORS(app)




if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)



# Endpoints para Documentos de Patrimônio
@app.route("/documentos_patrimonio", methods=["POST"])
@token_required
@permission_required("administrador")
def add_documento_patrimonio(current_user):
    data = request.json
    session = Session()
    new_documento = DocumentoPatrimonio(
        equipamento_id=data["equipamento_id"],
        nome_documento=data["nome_documento"],
        caminho_arquivo=data["caminho_arquivo"],
        tipo_documento=data.get("tipo_documento")
    )
    session.add(new_documento)
    session.commit()
    session.close()
    return jsonify({"message": "Documento de patrimônio adicionado com sucesso!"}), 201

@app.route("/documentos_patrimonio", methods=["GET"])
@token_required
@permission_required("administrador")
def get_documentos_patrimonio(current_user):
    session = Session()
    documentos = session.query(DocumentoPatrimonio).all()
    output = []
    for doc in documentos:
        output.append({
            "id": doc.id,
            "equipamento_id": doc.equipamento_id,
            "nome_documento": doc.nome_documento,
            "caminho_arquivo": doc.caminho_arquivo,
            "tipo_documento": doc.tipo_documento,
            "data_upload": doc.data_upload.isoformat()
        })
    session.close()
    return jsonify({"documentos_patrimonio": output})

