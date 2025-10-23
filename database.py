
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Date, DateTime, DECIMAL, Boolean, Enum, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime

Base = declarative_base()

class Fornecedor(Base):
    __tablename__ = 'fornecedores'
    id = Column(Integer, primary_key=True, autoincrement=True)
    nome = Column(String(255), nullable=False)
    contato = Column(String(255))
    telefone = Column(String(20))
    email = Column(String(255))

    equipamentos = relationship('Equipamento', back_populates='fornecedor')

class Equipamento(Base):
    __tablename__ = 'equipamentos'
    id = Column(Integer, primary_key=True, autoincrement=True)
    nome = Column(String(255), nullable=False)
    marca = Column(String(255), nullable=False)
    fornecedor_id = Column(Integer, ForeignKey('fornecedores.id'))
    valor_compra = Column(DECIMAL(10, 2), nullable=False)
    data_compra = Column(Date, nullable=False)
    data_garantia_fim = Column(Date)
    tipo_posse = Column(Enum('comodato', 'proprio', name='tipo_posse_enum'), nullable=False)
    numero_identificacao = Column(String(255), unique=True, nullable=False)
    ativo = Column(Boolean, default=True)
    
    # Novos campos para Equipamento
    status_operacional = Column(Enum('Operacional', 'Em Manutenção Corretiva', 'Em Manutenção Preventiva', 'Em Calibração', 'Fora de Operação/Backup', 'Descartado/Baixado', name='status_operacional_enum'), default='Operacional', nullable=False)
    tipo_equipamento = Column(String(100))
    # Calendário de Manutenções: será uma relação com a tabela Manutencao
    vida_util_anos = Column(Integer) # Tempo de vida útil em anos
    valor_atual = Column(DECIMAL(10, 2))
    total_reparos = Column(DECIMAL(10, 2), default=0.00)

    fornecedor = relationship('Fornecedor', back_populates='equipamentos')
    ordens_servico = relationship('OrdemDeServico', back_populates='equipamento')
    documentos = relationship('DocumentoPatrimonio', back_populates='equipamento')
    manutencoes_agendadas = relationship('ManutencaoAgendada', back_populates='equipamento')

class Usuario(Base):
    __tablename__ = 'usuarios'
    id = Column(Integer, primary_key=True, autoincrement=True)
    nome_usuario = Column(String(255), unique=True, nullable=False)
    senha_hash = Column(String(255), nullable=False)
    email = Column(String(255), unique=True)
    permissao = Column(Enum('administrador', 'patrimonio', 'tecnico', 'visualizador', name='permissao_enum'), default='visualizador')

    ordens_servico_responsavel = relationship('OrdemDeServico', foreign_keys='OrdemDeServico.responsavel_id', back_populates='responsavel')
    ordens_servico_responsavel_tecnico = relationship('OrdemDeServico', foreign_keys='OrdemDeServico.responsavel_tecnico_id', back_populates='responsavel_tecnico')

class OrdemDeServico(Base):
    __tablename__ = 'ordens_de_servico'
    id = Column(Integer, primary_key=True, autoincrement=True)
    equipamento_id = Column(Integer, ForeignKey('equipamentos.id'))
    setor = Column(String(255), nullable=False)
    descricao_problema = Column(String, nullable=False)
    data_abertura = Column(DateTime, default=datetime.now)
    # Novos campos para Ordem de Serviço
    responsavel_tecnico_id = Column(Integer, ForeignKey('usuarios.id')) # Engenheiro Clínico que indica o responsável técnico
    prazo_resolucao = Column(Date) # Prazo para resolução da OS
    status_fechamento = Column(Enum('aberta', 'em_andamento', 'fechada', 'cancelada', name='status_fechamento_enum'), default='aberta') # Status de fechamento
    
    data_fechamento = Column(DateTime)
    status = Column(Enum('aberta', 'em_andamento', 'fechada', 'cancelada', name='status_enum'), default='aberta')
    tipo_manutencao = Column(Enum('corretiva', 'programada', name='tipo_manutencao_enum'), nullable=False)
    custo_total = Column(DECIMAL(10, 2), default=0.00)
    responsavel_id = Column(Integer, ForeignKey('usuarios.id')) # Responsável pela execução da OS

    equipamento = relationship('Equipamento', back_populates='ordens_servico')
    responsavel = relationship('Usuario', foreign_keys=[responsavel_id], back_populates='ordens_servico_responsavel')
    responsavel_tecnico = relationship('Usuario', foreign_keys=[responsavel_tecnico_id], back_populates='ordens_servico_responsavel_tecnico')
    manutencoes = relationship('Manutencao', back_populates='ordem_servico')

class Manutencao(Base):
    __tablename__ = 'manutencoes'
    id = Column(Integer, primary_key=True, autoincrement=True)
    ordem_servico_id = Column(Integer, ForeignKey('ordens_de_servico.id'))
    data_manutencao = Column(DateTime, nullable=False)
    descricao = Column(String)
    custo = Column(DECIMAL(10, 2), default=0.00)
    realizada_por = Column(String(255))

    ordem_servico = relationship('OrdemDeServico', back_populates='manutencoes')

class ManutencaoAgendada(Base):
    __tablename__ = 'manutencoes_agendadas'
    id = Column(Integer, primary_key=True, autoincrement=True)
    equipamento_id = Column(Integer, ForeignKey('equipamentos.id'))
    data_agendada = Column(Date, nullable=False)
    tipo_manutencao = Column(Enum('preventiva', 'calibracao', name='tipo_manutencao_agendada_enum'), nullable=False)
    descricao = Column(String)

    equipamento = relationship('Equipamento', back_populates='manutencoes_agendadas')

class DocumentoPatrimonio(Base):
    __tablename__ = 'documentos_patrimonio'
    id = Column(Integer, primary_key=True, autoincrement=True)
    equipamento_id = Column(Integer, ForeignKey('equipamentos.id'))
    nome_documento = Column(String(255), nullable=False)
    caminho_arquivo = Column(String(255), nullable=False)
    data_upload = Column(DateTime, default=datetime.now)
    tipo_documento = Column(String(100))

    equipamento = relationship('Equipamento', back_populates='documentos')

def init_db():
    load_dotenv()
    database_url = os.environ.get("DATABASE_URL", "sqlite:///./clinic_management.db")
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return engine, Session

if __name__ == '__main__':
    engine, Session = init_db()
    print("Banco de dados inicializado com sucesso!")

