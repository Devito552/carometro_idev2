// Importando bibliotecas necessárias
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
require('dotenv').config();

// Criando a aplicação Express
const app = express();

// Habilitando CORS para permitir requisições de outras origens
app.use(cors());

// Configurando o body-parser para interpretar JSON e dados de formulários
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// Conectando ao banco de dados
db.connect(err => {
    if (err) {
        console.error('Error connecting to the database:', err);
        return;
    }
    console.log('Connected to the MySQL database');
});

// Configurando sessões com um segredo, sem regravar nem inicializar a sessão se não modificada
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Em produção, use 'secure: true' com HTTPS
}));

// Middleware de autenticação para proteger rotas
const authenticateSession = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).send('Acesso negado. Faça login para continuar.');
    }
    next();
};


// Rota de login
app.post('/login', (req, res) => {

    const { cpf, senha } = req.body;

    db.query('SELECT * FROM usuarios WHERE cpf = ?', [cpf], async (err, results) => {
        if (err) return res.status(500).send('Server error');
        if (results.length === 0) return res.status(400).send('Email ou senha incorretos');

        const professor = results[0];

        const senhaCorreta = await bcrypt.compare(senha, professor.senha);
        if (!senhaCorreta) return res.status(400).send('Email ou senha incorretos');

        // Salvar ID do professor na sessão
        req.session.userId = professor.idUsuarios;
        console.log("idUsuarios: ", professor.idUsuarios);
        res.json({ message: 'Login bem-sucedido' });
    });
});


// Rota para lidar com o cadastro de usuários
app.post('/cadastro', async (req, res) => {
    let { nome, email, cpf, senha, celular, cep, logradouro, bairro, cidade, estado, imagem, Tipos_Usuarios_idTipos_Usuarios } = req.body;

    // Remover o hífen do CEP, se presente
    cep = cep.replace(/-/g, '');

    db.query('SELECT cpf FROM usuarios WHERE cpf = ?', [cpf], async (err, results) => {
        if (err) {
            console.error('Erro ao consultar o CPF:', err);
            return res.status(500).json({ message: 'Erro ao verificar o CPF.' });
        }

        if (results.length > 0) {
            return res.status(400).json({ message: 'CPF já cadastrado.' });
        }

        // Hash da senha usando bcrypt
        const hashedPassword = await bcrypt.hash(senha, 10); // O segundo argumento é o custo do hash

        // Inserir novo usuário no banco de dados
        db.query('INSERT INTO usuarios (nome, email, cpf, senha, celular, cep, logradouro, bairro, cidade, estado, Tipos_Usuarios_idTipos_Usuarios, imagem) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [nome, email, cpf, hashedPassword, celular, cep, logradouro, bairro, cidade, estado, Tipos_Usuarios_idTipos_Usuarios, imagem],
            (err, results) => {
                if (err) {
                    console.error('Erro ao inserir usuário:', err);
                    return res.status(500).json({ message: 'Erro ao cadastrar usuário.' });
                }
                console.log('Novo usuário inserido com sucesso:', results.insertId);
                res.status(200).json({ message: 'Usuário cadastrado com sucesso!' });
            });

    });
});

app.post('/cadastro-turma', async (req, res) => {
    let { codigo, descricao, inicio, fim, imagem } = req.body;

    db.query('SELECT codigo FROM turmas WHERE codigo = ?', [codigo], async (err, results) => {
        if (err) {
            console.error('Erro ao consultar o codigo da turma:', err);
            return res.status(500).json({ message: 'Erro ao verificar o codigo da turma.' });
        }

        if (results.length > 0) {
            return res.status(400).json({ message: 'Turma já cadastrada.' });
        }

        // Inserir novo turma no banco de dados
        db.query('INSERT INTO turmas (codigo, descricao, inicio, fim, imagem) VALUES (?, ?, ?, ?, ?)',
            [codigo, descricao, inicio, fim, imagem],
            (err, results) => {
                if (err) {
                    console.error('Erro ao inserir turmas:', err);
                    return res.status(500).json({ message: 'Erro ao cadastrar turmas.' });
                }
                console.log('Turma cadastrada com sucesso:', results.insertId);
                res.status(200).json({ message: 'Turma cadastrado com sucesso!' });
            });
    });
});


// Servindo arquivos estáticos específicos das telas
app.use(express.static('src'));
app.use(express.static(__dirname + '/src'));

app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/src/login.html');
});

app.get('/cadastro', (req, res) => {
    res.sendFile(__dirname + '/src/cadastroUsuarios.html');
});

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/src/index.html');
});

app.get('/cadastro-turma', authenticateSession, (req, res) => {
    res.sendFile(__dirname + '/src/cadastroTurmas.html');
});

app.get('/aluno', authenticateSession, (req, res) => {
    res.sendFile(__dirname + '/src/aluno.html');
});

// Iniciando o servidor na porta especificada no ambiente ou na 5000
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));