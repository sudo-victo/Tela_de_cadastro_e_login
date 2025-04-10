//Importações:
const Express = require("express");
const app = Express();
app.use(Express.json());
app.use(Express.urlencoded({ extended: true }));
app.use(Express.static("public"));

const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

const bcrypt = require("bcrypt");
const saltRounds = 10;

//Rotas:

//rota GET para cadastro
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/cadastro.html");
});

//Rota POST para cadastro
app.post("/cadastro", async (req, res) => {
  const { nome, email, senha, confirmarSenha } = req.body;

  if (!nome || !email || !senha || !confirmarSenha) {
    return res.status(400).json({ erro: "Todos os campos são obrigatórios." });
  }

  const emailValido =
    /^[^\s@]+@(gmail\.com|hotmail\.com|yahoo\.com|outlook\.com|live\.com|com\.br|net|org|edu|gov|br)$/i.test(
      email
    ); //Regex para emails válidos
  if (!emailValido) {
    return res.status(400).json({ erro: "Email inválido." });
  }

  if (senha !== confirmarSenha) {
    return res.status(400).json({ erro: "As senhas não coincidem." });
  }

  try {
    const usuarioExistente = await prisma.usuarios.findUnique({
      where: { email }, //O Prisma vai buscar no banco de dados
    });

    if (usuarioExistente) {
      return res.status(409).json({ erro: "E-mail já cadastrado." }); //Se o usuario ja estiver cadastrado:
    }

    //Criptografa a senha antes de salvar no banco
    const senhaCriptografada = await bcrypt.hash(senha, saltRounds);

    const novoUsuario = await prisma.usuarios.create({
      data: {
        nome,
        email,
        senha: senhaCriptografada, //  Senha criptografada
        data_criacao: new Date(),
      },
    });

    res.status(201).json({
      mensagem: "Usuário cadastrado com sucesso!",
      usuario: novoUsuario,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao salvar no banco." });
  }
});

// Rota GET para o login
app.get("/login", async (req, res) => {
  res.sendFile(__dirname + "/public/login.html");
});

// Rota POST para o login verificando se o usuário existe e se a senha está correta
app.post("/login", async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ erro: "E-mail e senha são obrigatórios." });
  }

  try {
    const usuario = await prisma.usuarios.findUnique({
      where: { email }, //O Prisma vai buscar no banco de dados
    });

    if (!usuario) {
      //  Aqui caso o usuario não esteja no banco de dados, ele retorna um erro
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    const senhaCorreta = await bcrypt.compare(senha, usuario.senha);

    if (!senhaCorreta) {
      //  Só chega aqui se o usuário existir
      return res.status(401).json({ erro: "Usuário ou senha incorreto." });
    }

    res.status(200).json({ mensagem: "Login realizado com sucesso!", usuario });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao processar o login." });
  }
});

//Servidor ligado na porta 8081
app.listen(8081, function () {
  console.log("Servidor rodando na URL: http://localhost:8081");
});