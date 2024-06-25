const express = require('express')
const app = express()
const fs = require('fs')
const jwt = require('jsonwebtoken')

const usersFile = 'users.json'
const secretKey = 'мойСекретныйКлюч'
const tokenExpirationTime = 10 // 10 минут
const refreshTokenExpirationTime = 86400 // 24 часа

app.use(express.json())

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*")
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
    next()
})

// Загрузка пользователей из файла
let users = []
fs.readFile(usersFile, (err, data) => {
  if (err) {
    console.error(err)
  } else {
    users = JSON.parse(data)
  }
})

// Авторизация пользователя
app.post('/login', (req, res) => {
  const { username, password } = req.body
  const user = users.find((user) => user.username === username && user.password === password)
  if (!user) {
    res.status(401).send({ message: 'Неверный логин или пароль' })
  } else {
    const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: tokenExpirationTime })
    const refreshToken = jwt.sign({ userId: user.id }, secretKey, { expiresIn: refreshTokenExpirationTime })
    res.send({ token, refreshToken })
  }
})

// Аутентификация пользователя
app.post('/auth', (req, res) => {
  const { token, refreshToken } = req.body
  try {
    const decodedToken = jwt.verify(token, secretKey)
    const user = users.find((user) => user.id === decodedToken.userId)
    if (user) {
      res.send({ user })
    } else {
      res.status(401).send({ message: 'Неверный токен' })
    }
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      try {
        const decodedRefreshToken = jwt.verify(refreshToken, secretKey)
        const user = users.find((user) => user.id === decodedRefreshToken.userId)
        if (user) {
          const newToken = jwt.sign({ userId: user.id }, secretKey, { expiresIn: tokenExpirationTime })
          res.send({ token: newToken, user })
        } else {
          res.status(401).send({ message: 'Неверный токен обновления' })
        }
      } catch (err) {
        res.status(401).send({ message: 'Токен и токен обновления недействительны' })
      }
    } else {
      res.status(401).send({ message: 'Неверный токен' })
    }
  }
})

// Получение списка всех пользователей
app.get('/users', (req, res) => {
  res.send(users)
})

app.post('/register', (req, res) => {
  const { username, password, email, name, lastName, age, gender } = req.body

  if (!username || !password || !email || !name || !lastName || !age || !gender) {
    res.status(400).send({ message: 'Please fill in all required fields' })
    return
  }

  const existingUser = users.find((user) => user.username === username || user.email === email)
  if (existingUser) {
    if (existingUser.username === username) {
      res.status(400).send({ message: 'Username is already taken' })
    } else if (existingUser.email === email) {
      res.status(400).send({ message: 'Email is already in use' })
    }
  } else {
    const user = {
      id: users.length + 1,
      username,
      password,
      email,
      name,
      lastName,
      age,
      gender
    }
    users.push(user)
    fs.writeFile(usersFile, JSON.stringify(users), (err) => {
      if (err) {
        console.error(err)
        res.status(500).send({ message: 'Error registering user' })
      } else {
        res.send({ message: 'User registered successfully' })
      }
    })
  }
})

app.listen(3000, () => {
  console.log('Сервер запущен на порту 3000')
})