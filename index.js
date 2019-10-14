const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;

  // Validate the user
  if (user) {

  // Hash the password
    const hash = bcrypt.hashSync(user.password, 8);

  // Override the password with the hash
    user.password = hash;
  
  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
  } else {
    res.status(400).json({ message: 'Please provide a valid username' })
  }
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  if (username && password) {
  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
  } else {
      res.status(400).json({ message: 'Please provide valid credentials' })
  }
});

server.get('/api/users', protected, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.get('/hash', (req, res) => {
  // Read a password from the authorization header (must be explicitly stated within Insomnia Header)
  const password = req.headers.authorization;

  if (password) {
    const hash = bcrypt.hashSync(password, 8); // number makes cracking exponentially more difficult, 14 is best practice...
                                             // ...but also slows down server, so use smaller numbers for testing purposes

    res.status(200).json({ hash }); // no {} would return the same info as a plain string.
  } else {
    res.status(400).json({ message: 'Please provide credentials' })
  }

  // // read a password from the Authorization header
  // // return an object with the password hashed using bcryptjs
  // // { hash: '970(&(:OHKJHIY*HJKH(*^)*&YLKJBLKJGHIUGH(*P' }
});

function protected (req, res, next) {
  const { username, password } = req.headers;

  if (username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          next();
        } else {
          res.status(401).json({ message: 'Invalid Credentials' });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
    } else {
        res.status(400).json({ message: 'Please provide valid credentials' })
    }
  };

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
