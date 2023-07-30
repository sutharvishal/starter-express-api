// require('dotenv').config();
const fs = require('fs');
const https = require('https');
const express = require('express');
const app = express();
const session = require('express-session');
const cors = require('cors')

const { microsoftAuthRouter } = require('./routes');


const key = fs.readFileSync('./ssl/key.pem');
const cert = fs.readFileSync('./ssl/cert.pem');

app.use(session({
  secret: 'sdsfddfsffddslfsdfjdsdfsljrsdfosddffwusdfdffrowedsfttru',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true }
}))

app.use(cors());

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// set the view engine to ejs
app.set('view engine', 'ejs');

app.use('/oauth/microsoft', microsoftAuthRouter);

const server = https.createServer({key: key, cert: cert }, app);

server.listen(5000, () => { console.log('listening on 5000') });