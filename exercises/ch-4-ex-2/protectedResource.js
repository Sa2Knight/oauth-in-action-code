var express = require("express");
var bodyParser = require('body-parser');
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var __ = require('underscore');
var cors = require('cors');

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

var resource = {
  "name": "Protected Resource",
  "description": "This data has been protected by OAuth 2.0"
};

var getAccessToken = function(req, res, next) {
  var inToken = null;
  var auth = req.headers['authorization'];
  if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
    inToken = auth.slice('bearer '.length);
  } else if (req.body && req.body.access_token) {
    inToken = req.body.access_token;
  } else if (req.query && req.query.access_token) {
    inToken = req.query.access_token
  }

  console.log('Incoming token: %s', inToken);
  nosql.one(function(token) {
    if (token.access_token == inToken) {
      return token;
    }
  }, function(err, token) {
    if (token) {
      console.log("We found a matching token: %s", inToken);
    } else {
      console.log('No matching token was found.');
    }
    req.access_token = token;
    next();
    return;
  });
};

var requireAccessToken = function(req, res, next) {
  if (req.access_token) {
    next();
  } else {
    res.status(401).end();
  }
};

var savedWords = [];

/*
 * 保護対象リソースを取得
 * 閲覧権限が必要
 */
app.get('/words', getAccessToken, requireAccessToken, function(req, res) {
  if (__.contains(req.access_token.scope, 'read')) {
    res.json({words: savedWords.join(' '), timestamp: Date.now()});
  } else {
    res.set(
      'WWW-Authenticate',
      'Bearer realm=localhost:9002, error="insufficient_scope", scope="read"'
    );
    res.status(403).end();
  }
});

/*
 * 保護対象リソースを作成
 * 編集権限が必要
 */
app.post('/words', getAccessToken, requireAccessToken, function(req, res) {
  if (__.contains(req.access_token.scope, 'write')) {
    if (req.body.word) {
      savedWords.push(req.body.word);
    }
    res.status(201).end();
  } else {
    res.set(
      'WWW-Authenticate',
      'Bearer realm=localhost:9002, error="insufficient_scope", scope="write"'
    );
    res.status(403).end();
  }
});

/*
 * 保護対象リソースを削除
 * 削除権限が必要
 */
app.delete('/words', getAccessToken, requireAccessToken, function(req, res) {
  if (__.contains(req.access_token.scope, 'delete')) {
    savedWords.pop();
    res.status(204).end();
  } else {
    res.set(
      'WWW-Authenticate',
      'Bearer realm=localhost:9002, error="insufficient_scope", scope="write"'
    );
    res.status(403).end();
  }
});

var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});

