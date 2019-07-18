var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
  authorizationEndpoint: 'http://localhost:9001/authorize',
  tokenEndpoint: 'http://localhost:9001/token'
};

/**
 * OAuthクライアントの一覧を管理する
 * 実際は動的生成しながらRDBなどで永続化する
 */
var clients = [
  {
    "client_id": "oauth-client-1",
    "client_secret": "oauth-client-secret-1",
    "redirect_urls": ["http://localhost:9000/callback"]
  }
];

/**
 * 認可コードの一覧
 * 実際はRDBなどで永続化
 */
var codes = {};

/**
 * 認可エンドポイントへのリクエストをステートレスにするための変数
 * 実際はRDBだどでセッション管理する
 */
var requests = {};

/**
 * クライアントIDをもとにクライアントを取得する
 * 実際はRDSなどに対してクエリを発行するやつ
 */
var getClient = function(clientId) {
  return __.find(clients, function(client) { return client.client_id == clientId; });
};

/**
 * 認可エンドポイント
 * フロントチャネルで利用
 */
app.get("/authorize", function(req, res){
  var client = getClient(req.query.client_id);

  // 未知のクライアントだった場合、エラーページに誘導
  if (!client) {
    res.render('error', { error: 'お前クライアントのユーザちゃうやろ' });
    return;
  }

  // 認可のためのセッション管理
  var reqid = randomstring.generate(8);
  requests[reqid] = req.query

  // ユーザに権限委譲の承認をさせるための画面を描画
  res.render('approve', { client: client, reqid: reqid });
});

/**
 * 権限委譲の内容を伝えるエンドポイント
 * フロントチャネルで利用
 */
app.post('/approve', function(req, res) {
  var redirect_url;
  var reqid = req.body.reqid;
  var query = requests[reqid];
  delete requests[reqid];

  // CSRF対策
  if (!query) {
    res.render('error', { error: 'お前本人ちゃうやろ' });
    return;
  }

  // ユーザが権限委譲を承認した場合
  if (req.body.approve) {
    // 認可コードによる付与方式が要求された場合
    // クライアントに認可コードを伝えるためにリダイレクト
    if (query.response_type == 'code') {
      var code = randomstring.generate(8);
      codes[code] = { request: query };
      redirect_url = buildUrl(query.redirect_uri, { code: code, state: query.state });
    }
    // 付与方式が不正の場合はエラーを通知する
    else {
      redirect_url = buildUrl(query.redirect_uri, { error: '付与方式が不正です' });
    }
  }
  // ユーザが権限委譲を拒否した場合
  // リダイレクトURLに、エラーの旨を伝える
  else {
    redirect_url = buildUrl(query.redirect_uri, { error: '拒否られましたわ' });
  }

  // 確定したURLにリダイレクト
  console.log(redirect_url);
  res.redirect(redirect_url);
});

/**
 * トークンエンドポイント
 * バックチャンネルで利用
 */
app.post("/token", function(req, res){
  var auth = req.headers['authorization']

  // リクエストヘッダーにクレデンシャルが含まれてる場合の抽出
  if (auth) {
    var clientCredentials = decodeClientCredentials(auth);
    var clientId = clientCredentials.id;
    var clientSecret = clientCredentials.secret;
  }

  // リクエストボディにクレデンシャルが含まれてる場合の抽出
  if (req.body.client_id) {
    if (clientId) {
      res.status(401).json({ error: 'クレデンシャル二重に送ってるよ' });
    }

    var clientId = req.body.client_id;
    var clientSecret = req.body.client_secret;
  }

  // クレデンシャルをもとにクライアントを特定
  var client = getClient(clientId);
  if (!client) {
    res.status(401).json({ error: 'クライアントが見つからんぞ' });
    return;
  }
  if (client.client_secret != clientSecret) {
    res.status(401).json({ error: '偽物では？' });
    return;
  }

  // 認可コードによる付与方式しか実装してないので、そうでない場合エラー
  if (req.body.grant_type != 'authorization_code') {
    res.status(400).json({ error: '認可コードしか認めないよ' });
    return;
  }

  // 認可コードが正しくない場合もエラー
  var code = codes[req.body.code];
  if (!code) {
    res.status(400).json({ error: '認可コードが違うぞ' });
    return;
  }

  // 認可コードと紐付いてるクライアントと一致してなくてもエラー
  delete codes[req.body.code];
  if (code.request.client_id != clientId) {
    res.status(400).json({ error: '認可コードの持ち主ちゃうやん' });
    return;
  }

  // 流石に信頼して、アクセストークンを発行して永続化
  var access_token = randomstring.generate();
  nosql.insert({ access_token: access_token, client_id: clientId });

  // トークンとその使い方をクライアントに伝える
  var token_response = {
    access_token: access_token,
    token_type: 'Bearer'
  };
  res.status(200).json(token_response);
});

app.get('/', function(req, res) {
  res.render('index', {clients: clients, authServer: authServer});
});

var buildUrl = function(base, options, hash) {
  var newUrl = url.parse(base, true);
  delete newUrl.search;
  if (!newUrl.query) {
    newUrl.query = {};
  }
  __.each(options, function(value, key, list) {
    newUrl.query[key] = value;
  });
  if (hash) {
    newUrl.hash = hash;
  }

  return url.format(newUrl);
};


/**
 * Basic認証でエンコードされたクレデンシャルをデコードする
 */
var decodeClientCredentials = function(auth) {
  var clientCredentials = new Buffer(auth.slice('basic '.length), 'base64').toString().split(':');
  var clientId = querystring.unescape(clientCredentials[0]);
  var clientSecret = querystring.unescape(clientCredentials[1]);
  return { id: clientId, secret: clientSecret };
};

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

});

