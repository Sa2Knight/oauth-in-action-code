var express = require("express");
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// 認可サーバ情報
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// OAuthクライアント情報
var client = {
	"client_id": "oauth-client-1",
	"client_secret": "oauth-client-secret-1",
	"redirect_uris": ["http://localhost:9000/callback"]
};

var protectedResource = 'http://localhost:9002/resource';

var state = null;

var access_token = null;
var scope = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, scope: scope});
});

/*
 * 認可コードを取得させるために認可エンドポイントへリダイレクト
 * 認可コード取得後は、callbackURLにリダイレクトしてもらう
 */
app.get('/authorize', function(req, res){
  // ランダム文字列を生成して、サーバ経由のリダイレクトであることを保証する
  var state = randomstring.generate()
  var authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    state: state
  });
  res.redirect(authorizeUrl);
});

/*
 * 認可コードを受け取ったあとのリダイレクト先
 * トークンエンドポイントからアクセストークンを受け取る
 */
app.get('/callback', function(req, res){
  // 認可エンドポイントが発行した認可コード
  var code = req.query.code;

  // トークンエンドポイント用のクエリストリングの組み立て
  var form_data = qs.stringify({
    grant_type: 'authorization_code',       // 認可コードによる認証を使う
    code: code,                             // 認可コード
    redirect_uri: client.redirect_uris[0]   // 認可コード取得時に使ったコールバックURL
  })

  // リクエストヘッダの組み立て
  var headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret)
  }

  // トークンエンドポイントにPOSTする
  var tokRes = request('POST', authServer.tokenEndpoint, {
    body: form_data,
    headers: headers
  });

  // POSTに成功した場合、アクセストークンを設定してトップページに戻る
  if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
    var body = JSON.parse(tokRes.getBody());
    console.log(body)
    access_token = body.access_token;
    scope = body.scope;
    res.render('index', {access_token: access_token, scope: scope});
  }
  // POSTに失敗した場合、エラーページをレンダリング
  else {
    res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
  }

});

app.get('/fetch_resource', function(req, res) {

	/*
	 * Use the access token to call the resource server
	 */

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

var encodeClientCredentials = function(clientId, clientSecret) {
	return new Buffer(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});

