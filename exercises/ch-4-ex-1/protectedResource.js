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

/*
 * アクセストークンを持ったクライアントにだけ見せて良い情報
 */
var resource = {
  "name": "Protected Resource",
  "description": "This data has been protected by OAuth 2.0"
};

/*
 * リクエストからアクセストークンを取り出すヘルパー関数
 * 取り出したアクセストークンが有効かも評価する
 */
var getAccessToken = function(req, res, next) {
  var inToken = null;
  var auth = req.headers['authorization'];

  // パターン1: authorizationヘッダーにトークンが含まれている場合
  if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
    inToken = auth.slice('bearer '.length);
  }
  // パターン2: リクエストボディにフォームエンコードされたトークンが含まれている場合(非推奨)
  else if (req.body && req.body.access_token) {
    inToken = req.body.access_token;
  }
  // パターン3: クエリストリングにトークンが含まれている場合(非推奨)
  else if (req.query && req.query.access_token) {
    inToken = req.query.access_token;
  }

  // 抽出したアクセストークンをトークンデータベースと照合する
  // 正常なトークンだった場合、リクエストオブジェクトに追加する
  nosql.one(function(token) {
    if (token.access_token == inToken) {
      return token;
    }
  }, function(err, token) {
    if (token) {
      console.log("このトークンは正当やで %s", inToken);
    } else {
      console.log("このトークン不正やで %s", inToken);
    }
    req.access_token = token;
    next(); // 次のミドルウェアのコールバック
    return;
  });
};

app.options('/resource', cors());

/*
 * 保護対象リソースの取得エンドポイント
 * 事前にアクセストークンを検証し、有効な場合のみ保護対象リソースを返却
 */
app.post("/resource", cors(), getAccessToken, function(req, res){
  if (req.access_token) {
    res.json(resource);
  } else {
    res.status(401).end();
  }
});

var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});

