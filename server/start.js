var app = require('http').createServer(handler)
  , io = require('socket.io').listen(app)
  , fs = require('fs')
  , static = require('node-static')
  , fileServer = new static.Server('../client')
  , url = require('url')
  , crypto = require('crypto')
  , node_cryptojs = require('node-cryptojs-aes')
  , CryptoJS = node_cryptojs.CryptoJS
  , JsonFormatter = node_cryptojs.JsonFormatter
  _ = require('underscore');


var params = {
	staticpath: '../client'
}

app.listen(8080, '0.0.0.0');

function handler (request, response) {

	var url_parts = url.parse(request.url, true);

	if(url_parts.pathname == '/')
    {
    	fileServer.serveFile('/index.html', 500, {}, request, response);
    }
	else if(url_parts.pathname.split('/')[1] == 'static')
	{
		fileServer.serve(request, response);
	}
	else if(url_parts.pathname === '/getip') {
		response.writeHead(200, {'Content-Type': 'text/html'});
		response.end(request.headers.host);
	}
}

// console.log(crypto.Cipher+'')


var security = {
	fingerprintsalt: 'iservernodejsandiwantcreatesomem',
	sessions: {},
	encryptkeys:{},
	accesslist: {},
	genUserKey: function (callback) {

		// generate random passphrase binary data
		var r_key = crypto.randomBytes(128);

		// convert passphrase to base64 format
		var r_key_base64 = r_key.toString("base64");

		if(callback)
		{
			callback(r_key_base64);
		}
		else
		{
			return r_key_base64;
		}

		/*
		crypto.randomBytes(128, function(ex, userkey) {
		  	if (ex) throw ex;
			userkey = userkey.toString('utf8', 0, userkey.length)
		});
		*/
	},
	genEncryptKey: function (callback) {

		// generate random passphrase binary data
		var r_key = crypto.randomBytes(128);

		// convert passphrase to base64 format
		var r_key_base64 = r_key.toString("base64");
		
		if(callback)
		{
			callback(r_key_base64);
		}
		else
		{
			return r_key_base64;
		}

		/*crypto.randomBytes(256, function(ex, encryptkey) {
		  	
		  	if (ex) throw ex;

			encryptkey = encryptkey.toString('utf8', 0, encryptkey.length)

		  	callback(encryptkey);

		});*/
	},
	genFingerprint: function (userinfo, callback) {
		crypto.pbkdf2(JSON.stringify(userinfo), security.fingerprintsalt, 1, 50, function(err, fingerprint) {
			
			if(err) throw err;

			callback(fingerprint);

		});
	},
	encrypt: function(text, key){
		var cipher = crypto.createCipher('aes-256-cbc', key)
		var crypted = cipher.update(text,'utf8','hex')
		crypted += cipher.final('hex');
		return crypted;
	},
	decrypt: function(text, key){
		var decipher = crypto.createDecipher('aes-256-cbc', key)
		var dec = decipher.update(text,'hex','utf8')
		dec += decipher.final('utf8');
		return dec;
	}

};


var users = {
	dehimer: '130890',
	ded: 'dedok'
}

io.set('log level', 1); 

io.sockets.on('connection', function (socket) {


	var ippart = socket.handshake.address.address.split('.'),
		local = _.include([127, 192, 10], ippart[0]*1);

	//проверка userkey на валидность
	socket.on('c:checkuserkey', function (request) {
		
		request.userinfo['useragent'] = socket.handshake.headers['user-agent'];

		security.genFingerprint(request.userinfo, function (fingerprint) {

			if(security.sessions[request.userkey+fingerprint])
			{
				security.accesslist[socket.id] = 1;
				if ( local )
				{
					security.genEncryptKey(function (encryptkey) {
						
						//обновляем ключ шифрования
						security.sessions[request.userkey+fingerprint] = encryptkey;
						//присваиваем ключ сессии
						security.encryptkeys[socket.id] = encryptkey;

						socket.emit('s:checkuserkey', {res:1, encryptkey:encryptkey});
					});
				}
				else
				{
					//используем старый ключ шифрования для сокеса
					security[socket.id].encryptkey = security.sessions[request.userkey+fingerprint];

					socket.emit('s:checkuserkey', {res:1});
				}
			}
			else
			{
				if(local)
				{
					security.genEncryptKey(function (encryptkey) {
						//временный ключ шифрования для сессии
						security.encryptkeys[socket.id] = encryptkey;

						socket.emit('s:checkuserkey', {res:0, encryptkey:encryptkey});
					});
				}
				else
				{
					socket.emit('s:checkuserkey', {res:0});
				}
			}
		});
	});

	//получение userkey
	socket.on('c:givemeuserkey', function (request) {

		var decrypted = CryptoJS.AES.decrypt(request, security.encryptkeys[socket.id], { format: JsonFormatter });
		var decrypted_str = CryptoJS.enc.Utf8.stringify(decrypted);

		request = JSON.parse(decrypted_str);

		if (local && users[request.login] == request.password)
		{

			security.genUserKey(function (userkey) {

				request.userinfo['useragent'] = socket.handshake.headers['user-agent'];
				security.genFingerprint(request.userinfo, function (fingerprint) {

					security.sessions[userkey+fingerprint] = security.encryptkeys[socket.id];

					socket.emit('s:givemeuserkey', {res:1, userkey:userkey});
				});
			});
		}
		else
		{
			socket.emit('s:givemeuserkey', {res:0});
		}
	});

  	socket.on('message', function (request) {

  		//дешифровать сообщение
  		var decrypted = CryptoJS.AES.decrypt(request, security.encryptkeys[socket.id], { format: JsonFormatter });
		var decrypted_str = CryptoJS.enc.Utf8.stringify(decrypted);

		// request = JSON.parse(decrypted_str);

  		if(security.accesslist[socket.id] === 1)
  		{
    		io.sockets.emit('message', decrypted_str);
  		}

  	});
});