module.exports = {
  create: create,
  destroy: destroy,
  loginRequired: loginRequired
};

var json = require('../../lib/form-json');
var encryption = require('../../lib/encryption');

function create(req, res, db) {
  json(req, res, function(req, res){
    var username = req.body.username;
    var password = req.body.password;
    db.get("SELECT * FROM users WHERE username=?", [username], function(err, user){
      if(err){
        res.statusCode = 500;
        res.end("Server error");
        return;
      }
      if(!user){
        // user not found
        return;
      }else {
        var cryptedPassword = encryption.digest(password + user.salt)
        if(cryptedPassword == user.cryptedPassword){
          // user is gg
          var cookieData = JSON.stringify({userId: user.id});
          var encryptedCookie = encryption.encipher(cookieData);
          res.setHeader("Set-Cookie", ["session=" + encryptedCookie]);
          res.statusCode = 200;
          res.end("Logged in");
        } else{
          // invalid username/password
        }
      }
    })
  });
}

function destroy(req, res){
  res.setHeader("Set-Cookie", "");
  res.statusCode = 200;
  res.end("Logged out successfully")
}

function loginRequired(req, res, next) {
  var session = req.headers.cookie.session;
  var sessionData = encryption.decipher(session);
  var sessionObj = JSON.parse(sessionData);
  if(sessionObj.userId) {
    req.currentUserId = sessionObj.userId;
    next(req,res);
    return;
  } else {
    res.statusCode = 403;
    res.end("Authentication required");
  }
}
