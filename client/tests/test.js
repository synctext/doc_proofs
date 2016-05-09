var Brackets = require('../index.js');
var Bitcore = require('bitcore-lib');
function testCreate(){
  var masterPrivateKey = "xprv9s21ZrQH143K4WBp2uyZ2EcZqYhHBjSfYmDzNEyErUiyjHFYgiuvgS43wU8K4gBEYxZvNHdgsmA6JTzin1wodcsPUV4nJbpEUTYFP8uFbwD"
  var priv = new Bitcore.HDPrivateKey(masterPrivateKey);
  var pub1 = priv.derive(1).publicKey
  var pub2 = priv.derive(2).publicKey
  var pub3 = priv.derive(3).publicKey
  var digest = Bitcore.crypto.Hash.sha256(Buffer("hello_world"))

  var prom = Brackets.createBracket("89thBracket",1,[digest],[pub1.toBuffer(),pub2.toBuffer(),pub3.toBuffer()])
  prom.then(function(){
    console.log("Done");
  })

}

function testQuery(){
  var prom = Brackets.bracketStatus("89thBracket")
  prom.then(function(data){
    console.log(data);
    console.log("Done");
  })
}

function signBracket(){

  var masterPrivateKey = "xprv9s21ZrQH143K4WBp2uyZ2EcZqYhHBjSfYmDzNEyErUiyjHFYgiuvgS43wU8K4gBEYxZvNHdgsmA6JTzin1wodcsPUV4nJbpEUTYFP8uFbwD"
  var priv = new Bitcore.HDPrivateKey(masterPrivateKey);

  var dataPayload = "Payload"
  var bracketName = "89thBracket"
  var message = new Buffer(bracketName+":"+dataPayload);
  var digest = new Bitcore.crypto.Hash.sha256(message);

  var sig1 = Bitcore.crypto.ECDSA.sign(digest,priv.derive(1).privateKey,'little')

  Brackets.signBracket("")
}



// testCreate();
testQuery();
