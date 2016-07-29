var ProtoBuf = require("protobufjs");
var argsBuilder = require("./proofTx.pb.js")
var ProofTX = argsBuilder.ProofTX;
//Load modules
var fs = require('fs');
var path = require('path');
var https = require('https');
var async = require('async');
var rest = require(__dirname + '/lib/rest.js');

var HYPERLEDGER_SERVER="hyperledger.brackets.doc";

var CHAINCODENAME ="docproofs";

var enrollId="";

function createBracket(bracketName,threshold,digests,publicKeys){
  var args = new BracketArg()
  args.name= bracketName;
  args.threshold = threshold
  args.setDigests(digests)
  args.setPubKeys(publicKeys)
  args.type =argsBuilder.ProofTX.ProofType["SECP256K1SHA2"]
  return new Promise(function(reject,resolve){
    invoke("createBracket",args.encode().toString('hex'),function(data,err){
      if (err){
        reject(err)
      }
      else {
        resolve(data)
      }
    })
  })
}


function signBracket(bracketName,signatures,preimages,data){
  var args = new ProofTX()
  args.name = bracketName;
  args.data = data;
  args.setSignatures(signatures)
  args.setPreImages(preimages)
  return new Promise(function(resolve,reject){
    invoke("signBracket",args.encode().toString('hex'),function(data,err){
      if (err){
        reject(err)
      }
      else {
        resolve(data)
      }
    })
  })
}

function revokeBracket(bracketName,signatures){
  var args = new ProofTX()
  args.name = bracketName;
  args.setSignatures(signatures)

  return new Promise(function(resolve,reject){
    invoke("revokeBracket",args.encode().toString('hex'),function(data,err){
      if (err){
        reject(err)
      }
      else {
        resolve(data)
      }
    })
  })
}


function supercedeBracket(bracketName,signatures,
  supercedingName, supercedingKeys, supercedingDigests){

  var args = new ProofTX()
  args.name = bracketName
  args.setSignatures(signatures)
  args.supercede.name = supercedingName
  args.supercede.type = argsBuilder.SupercededBy.ProofType.SECP256K1SHA2
  args.supercede.setPubKeys(supercedingKeys);
  args.supercede.setDigests(supercedingDigests);
  return new Promise(function(resolve,reject){
    invoke("supercedeBracket",args.encode().toString('hex'),function(data,err){
      if (err){
        reject(err)
      }
      else {
        resolve(data)
      }
    })
  })
}

function bracketStatus(bracketName){
  return new Promise(function(resolve,reject){
    query("status",bracketName,function(data,err){
      if (err){
        reject(err);
      }else{
        resolve(data);
      }
    })
  })
}



function tx(type,txname, proofTX, cb){
  var options = {host:HYPERLEDGER_SERVER,port:5000,path: '/chaincode',ssl:false};
  console.log(proofTX);
  var body = {
        jsonrpc: '2.0',
        method: type,
        params: {
          type: 1,
          chaincodeID:{
            name: CHAINCODENAME
          },
          ctorMsg: {
            function: txname,
            args: [proofTX]
          },
          secureContext: enrollId
        },
        id: Date.now()
      };
  options.success = function(statusCode, data){
    console.log('[ibc-js]', txname, ' - success:', data);
    if(cb) cb(null, data);
  };
  options.failure = function(statusCode, e){
    console.log('[ibc-js]', txname, ' - failure:', statusCode, e);
    if(cb) cb(e, null);
  };

  rest.post(options, '', body);
}

function invoke(funcname, proofTX, cb){
  tx('invoke',funcname,proofTX,cb)
  }

function query(funcname, proofTX, cb){
  tx('query',funcname,proofTX,cb)
  }

module.exports ={
  createBracket:createBracket,
  signBracket:signBracket,
  revokeBracket:revokeBracket,
  supercedeBracket:supercedeBracket,
  bracketStatus:bracketStatus
}
