module.exports = require("protobufjs").newBuilder({})['import']({
    "package": null,
    "messages": [
        {
            "name": "ProofTX",
            "fields": [
                {
                    "rule": "optional",
                    "type": "ProofType",
                    "name": "type",
                    "id": 1
                },
                {
                    "rule": "optional",
                    "type": "string",
                    "name": "name",
                    "id": 2
                },
                {
                    "rule": "optional",
                    "type": "int32",
                    "name": "threshold",
                    "id": 3
                },
                {
                    "rule": "optional",
                    "type": "string",
                    "name": "data",
                    "id": 4
                },
                {
                    "rule": "repeated",
                    "type": "bytes",
                    "name": "PubKeys",
                    "id": 5
                },
                {
                    "rule": "repeated",
                    "type": "bytes",
                    "name": "Signatures",
                    "id": 6
                },
                {
                    "rule": "repeated",
                    "type": "bytes",
                    "name": "Digests",
                    "id": 7
                },
                {
                    "rule": "repeated",
                    "type": "bytes",
                    "name": "PreImages",
                    "id": 8
                },
                {
                    "rule": "optional",
                    "type": "SupercededBy",
                    "name": "supercede",
                    "id": 9
                }
            ],
            "enums": [
                {
                    "name": "ProofType",
                    "values": [
                        {
                            "name": "NULL",
                            "id": 0
                        },
                        {
                            "name": "SECP256K1",
                            "id": 1
                        },
                        {
                            "name": "SECP256K1SHA2",
                            "id": 2
                        }
                    ]
                }
            ]
        },
        {
            "name": "SupercededBy",
            "fields": [
                {
                    "rule": "optional",
                    "type": "ProofType",
                    "name": "type",
                    "id": 1
                },
                {
                    "rule": "optional",
                    "type": "string",
                    "name": "name",
                    "id": 2
                },
                {
                    "rule": "repeated",
                    "type": "bytes",
                    "name": "PubKeys",
                    "id": 3
                },
                {
                    "rule": "repeated",
                    "type": "bytes",
                    "name": "Digests",
                    "id": 4
                },
                {
                    "rule": "optional",
                    "type": "int32",
                    "name": "threshold",
                    "id": 5
                }
            ],
            "enums": [
                {
                    "name": "ProofType",
                    "values": [
                        {
                            "name": "NULL",
                            "id": 0
                        },
                        {
                            "name": "SECP256K1",
                            "id": 1
                        },
                        {
                            "name": "SECP256K1SHA2",
                            "id": 2
                        }
                    ]
                }
            ]
        }
    ]
}).build();
