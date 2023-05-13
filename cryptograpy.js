( function ( parent ){
    "use strict ";
    
    var app = parent .app = parent .app || {};
   
    if ( window . crypto && ! window .crypto .subtle && window .
    crypto . webkitSubtle ) {
    window .crypto .subtle = window . crypto . webkitSubtle ;
    }
    
    function isWebCryptoAPISupported () {
    return 'crypto ' in window && 'subtle ' in window . crypto ;
    }
    
    app. cryptography = ( function (){
    
    var self = this;
    
    var module = {
    
    isSupported : function () {
    
        if (" crypto " in window ) {
    
            if (" subtle " in window . crypto ) {
                return true;
            }
        }
        return false;
    },
  
    returnResolve : function (value) {
        return new Promise ( function (resolve , reject ) {
            resolve (value);
        });
    },
    digest : function (alg , data) {
        return window .crypto .subtle . digest (alg , data);
    },
    generateKeys : function (alg , exportable , usage) {
        return window .crypto .subtle . generateKey (alg, exportable, usage);
    },
    
    importKey : function (key, alg, format, exportable, usage) {
        return window .crypto .subtle . importKey (format, key, alg, exportable, usage);
    },
    
    exportKey : function (key , format ) {
        return window .crypto .subtle . exportKey (format, key);
    },

    encryptData : function (alg , key , inputData ) {
        return window .crypto .subtle . encrypt (alg, key, inputData);
    },

    decryptData : function (alg , key , inputData ) {
        return window .crypto .subtle . decrypt (alg, key, inputData);
    },
    signData : function (alg , key , inputData ) {
        return window .crypto .subtle .sign(alg, key, inputData);
    },

    exportIdentity : function (publicKey, privateKey, signingKey, verifyKey) {
        return new Promise ( function (resolve , reject ) {
            var exported = {};
            function exportKeyOrContinue (key , format , c, k) {
                return new Promise ( function (done , fail) {
                    module . exportKey (key , format )
                    .then( function (result ) {
                        c[k] = new UintArray (result );
                        done ();
                    })
                    .catch( function (err) { done (); });
            });
        }
        exportKeyOrContinue (publicKey, 'spki ', exported, 'publicKeyData ')
        .then( function ( result ) {
            return exportKeyOrContinue (privateKey, 'pkcs', exported, 'privateKeyData');
        })
        .then( function ( result ) {
            return exportKeyOrContinue (verifyKey, 'spki', exported, 'verifyKeyData');
        })
        .then( function ( result ) {
            return exportKeyOrContinue (signingKey, 'pkcs', exported, 'signingKeyData');
        })
        .then( function (){
            if (! exported . verifyKeyData ) {
                exported . publicIdentityData = app.utils.packUintArrays (exported . publicKeyData);
            } else {
                exported . publicIdentityData = app.utils.packUintArrays (exported . publicKeyData, exported . verifyKeyData);
            }
            if (! exported . signingKeyData ) {
                exported . privateIdentityData = app.utils.packUintArrays (exported . privateKeyData);
            } else {
                exported . privateIdentityData = app.utils.packUintArrays (exported . privateKeyData, exported . signingKeyData);
            }
            resolve ( exported );
        })
        .catch( function (err){
            reject (err);
        });
    });
},

importIdentity : function (asymAlg, signingAlg, publicIdentityData, privateIdentityData, exportablePrivateIdentity ) {
    return new Promise ( function (resolve , reject ) {
        var imported = {};
        
        function importKeyOrContinue (key, alg, format, exportable, usage) {
            return new Promise ( function (done , fail) {
                if (key) {
                    module . importKey (key, alg, format, exportable, usage)
                    .then( function (result ) { done( result ); })
                    .catch( function (err) { done (); });
                } else {
                    done ();
                }
            });
        }
        var publicIdentity = app.utils. unpackUintArrays (publicIdentityData);
        var privateIdentity = app.utils. unpackUintArrays (privateIdentityData);

        imported = {
            publicKeyData : publicIdentity [0],
            verifyKeyData : publicIdentity [1],
            privateKeyData : privateIdentity [0],
            signingKeyData : privateIdentity [1]
        };
        importKeyOrContinue ( imported . publicKeyData, asymAlg, 'spki', true, ['encrypt'])
        .then( function ( result ) {
            imported . publicKey = result ;
            return importKeyOrContinue ( imported . verifyKeyData, signingAlg, 'spki', true, ['verify']);
        })

        .then( function ( result ) {
            imported . verifyKey = result ;
            return importKeyOrContinue ( imported . privateKeyData, asymAlg, 'pkcs', exportablePrivateIdentity , ['decrypt']);
        })
        .then( function ( result ) {
            imported . privateKey = result ;
            return importKeyOrContinue ( imported . signingKeyData, signingAlg, 'pkcs', exportablePrivateIdentity, ['sign']);
        })
        .then( function ( result ) {
            imported . signingKey = result ;
            resolve ( imported );
        });
    });
},

verifyData : function (alg, key, digitalSignature, inputData ) {
    return window .crypto .subtle . verify (alg, key, digitalSignature, inputData);
},

encryptAndSign : function (asymAlg, symAlg, signingAlg, plaintext, encryptionKey, signingKey, verifyKey, publicKey ) {
    return new Promise ( function (resolve , reject ) {
        var state = {};
        state. plaintextUintArray = app.utils. convertTextToUintArray ( plaintext );
        state. signed = signingKey ?true:false;
        state. hasSignature = state. signed ?true:false;
        state. hasPublicKey = publicKey ?true:false;
        state. symmetricIV = window . crypto . getRandomValues (new UintArray (1));
        module . generateKeys (symAlg , true , ['encrypt', 'decrypt'])
        .then( function ( symmetricKey ) {
            state. symmetricKey = symmetricKey ;
            return module . exportKey (state.symmetricKey, 'raw');
        })
        .then( function ( exportedSymmetricKey ) {
            state. exportedSymmetricKey = new UintArray (exportedSymmetricKey);
            if (state.signed && verifyKey ) {
                return module . exportKey (verifyKey , 'spki ');
            } else {
                return module . returnResolve (false);
            }
        })
        .then( function ( exportedVerifyKey ) {
            if (state.signed && verifyKey ) {
                state. exportedVerifyKey = new UintArray (exportedVerifyKey);
                return module . signData (signingAlg , signingKey, state. plaintextUintArray);
            } else {
                state. exportedVerifyKey = new UintArray ();
                return module . returnResolve ();
            }
        })
        .then( function ( digitalSignature ) {
            state. digitalSignature = new UintArray (digitalSignature);
            if (state. hasPublicKey ) {
                return module . exportKey (publicKey , 'spki ');
            } else {
                return module . returnResolve ();
            }
        })
        .then( function ( exportedPublicKey ) {
            if (state. hasPublicKey ) {
                state. exportedPublicKey = new UintArray (exportedPublicKey);
            }
            if (state.signed ) {
                state. dataToEncrypt = app.utils.packUintArrays (
                    new UintArray ([1, state. hasPublicKey ?1:0]) ,
                    state. plaintextUintArray ,
                    state. digitalSignature ,
                    state. exportedVerifyKey ,
                    state. exportedPublicKey
                    );
                } else {
                    state. dataToEncrypt = app.utils.packUintArrays (
                        new UintArray ([0, state. hasPublicKey ?1:0]) ,
                        state. plaintextUintArray ,
                        state. exportedPublicKey
                        );
                    }
                    symAlg .iv = state. symmetricIV ;
                    return module . encryptData (symAlg , state.symmetricKey , state. dataToEncrypt );
                })
                .then( function ( encryptedDataArray ) {
                    state.encryptedPlaintextAndDigitalSignatureAndVerifyKey = new UintArray ( encryptedDataArray );
                    state. symmetricKeyAndIVpack = app.utils.packUintArrays (
                        state. exportedSymmetricKey ,
                        state. symmetricIV
                        );
                        return module . encryptData ( encryptionKey .algorithm , encryptionKey , state.symmetricKeyAndIVpack );
                    })
                    state.then( function ( encryptedSymmetricKeyAndIVArray ) {
                        new UintArray ( encryptedSymmetricKeyAndIVArray );
                        encryptedSymmetricKeyAndIV = new state. packedCipher = app.utils. packUintArrays (state.encryptedPlaintextAndDigitalSignatureAndVerifyKey, state. encryptedSymmetricKeyAndIV);
                        resolve (state);
                    })
                    .catch( function (err) {
                        reject (err);
                    });
                });
            },
            decryptAndVerify : function (asymAlg , symAlg , signingAlg, digestAlg , packedCipher , decryptionKey ) {
                return new Promise ( function (resolve , reject ) {
                    var state = {
                        signed : false
                    };
                    var unpackedCipher = app.utils. unpackUintArrays (packedCipher );
                    state.encryptedPlaintextAndDigitalSignatureAndVerifyKey = unpackedCipher [0];
                    state. encryptedSymmetricKeyAndIV = unpackedCipher[1];
                    module . decryptData ( decryptionKey .algorithm , decryptionKey , state. encryptedSymmetricKeyAndIV)
                    .then( function ( result ) {
                        var symmetricKeyAndIV = app.utils.unpackUintArrays (new UintArray ( result ));
                        state. symmetricKeyData = symmetricKeyAndIV [0];
                        state. symmetricIV = symmetricKeyAndIV [1];
                        return module . importKey (state. symmetricKeyData , symAlg , 'raw ', false , ['decrypt ']);
                    })
                    .then( function ( result ) {
                        state. symmetricKey = result ;
                        symAlg .iv = state. symmetricIV ;
                        return module . decryptData (symAlg , state.symmetricKey , state.encryptedPlaintextAndDigitalSignatureAndVerifyKey);
                    })
                    .then( function ( result ) {
                        var plaintextAndDigitalSignatureAndVerifyKey = app.utils. unpackUintArrays (new UintArray (result ));
                        state. hasSignature =
                        plaintextAndDigitalSignatureAndVerifyKey[0][0];
                        state. hasPublicKey = plaintextAndDigitalSignatureAndVerifyKey[0][1];
                        state. plaintextUintArray = plaintextAndDigitalSignatureAndVerifyKey [1];
                        if (state. hasSignature ) {
                            state.signed = true;
                            state. digitalSignature = plaintextAndDigitalSignatureAndVerifyKey[2];
                            state. verifyKeyData = plaintextAndDigitalSignatureAndVerifyKey[3];
                            state. publicKeyData = state. hasPublicKey ? plaintextAndDigitalSignatureAndVerifyKey[4]: undefined ;
                            return module . digest (digestAlg , state.verifyKeyData );
                        } else {
                            state. publicKeyData = state. hasPublicKey ? plaintextAndDigitalSignatureAndVerifyKey[2]: undefined ;
                            return module . returnResolve ();
                        }
                    })
                    .then( function (hash) {
                        if (state.signed ) {
                            state. verifyKeyFingerprint = new UintArray (hash);
                            return module . importKey (state. verifyKeyData , signingAlg , 'spki ', true , ['verify ']);
                        } else {
                            return module . returnResolve ();
                        }
                    })
                    .then( function ( result ) {
                        if (state.signed ) {
                            state. verifyKey = result ;
                        }
                        if (state. publicKeyData ) {
                            return module . importKey (state. publicKeyData , asymAlg , 'spki ', true , ['encrypt ']);
                        } else {
                            return module . returnResolve ();
                        }
                    })
                    .then( function ( publicKey ) {
                        state. publicKey = publicKey ;
                        if (state. publicKeyData ) {
                            return module . digest (digestAlg , state.publicKeyData );
                        } else {
                            return module . returnResolve ();
                        }
                    })
                    .then( function (hash) {
                        if (state. publicKeyData ) {
                            state. publicKeyFingerprint = new UintArray (hash);
                        }
                        if (state.signed ) {
                            return module . verifyData (signingAlg , state.verifyKey , state. digitalSignature , state.plaintextUintArray );
                        } else {
                            return module . returnResolve (false);
                        }
                    })
                    .then( function ( result ) {
                        state. digitalSignatureValid = result ;
                        resolve (state);
                    })
                    .catch( function (err){
                        reject (err);
                    });
                });
            }
        };
        return module ;
    })();
})(this);
