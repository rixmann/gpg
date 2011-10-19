var SignedMessage = {};

SignedMessage.parse = function(signature) {
    var retval = {
	verify: function(key) {
	    return Symcrypt.verifyAuthentication(key, this);
	}
    };
    signature = Symcrypt.$gp(signature).get_signature_values();
    retval.issuer_id = signature.signature.issuer;
    retval.signature = signature.signature;
    retval.hash = signature.get_signature_hash().toUpperCase();
    retval.content = signature.signature.signature_content;
//    console.log(signature);
    return retval;
}