var SignedMessage = {};

SignedMessage.parse = function(signature) {
    var retval = {
	verify: function(key) {
	    return $gp.verifyAuthentication(key, this);
	}
    };
    signature = $gp(signature).get_signature_values();
    retval.issuer_id = signature.signature.issuer;
    retval.signature = signature.signature;
    var sighash = signature.get_signature_hash();
    if (sighash) {
      retval.hash = sighash.toUpperCase();
    } else {
      retval.hash = '';
    }
    retval.content = signature.signature.signature_content;
//     console.log(signature);
    return retval;
}
