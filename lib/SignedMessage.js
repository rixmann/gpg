/*
  ############################################################################
  # Copyright 2011 Ole Rixmann, Deborah Schmidt                              #
  #                                                                          #
  # This file is part of gpg_parser.                                         #
  # gpg_parser is free software: you can redistribute it and/or modify it    #
  # under the terms of the GNU Affero General Public License as published by #
  # the Free Software Foundation, either version 3 of the License, or        #
  # (at your option) any later version.                                      #
  #                                                                          #
  # gpg_parser is distributed in the hope that it will be useful, but WITHOUT#
  # ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or    #
  # FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public     #
  # License for more details.                                                #
  #                                                                          #
  # You should have received a copy of the GNU Affero General Public License #
  # along with dudle.  If not, see <http://www.gnu.org/licenses/>.           #
  ############################################################################
*/

// To parse a cleartext Signature made with gpg run:

// SignedMessage.parse(Signatur); 

// Where Signature is a string containing a
// gpg-signature created for example with "gpg --clearsign"

// If you parsed the corresponding key with GPGKey.js you can run:

// SignedMessage.parse(Signatur).verify(Key); -> Boolean

// To check if the signature is correct.

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
