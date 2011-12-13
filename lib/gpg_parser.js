/*
  ############################################################################
  # Copyright 2011 Ole Rixmann, Deborah Schmidt                              #
  #                                                                          #
  #                                                                          #
  # Dudle is free software: you can redistribute it and/or modify it under   #
  # the terms of the GNU Affero General Public License as published by       #
  # the Free Software Foundation, either version 3 of the License, or        #
  # (at your option) any later version.                                      #
  #                                                                          #
  # Dudle is distributed in the hope that it will be useful, but WITHOUT ANY #
  # WARRANTY; without even the implied warranty of MERCHANTABILITY or        #
  # FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public     #
  # License for more details.                                                #
  #                                                                          #
  # You should have received a copy of the GNU Affero General Public License #
  # along with dudle.  If not, see <http://www.gnu.org/licenses/>.           #
  ############################################################################
*/

/**************************************************************
 * This Function parses Packages compliant with rfc4880        *
 * which can be found at http://tools.ietf.org/html/rfc4880.   *
 *                                                             *
 * Currently Clearsignatures and Public Key Packages are       *
 * supported.                                                  *
 *                                                             *
 * You need hash-algorithms from the pidCrypt library and      *
 * maybe the widely used BigInteger library to perform the math*
 *                                                             *
 * Usage example:                                              *
 *                                                             *
 * var clearsigned; // The Signature, provided as a String     *
 *                                                             *
 * clearsigned = $gp(clearsigned); // _init()                  *
 *                                                             *
 * clearsigned.get_signature_values();                         *
 * //extends the object with the object clearsigned.signature  *
 *                                                             *
 * issuer = clearsigned.signature.issuer;                      *
 * //The id of the public key which made this signature        *
 *                                                             *
 * issuer = "0x" + issuer.slice(issuer.length - 8);            *
 * //To get the last 8 hex-numbers which are needed to         *
 * //retrieve the public key from a keyserver.                 *
 *                                                             *
 * var pubkey; // your public key ;) - a String                *
 *                                                             *
 * pubkey = $gp(pubkey);                                       *
 * var id = pubkey.find_id_packet().id; // email-address of    *
 * // the user owning this key - String.                       *
 *                                                             *
 * var algorithm = pubkey.signature.signature_algo;            *
 * pubkey.get_keys();                                          *
 * // now there is a keymaterial-object in                     *
 * // pubkey.keymaterial, field-names are the names of         *
 * // the algorithm.                                           *
 * // Values are arrays containing the keys.                   *
 *                                                             *
 * hash = clearsigned.get_signature_hash();                    *
 * // you will need this for checking, it is the Hash over     *
 * // the signed text and parts of the signature.              *
 *                                                             *
 * var algo_specific_vals = clearsigned.signature.signature;   *
 * // this array contains the algorithm specific integers      *
 *                                                             *
 *                                                             *
 **************************************************************/
var $gp = $gp || function(packet){
  return new GPGPackageParser(packet);
};


GPGPackageParser = function(packet){
  var retval;
  if(typeof(packet) == 'string') {
    this.clearpacket = packet;
    if(packet.indexOf('-----BEGIN PGP SIGNED MESSAGE-----') >= 0){
      this._parse_clearsigned(packet);
    } else return this._init(packet);
  }
  else return this._init_preparsed(packet);
}

GPGPackageParser.prototype = {
 log: //function() {
    function(schtr) {
    console.log("GPGParser-> " + schtr);
    return this;
  },
 _parse_clearsigned: function(packet){
    var pgp_marker = {
    begin: '-----BEGIN PGP SIGNED MESSAGE-----',
    begin_sig: '-----BEGIN PGP SIGNATURE-----',
    end: '-----END PGP SIGNATURE-----',
    index:function(name){
	return packet.indexOf(pgp_marker[name]);
      }
    };
    var cut_a_line = function(schtr){
      var idx = schtr.indexOf("\n");
      return schtr.slice(idx + 1);
    };
    var cut_a_line_rev = function(schtr){
      var idx = schtr.lastIndexOf("\n");
      return schtr.slice(0,idx);
    };
    var content = packet.slice(pgp_marker.index("begin") + pgp_marker.begin.length + 1, pgp_marker.index("begin_sig") - 1);
    content = cut_a_line(cut_a_line(content))
    this.log(content);
    content = content.replace(/\s*\n/g, String.fromCharCode(13,10));
    content = content.replace(/\s+$/, "");
    this.signature = {signature_content: content};
    this.log("content of clearsigned packet: " + content);
    this.log("content of clearsigned packet as ba: " + this.string2byteArray(content));
    packet = packet.slice(pgp_marker.index("begin_sig") + pgp_marker.begin_sig.length + 1, pgp_marker.index("end"));
    
    packet = cut_a_line_rev(cut_a_line_rev(cut_a_line(cut_a_line(packet))));
    //TODO!!!
    this.log("signature part of clearsigned packet: " + packet);
    this.log("base 64 encoded data as ba" + this.string2byteArray(packet));
    var decoded = base64.decode(packet.replace(/[\n\r]/ig, ""));
    this.log("from base64 decoding: " + decoded);
    if(decoded) {
      this._init_preparsed(decoded);
    } else return null;
  },
 _parse_header: function(offset){
    this.log("Wenn das Paket im alten Format ist 2, sonst 3: " + ((this.packet[offset] & 0xc0) >> 6));
    if(((this.packet[offset] & 0xc0) >> 6) != 2) return null;
    retval = {};
    retval.packet_tag = ((this.packet[offset] & 0x3c) / 4);
    var length_type = this.packet[offset] & 0x03;
    this.log("parse_header, laengen-typ: " + length_type);
    if(length_type < 2) retval.body_offset = length_type + 2 + offset;
    if(length_type == 2) retval.body_offset = 5 + offset;
    if(length_type == 3) retval.body_offset = 1 + offset;
    var new_length = 0;
    for(i = offset + 1; i < retval.body_offset; i++){
      new_length = (new_length << 8) | this.packet[i];
    }
    retval.length = new_length;
    retval._next_packet_offset = retval.body_offset + retval.length;
    return retval;
  },
 _parse_pubkey_header: function(offset){
    this.log("pubkey packetversion: " + this.packet[offset]);
    if(this.packet[offset] != 4) return null; //only version4 packets accepted
    var retval = {body_offset: offset + 6};
    retval.algorithm = this.packet[offset + 5];
    return retval;
  },
 _init_preparsed: function(packet){
    this.packet = packet;
    $.extend(this, this._parse_header(0));
    this.log("packet_tag: " + this.packet_tag);
    if(this.packet_tag == 13) return this.get_id();
    if(this.packet_tag == 6) return this.get_keys();
    return this;
  },
 _init: function(packet){
    packet = packet.replace(/\r/ig, "");
    var array64 = packet.split("\n");
    var decoded = base64.decode(array64.slice(3, array64.length - 3).join(""));
    if(decoded) {
      this._init_preparsed(decoded);
    } else return null;
  },
 _bint256: int2bigInt(256,9,1),
 baToBInt: function(ba, start, stop){
    var retval = int2bigInt(0,8,1);
    for(i = start; i <= stop; i++){
      retval = add(mult(retval, this._bint256), int2bigInt(ba[i],8,1));
    }
    return retval;
  },
 get_id: function(){
    this.id = this.ba2string(this.packet.splice(this.body_offset, this._next_packet_offset -1));
    var id = this.id;
    var i_idx = id.lastIndexOf(">");
    if (i_idx != -1) id = id.slice(0, i_idx + 1);
    this.id = id;
    return this;
  },
 get_keys: function(){
    var offset = this.body_offset;
    var header;
    var laufen = true;
    var retval = [];
    while(laufen){
      header = this._parse_pubkey_header(offset);
      if(header && header.algorithm == 1) {
	retval = {"rsa": this._get_mpis(2 ,offset + 6)};
	this.log("rsa-key gefunden:");

	offset = this._skip_mpis(2, offset + 6);
      }
      else if(header && header.algorithm == 17) {
	retval.push({"dsa": this._get_mpis(4,offset + 6)});
	offset = this._skip_mpis(4, offset + 6);
      }
      else laufen = false;
    }
    this._next_packet_offset = offset;
    this.keymaterial = retval;
    var packet = this.packet.slice(this.body_offset, offset);
    var packet_length = packet.length;
    var fingerprint_array = [153, Math.floor(packet_length/256),  packet_length % 256].concat(packet);
    this.fingerprint = pidCrypt.SHA1(pidCryptUtil.byteArray2String(fingerprint_array));
    return this;
  },
 get_next_packet: function(){
    if(this._next_packet_offset){
      var new_packet = this.packet.slice(this._next_packet_offset);
      this.log("parsing next packet, length: " + new_packet.length);
      return $gp($.extend([], new_packet));
    }
    else return null;
  },
 get_signature_values: function(){
    var offset = this.body_offset,
    retval = {};
    retval.signature_version = this.packet[offset];
    retval.signature_type = this.packet[offset + 1];
    retval.signature_algo = this.packet[offset + 2];
    if(retval.signature_algo == 1) retval.signature_algo = "rsa";
    else if(retval.signature_algo == 17) retval.signature_algo = "dsa";
    retval.signature_hash_algo = this.packet[offset + 3];
    if(retval.signature_hash_algo == 2) retval.signature_hash_algo = "SHA1";
    var hashed_subpacket_data_count = (this.packet[offset + 4] * 256) + this.packet[offset + 5];
    retval.hashed_subpackets = this._get_sig_subpackets(offset + 6, hashed_subpacket_data_count);
    offset = this.body_offset + 6 + hashed_subpacket_data_count; //offset is now after the hashed subpacket data :)
    retval.value_to_hash = this.packet.slice(this.body_offset, offset);
    var subpacket_data_count = (this.packet[offset] * 256) + this.packet[offset + 1];
    //this.log("Laenge der Subpakete: " + subpacket_data_count);
    retval.subpackets = this._get_sig_subpackets(offset + 2, subpacket_data_count);
    var subpackets = retval.subpackets.concat(retval.hashed_subpackets);
    retval.issuer = this.reduce(function(a,b){
	if(b.type == 16) return b.data; //issuer subpacket found
	else return a;
      },null,subpackets);
    this.log("issuer: " + retval.issuer);
    retval.issuer = this.ba2hex(retval.issuer);
    offset = offset + 2 + subpacket_data_count; //offset is now after the subpacket data
    retval.first16bit_hash = (this.packet[offset] * 256) + this.packet[offset + 1];
    if(retval.signature_algo == "rsa") retval.signature = this._get_mpis(1,offset + 2);
    else if (retval.signature_algo == "dsa") retval.signature = this._get_mpis(2,offset + 2);
    this.signature = $.extend(this.signature,retval);
    return this;
  },
 string2byteArray: function(str){
    var ba= [];
    for(var i=0;i<str.length; i++){
      ba.push(str.charCodeAt(i));
    }
    return ba;
  },
 ba2hex: function(ba) {
    var hexchars = "0123456789abcdef",
    retval = "",
    i = 0;
    for(i  in ba){
      var char1 = ba[i] >> 4,
	char2 = ba[i] & 0xf;
      retval = retval + hexchars.charAt(char1) + hexchars.charAt(char2);
    }
    return retval;
  },
 ba2string: function(ba){
    return String.fromCharCode.apply(this, ba);
  },
 get_signature_hash: function(){
    if(! this.signature) return null;
    if(! this.signature.signature_version) this.get_signature_values();
    var hash_appender_as_string = pidCryptUtil.byteArray2String(this.signature.value_to_hash);
    var val_to_hash = this.signature.signature_content + hash_appender_as_string;
    var laenge = [hash_appender_as_string.length];
    laenge.reverse();
    while(laenge.length < 4){
      laenge.push(0);
    }
    laenge.reverse();
    val_to_hash = val_to_hash + this.ba2string([this.signature.signature_version, 255].concat(laenge));
    this.log("string from which hash is computed: ||" + val_to_hash + "||\n" +
	     "as byte-array: " + this.string2byteArray(val_to_hash));
    var sig_hash;
    if(this.signature.signature_hash_algo == 8) sig_hash = pidCrypt.SHA256(val_to_hash);
    else if(this.signature.signature_hash_algo == 2 ||
	    this.signature.signature_hash_algo == "SHA1") 
      sig_hash = pidCrypt.SHA1(val_to_hash);
    else if(this.signature.signature_hash_algo == 8 ||
	    this.signature.signature_hash_algo == "SHA256") 
      sig_hash = pidCrypt.SHA256(val_to_hash);
    else if(this.signature.signature_hash_algo == 9 ||
	    this.signature.signature_hash_algo == "SHA384") 
      sig_hash = pidCrypt.SHA384(val_to_hash);
    else if(this.signature.signature_hash_algo == 10||
	    this.signature.signature_hash_algo == "SHA512") 
      sig_hash = pidCrypt.SHA512(val_to_hash);
    else if(this.signature.signature_hash_algo == 3 ||
	    this.signature.signature_hash_algo == "RIPEMD160") 
      sig_hash = hex_rmd160(val_to_hash);	
    else if(this.signature.signature_hash_algo == 1 ||
	    this.signature.signature_hash_algo == "MD5") 
      sig_hash = pidCrypt.MD5(val_to_hash);	
    else {
      sig_hash = "";
      throw "unknown hash algorithm, algo id: " + this.signature.signature_hash_algo;
    }
    var hash_control_bytes = this.signature.first16bit_hash.toString(16);
    if (parseInt(hash_control_bytes, 16) == parseInt(sig_hash.slice(0,4), 16)){
      this.log("signature hash calculated correct!");
      return sig_hash;
    }
    else {
      throw "Hash of the cleartext is wrong, 4 control-bytes did not match, " + hash_control_bytes + " != " + sig_hash.slice(0,4);
      return null;
    }
  },
 _get_sig_subpackets: function(offset, length){
    var retval = [],
    packet = this.packet,
    i = 0,
    laufen = true,
    offs = offset;
    var parse_length = function(offs){
      if(packet[offs] < 192) return 1;
      if(packet[offs] >= 192 && packet[offs] < 255) return 2;
      if(packet[offs] == 255) return 5;
      return null;
    };

    while(laufen) {
      var reti = {};
      reti.length_of_length = parse_length(offs);
      if(reti.length_of_length){
	if(reti.length_of_length == 1) reti.length = packet[offs];
	offs += reti.length_of_length;
	reti.type = packet[offs];
	reti.data = packet.slice(offs + 1, offs + reti.length);
	retval.push(reti);
	offs += reti.length;
	if(offs >= offset + length) laufen = false;
      } else laufen = false;
    }
    return retval;
  },
 _get_mpis: function(n, offset){
    var position = offset;
    var retval = [];
    var new_pos = 0;
    var i = 0;
    while(i < n){
      this.log("In _get_mpis #mpi: " + i + ", position: " + position + ", mpi length in Bit: " + ((this.packet[position] * 256) + this.packet[position + 1]) + ", mpi-length-bytes: " + this.packet[position] + ", " + this.packet[position + 1]);
      new_pos = position + 2 + Math.floor((((this.packet[position] * 256) + this.packet[position + 1] + 7)/8));
      retval.push(this.baToBInt(this.packet, position + 2, new_pos -1));
      this.log("mpi calculated: " + bigInt2str(retval[retval.length -1], 10));
      position = new_pos;
      i = i + 1;
    }
    return retval;
  },
 _skip_mpis: function(n, offset){
    var retval = offset;
    for(i = 0; i < n; i++){
      retval = retval + 2 + Math.floor((((this.packet[retval] * 256) + this.packet[retval + 1] + 7)/8));
      this.log("skip_mpis, new_position: " + retval);
    }
    return retval;
  },
 find_id_packet: function() {
    var laufen = true;
    var pubkey = this;
    while(laufen && pubkey) {
      if(pubkey.id) laufen = false;
      else pubkey = pubkey.get_next_packet();
    }
    return pubkey;
  },
 map : function(m,f) {
    var newm = [];
    for (i in m) {
      newm.push(f(m[i]));
    }
    return newm;
  },
 reduce: function() {
    var fn = arguments[0];
    var start_value_p = arguments.length > 2;
    var start;
    var map;
    if(start_value_p) {
      map = arguments[2];
      start = arguments[1];
    }
    else {
      start = arguments[1][0];
      map = arguments[1].slice(1);
    }
    var i = 0;
    for(i in map){
      start = fn(start, map[i]);
    }
    return start;
  },
 hexstring2bigInt: function(str){
    var rval = int2bigInt(0,1,1); //initialize return value with zero
    var sixteen = int2bigInt(16, 1, 1);
    for(var i = 0; i < str.length; i++){
      var next_figure = int2bigInt(parseInt(str.charAt(i), 16), 1, 1);
      rval = mult(sixteen, rval);
      rval = add(rval, next_figure);
    }
    this.log("retval: " + bigInt2str(rval));
    return rval;
  }
}

$gp.verifyAuthentication = function(publickey, signature) {

  if(signature.signature.signature_algo == "dsa") {
    return GPGPackageParser.prototype.dsa(publickey, signature);
  }
  else {
    if(signature.signature.signature_algo == "rsa") {
      return GPGPackageParser.prototype.rsa(publickey, signature);
    }
    else {
      throw "The algorithm used for verifying is not supported";
      return false;
    }
  }
};

String.prototype.reverse = function(){
  splitext = this.split("");
  revertext = splitext.reverse();
  reversed = revertext.join("");
  return reversed;
};

GPGPackageParser.prototype.dsa = function(publickey, signature) {
  
  this.log("dsa started..");
  
  this.log(signature);
  this.log(publickey);
  
  signature_hash = this.hexstring2bigInt(signature.hash);
  this.log(signature_hash);
  p = publickey.keymaterial[0].dsa[0];
  q = publickey.keymaterial[0].dsa[1];
  g = publickey.keymaterial[0].dsa[2];
  y = publickey.keymaterial[0].dsa[3];
  
  r = signature.signature.signature[0];
  s = signature.signature.signature[1];
  
  if(!negative(r) && !isZero(r) && greater(q,r) && !negative(s) && !isZero(s) && greater(q,s)) {
    
    var w = inverseMod(s,q);
    var u1 = multMod(signature_hash, w, q);
    var u2 = multMod(r, w, q);
    
    var v = multMod(powMod(g, u1, p), powMod(y, u2, p) , p);
    v = mod(v,q);
    
    v = bigInt2str(v, 16);
    r = bigInt2str(r, 16);
    this.log("v: " + v + " r: " + r);
    return (v.slice(v.length - r.length) == r)
      
      }
  else {
    this.log("0 < r < q and 0 < s < q is not satisfied");
    if(!negative(r) && !isZero(r))
      this.log("0>=r");
    if(! greater(q,r))
      this.log("r>=q");
    if(!negative(s) && !isZero(s))
      this.log("0>=s");
    if(!greater(q,s))
      this.log("s>=q");
    return false;
  }
};

GPGPackageParser.prototype.rsa = function(publickey, signature) {

  var signature_hash = signature.hash;
  var signature_hash_decrypted = signature.signature.signature[0];
  
  var key = publickey.keymaterial.rsa;
  var n = key[0];
  var e = key[1];
  var erg = powMod(signature_hash_decrypted, e, n);
  erg = bigInt2str(erg, 16);
  if(!signature_hash) 
    return false;
  else if(erg.slice(erg.length - signature_hash.length) == signature_hash)
    return true;
  else
    {
      throw "Signature was tampered, " + erg + " != " + signature_hash;
      return false;
    }
}
  
