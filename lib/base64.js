///
///
// This file implements base64 encoding and decoding.
// Encoding is done by the function base64Encode(), decoding
// by base64Decode(). The naming mimics closely the corresponding
// library functions found in PHP. However, this implementation allows
// for a more flexible use.
//
// This implementation follows RFC 3548 (http://www.faqs.org/rfcs/rfc3548.html),
// so the copyright formulated therein applies.
//
// Dr.Heller Information Management, 2005 (http://www.hellerim.de).
//
///

//     try {
// 	if (system.utility.base64 == null) {
// 	    throw new Error('');
// 	};
//     } catch(e) { // don't install twice
//   // dependencies
// 	try {
// 	    eval('core');
// 	} catch(e) {
// 	    throw new Error('base64: class \'core\' not installed');
// 	}

	var base64 = function(){};

// provide for class information
	base64.classID = function() {
	    return 'system.utility.base64';
	};

//disallow subclassing
	base64.isFinal = function() {
	    return true;
	};

// original base64 encoding
	base64.encString = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
// URL and file name safe encoding
	base64.encStringS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

	/// BEGIN_DOC(base64).METHOD(encode)
///
	// method String base64.encode(INPUTTYPE inp [, bool uc [, bool safe]])
//
// Encode input data into a base64 character string.
//
	// Function arguments:
	//     INPUTTYPE inp:        data to be encoded. INPUTTYPE may be String or Array.
//                           Any other INPUTTYPE results in an output value of null.
//                           If INPUTTYPE is String each character is converted into
//                           two bytes each of which is encoded separately.
//     bool uc               Optional. If this parameter has a value of 'true' which is
	//                           the default, code of each character is treated as a 16-bit
	//                           entity (UniCode), i.e. as two bytes. Otherwise, the codes
	//                           are truncated to one byte (8-bit character set) which
	//                           may result in information loss. If INPUTTYPE is Array,
//                           the value of this parameter has no effect.
	//     bool safe:            Optioanal. If this parameter is set to true, the standard base64
//                           character set is replaced with a modified version where
	//                           the characters '+' and '/' are replace with '-' and '_',
	//                           repectively, in order to avoid problems with file system
//                           namings which otherwise could occur on some systems.
	//                           By default, the value of this argument is assumed to be
//                           false.
	// Return value:             The function returns a character string consisting of
//                           the base64 representaion of the input. Its length is a
//                           multiple of 4. If the encoding yields less than this
	//                           the string is stuffed with the '=' character. In each case,
//                           the string maybe empty but not null if no error occurred.
	// Errors:                   Whenever an error occurs, null is returned. Parameter values
//                           not defined above are considered errors.
	// Remarks:                  If the input array contains something different from
//                           a byte at some position the first 8 bits only of this entity are
	//                           processed silently without returning an error, which probably
//                           results in garbage converted to base64.
//
/// END_DOC
	base64.encode = function(inp, uc, safe) {
  // do some argument checking
	    if (arguments.length < 1) return null;
	    var readBuf = new Array();    // read buffer
	    if (arguments.length >= 3 && safe != true && safe != false) return null;
	    var enc = (arguments.length >= 3 && safe) ? this.encStringS : this.encString; // character set used
	    var b = (typeof inp == "string"); // how input is to be processed
	    if (!b && (typeof inp != "object") && !(inp instanceof Array)) return null; // bad input
	    if (arguments.length < 2) {
		uc = true;                  // set default
	    } // otherwise its value is passed from the caller
	    if (uc != true && uc != false) return null;
	    var n = (!b || !uc) ? 1 : 2;  // length of read buffer
	    var out = '';                 // output string
	    var c = 0;                    // holds character code (maybe 16 bit or 8 bit)
	    var j = 1;                    // sextett counter
	    var l = 0;                    // work buffer
	    var s = 0;                    // holds sextett

  // convert
	    for (var i = 0; i < inp.length; i++) {  // read input
		c = (b) ? inp.charCodeAt(i) : inp[i]; // fill read buffer
		for (var k = n - 1; k >= 0; k--) {
		    readBuf[k] = c & 0xff;
		    c >>= 8;
		}
		for (var m = 0; m < n; m++) {         // run through read buffer
      // process bytes from read buffer
		    l = ((l<<8)&0xff00) | readBuf[m];   // shift remaining bits one byte to the left and append next byte
		    s = (0x3f<<(2*j)) & l;              // extract sextett from buffer
		    l -=s;                              // remove those bits from buffer;
		    out += enc.charAt(s>>(2*j));        // convert leftmost sextett and append it to output
		    j++;
		    if (j==4) {                         // another sextett is complete
			out += enc.charAt(l&0x3f);        // convert and append it
			j = 1;
		    }
		}
	    }
	    switch (j) {                            // handle left-over sextetts
	    case 2:
		s = 0x3f & (16 * l);                // extract sextett from buffer
		out += enc.charAt(s);               // convert leftmost sextett and append it to output
		out += '==';                        // stuff
		break;
	    case 3:
		s = 0x3f & (4 * l);                 // extract sextett from buffer
		out += enc.charAt(s);               // convert leftmost sextett and append it to output
		out += '=';                         // stuff
		break;
	    default:
		break;
	    }

	    return out;

	}

	/// BEGIN_DOC(base64).METHOD(decode)
///
	// method RETURNTYPE base64.decode(String inp [, enum outType [, bool safe [, bool lax]]])
//
// Encode input data into a base64 character string.
//
	// Function arguments:
	//     String inp:           base64 encoded data string to be decoded.
//     enum outType          Optional. This parameter specifies the type of the output and determines
	//                           how the input data is to be interpreted.:
	//                             0  - binary data; create a byte array (default)
	//                             1  - 8-bit character string, assuming 1-byte characters encoded in inp
	//                             2  - 16-bit (UniCode) character string, assuming 2-byte
//                                  characters encoded in inp
	//                           If 2 is passed to the function, but the number of base64 characters
	//                           is odd, a value of null is returned.
	//     bool safe             Optional. If this parameter is set to true, the standard base64
//                           character set is replaced with a modified version where
	//                           the characters '+' and '/' are replaced with '-' and '_',
	//                           repectively, in order to avoid problems with file system
//                           namings which otherwise could occur on some systems.
	//                           By default, the value of this argument is assumed to be
//                           false.
	//     bool lax              Optional. If set to true, the function skips all input characters which
	//                           cannot be processed. This includes the character '=', too, if
//                           it is followed by at least one different character before the string
	//                           ends. However, if skipping infeasible characters amounts to a number
	//                           of allowed base64 characters which is not amultiple of 4,
//                           this is considered an error and null is returned.
	//                           If lax is set to false (the default), null is returned
//                           whenever an infeasible character is found.
//                           The purpose of this parameter is to give support in cases
//                           where data has been base64 encoded and later on was folded by
	//                           some other software, e.g. '\r\n\'s have been inserted in email.
//                           exchange.
	// Return value:             The function's processing result value is stored in a string or in
	//                           a byte array before it is returned, depending on the value
	//                           assigned to the type parameter. In each case, the value
//                           maybe empty but not null if no error occurred.
	// Errors:                   Whenever an error occurs, null is returned. Parameter values
//                           not defined above are considered errors.
//
/// END_DOC

	base64.decode = function(inp, outType, safe, lax) {

  // do some argument checking
	    if (arguments.length < 1) return null;
	    if (arguments.length < 2) outType = 0 ;// produce character array by default
	    if (outType != 0 && outType != 1 && outType != 2) return null;
	    if (arguments.length >= 3 && safe != true && safe != false) return null;
	    var sEnc = (arguments.length >= 3 && safe) ? this.encStringS : this.encString;  // select encoding character set
	    if (arguments.length >= 4 && lax != true && lax != false) return null;
	    var aDec = new Object();                // create an associative array for decoding
	    for (var p = 0; p < sEnc.length; p++) { // populate array
		aDec[sEnc.charAt(p)] = p;
	    }
	    var out = (outType == 0) ? new Array() : '';
	    lax = (arguments.length == 4 && lax); // ignore non-base64 characters
	    var l = 0;               // work area
	    var i = 0;               // index into input
	    var j = 0;               // sextett counter
	    var c = 0;               // input buffer
	    var k = 0;               // index into work area
	    var end = inp.length;    // one position past the last character to be processed
	    var C = '';
  // check input
	    if (lax) {
		var inpS = '';         // shadow input
		var ignore = false;    // determines wether '=' must be counted
		var cnt = 0;
		for (var p = 1; p <= inp.length; p++) {    // check and cleanup string before trying to decode
		    c = inp.charAt(end - p);
		    if (c == '=') {
			if (!ignore) {
			    if (++cnt > 1) ignore = true;
			} else {
			    continue;
			}
		    } else if (undefined != aDec[c]) { // the character is base64, hence feasible
			if (!ignore) ignore = true;      // no more '=' allowed
			inpS = c + inpS;                 // prepend c to shadow input
		    }
		}
		for (var p = 0; p <= cnt; p++) {     // at most cnt '=''s were garbage, a number in
		    if (p == 2) return null;           // [inpS.length, inpS.length + cnt] must be a
		    if ((inpS.length + cnt)%4 == 0) break;  // multiple of 4
		}
		if (inpS.length%4==1) return null;   // must be 0, 2, or 3 for inpS to contain correctly base64 encoded data
		inp = inpS;                          // inp now contains feasible characters only
		end = inp.length;
	    } else {
		if (inp.length%4 > 0) return null;   // invalid length
		for (var p = 0; p < 2; p++) {        // search for trailing '=''s
		    if (inp.charAt(end - 1) == '=') {
			end--;
		    } else {
			break;
		    }
		}
	    }
  // convert
	    for (i = 0; i < end; i++) {
		l <<= 6;                             // clear space for next sextett
		if (undefined == (c = aDec[inp.charAt(i)])) return null; // lax must be false at this place!
		l |= (c&0x3f);    // append it
		if (j == 0) {
		    j++;
		    continue;                          // work area contains incomplete byte only
		}
		if (outType == 2) {
		    if (k == 1) {                      // work area contains complete double byte
			out += String.fromCharCode(l>>(2*(3-j)));  // convert leftmost 16 bits and append them to string
			l &= ~(0xffff<<(2*(3-j)));       // clear the 16 processed bits
		    }
		    k = ++k%2;
		} else {                             // work area contains complete byte
		    if (outType == 0) {
			out.push(l>>(2*(3-j)));          // append byte to array
		    } else {
			out += String.fromCharCode(l>>(2*(3-j))); // convert leftmost 8 bits and append them to String
		    }
		    l &= ~(0xff<<(2*(3-j)));           // clear the 8 processed bits
		}
		j = ++j%4;                           // increment sextett counter cyclically
	    }
	    if (outType == 2 && k == 1) return null;  // incomplete double byte in work area

	    return out;
	}

	//core.installClass(base64);

   // } // end catch
