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

// To parse an ascii-armored (radix-64) gpg-key run:

// GPGKey.parse(String);

// Where String is the string containing the armored key.

// The following fields of the return-Object contain information that may  be useful:

// - id: The keys owners id (which is a string).
// - fingerprint: A Number (hex) identifying this key.
// - short_id: Last 32 bits of the Fingerprint.

var GPGKey = {};

GPGKey.parse = function(string) {
    var retval = {};
    var key = $gp(string);
    retval.id = key.find_id_packet().id;
    retval.keymaterial = key.keymaterial;
    retval.fingerprint = key.fingerprint;
    retval.short_id = key.fingerprint.substr(key.fingerprint.length - 16);
    return retval;
}
