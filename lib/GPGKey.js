var GPGKey = {};

GPGKey.parse = function(string) {
    var retval = {};
    var key = Symcrypt.$gp(string);
    retval.id = key.find_id_packet().id;
    retval.keymaterial = key.keymaterial;
    retval.fingerprint = key.fingerprint;
    retval.short_id = key.fingerprint.substr(key.fingerprint.length - 16);
    return retval;
}