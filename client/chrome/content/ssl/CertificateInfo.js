
// Copyright (c) 2011 Moxie Marlinspike <moxie@thoughtcrime.org>
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation; either version 3 of the
// License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
// USA


/**
 * This class is a holder for the information we pull out of a certificate,
 * such as its fingerprint.
 *
 **/


function CertificateInfo(certificate, serialized) {
  if (!(typeof serialized == 'undefined')) {
    this.deserialize(serialized);
    return;
  }

  // XXX uhm, free this?
  this.arena       = NSS.lib.PORT_NewArena(2048);
  this.commonName  = NSS.lib.CERT_GetCommonName(certificate.contents.subject.address());
  this.orgUnitName = NSS.lib.CERT_GetOrgUnitName(certificate.contents.subject.address());
  this.altNames    = NSS.lib.CERT_GetCertificateNames(certificate, this.arena);

  this.md5         = this.calculateFingerprint(certificate, NSS.lib.SEC_OID_MD5, 16);
  this.sha1        = this.calculateFingerprint(certificate, NSS.lib.SEC_OID_SHA1, 20);
  this.issuerAltName = null;
}

CertificateInfo.prototype.encodeVerificationDetails = function(details) {
  // this.orgUnitName = NSS.lib.buffer("Foo~Bar");
  var encodedDetails = "";

  for (var i in details) {
    encodedDetails += (details[i].notary + ":" + details[i].status + "*");
  }

  dump("Encoded details: " + encodedDetails + "\n");

  this.issuerAltName = encodedDetails;
};

CertificateInfo.prototype.deserialize = function(serialized) {
  this.destination      = new Object();
  this.destination.host = serialized.host;
  this.destination.port = serialized.port;
  this.commonName       = serialized.commonName;
  this.altNames         = Serialization.deserializeCERTGeneralName(serialized.altNames),
  this.md5              = serialized.md5;
  this.sha1             = serialized.sha1;
  this.issuerAltName    = serialized.issuerAltName;
};

CertificateInfo.prototype.serialize = function() {
  return {'host' : this.destination.host,
	  'port' : this.destination.port,
	  'commonName' : this.commonName,
	  'altNames' : Serialization.serializePointer(this.altNames),
	  'md5' : this.md5,
	  'sha1' : this.sha1,
          'issuerAltName' : this.issuerAltName};
};

CertificateInfo.prototype.calculateFingerprint = function(certificate, type, length) {
  var fingerprint = new NSS.lib.ubuffer(20);
  
  NSS.lib.PK11_HashBuf(type, fingerprint, 
		       certificate.contents.derCert.data, 
		       certificate.contents.derCert.len);

  var secItem        = NSS.types.SECItem({'type' : 0, 
					  'data' : fingerprint, 
					  'len' : length});
  var fingerprintHex = NSS.lib.CERT_Hexify(secItem.address(), 1);

  return fingerprintHex.readString();
};


