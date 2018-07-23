#!/bin/sh

# Usage: ./generate.sh
#
# Generate with OpenSSL input files used by the test suite.

DEST_DIR="`dirname "$0"`"

PASSWORD=dontchangeme
MESSAGE="hello, world"

CIPHER_KEYS_ENVELOPED=" \
  -des-ede3-cbc:000102030405060708090a0b0c0d0e0f1011121314151617 \
  -aes-128-cbc:000102030405060708090a0b0c0d0e0f \
  -aes-192-cbc:000102030405060708090a0b0c0d0e0f1011121314151617 \
  -aes-256-cbc:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -cast5-cbc:000102030405060708090a0b0c0d0e0f \
  -camellia-128-cbc:000102030405060708090a0b0c0d0e0f \
  -aes-128-ecb:000102030405060708090a0b0c0d0e0f \
  -aes-192-ecb:000102030405060708090a0b0c0d0e0f1011121314151617 \
  -aes-256-ecb:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -camellia-128-ecb:000102030405060708090a0b0c0d0e0f"

CIPHER_KEYS_ENCRYPTED=" \
  -des-cbc:0001020304050607 \
  -des-ede3-cbc:000102030405060708090a0b0c0d0e0f1011121314151617 \
  -aes-128-cbc:000102030405060708090a0b0c0d0e0f \
  -aes-192-cbc:000102030405060708090a0b0c0d0e0f1011121314151617 \
  -aes-256-cbc:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -cast5-cbc:0001020304 \
  -cast5-cbc:000102030405060708090a0b0c0d0e0f \
  -camellia-128-cbc:000102030405060708090a0b0c0d0e0f \
  -des-ecb:0001020304050607 \
  -aes-128-ecb:000102030405060708090a0b0c0d0e0f \
  -aes-192-ecb:000102030405060708090a0b0c0d0e0f1011121314151617 \
  -aes-256-ecb:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -camellia-128-ecb:000102030405060708090a0b0c0d0e0f"

if [ -z "$OPENSSL" ]; then
  OPENSSL=openssl
fi

"$OPENSSL" version || exit $?

function encrypt() {
  local TYPE="$1"

  # PBES1
  (
    for cipher in pbeWithMD5AndDES-CBC \
                  pbeWithSHA1AndDES-CBC \
                  PBE-SHA1-RC4-128 \
                  PBE-SHA1-RC4-40 \
                  pbeWithSHA1And3-KeyTripleDES-CBC \
                  pbeWithSHA1And2-KeyTripleDES-CBC; do
      "$OPENSSL" pkcs8 -topk8 -in "$DEST_DIR"/"$TYPE"-unencrypted-pkcs8.pem \
        -v1 $cipher -passout pass:"$PASSWORD"
    done
  ) > "$DEST_DIR"/"$TYPE"-encrypted-pbes1.pem

  # PBES2 with PBKDF2
  (
    for cipher in des des3 cast camellia128; do
      "$OPENSSL" pkcs8 -topk8 -in "$DEST_DIR"/"$TYPE"-unencrypted-pkcs8.pem \
        -v2 $cipher -passout pass:"$PASSWORD"
    done
  ) > "$DEST_DIR"/"$TYPE"-encrypted-pbkdf2.pem

  # PBES2 with scrypt
  (
    for cipher in aes128 aes192 aes256; do
      "$OPENSSL" pkcs8 -topk8 -in "$DEST_DIR"/"$TYPE"-unencrypted-pkcs8.pem \
        -v2 $cipher -passout pass:"$PASSWORD" -scrypt
    done
  ) > "$DEST_DIR"/"$TYPE"-encrypted-scrypt.pem
}


# RSA

"$OPENSSL" genpkey -algorithm RSA -out "$DEST_DIR"/rsa-unencrypted-pkcs8.pem

"$OPENSSL" rsa -in "$DEST_DIR"/rsa-unencrypted-pkcs8.pem \
  -out "$DEST_DIR"/rsa-unencrypted-trad.pem

encrypt rsa


# DSA

"$OPENSSL" genpkey -genparam -algorithm DSA -out "$DEST_DIR"/dsa-params.pem

"$OPENSSL" genpkey -paramfile "$DEST_DIR"/dsa-params.pem \
  -out "$DEST_DIR"/dsa-unencrypted-pkcs8.pem

"$OPENSSL" dsa -in "$DEST_DIR"/dsa-unencrypted-pkcs8.pem \
  -out "$DEST_DIR"/dsa-unencrypted-trad.pem

encrypt dsa


# ECDSA (named curve)

"$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$DEST_DIR"/ecdsa-p256-unencrypted-pkcs8.pem

"$OPENSSL" ec -in "$DEST_DIR"/ecdsa-p256-unencrypted-pkcs8.pem \
  -out "$DEST_DIR"/ecdsa-p256-unencrypted-trad.pem

encrypt ecdsa-p256


# ECDSA (explicit prime curve)

"$OPENSSL" ecparam -name prime256v1 -out "$DEST_DIR"/ecdsa-epc-params.pem \
  -param_enc explicit

"$OPENSSL" genpkey -paramfile "$DEST_DIR"/ecdsa-epc-params.pem \
  -out "$DEST_DIR"/ecdsa-epc-unencrypted-pkcs8.pem

"$OPENSSL" ec -in "$DEST_DIR"/ecdsa-epc-unencrypted-pkcs8.pem \
  -out "$DEST_DIR"/ecdsa-epc-unencrypted-trad.pem

encrypt ecdsa-epc


# Certificates

for TYPE in rsa dsa ecdsa-p256 ecdsa-epc; do
  "$OPENSSL" req -x509 -new -subj /emailAddress=test@example.com \
    -key "$DEST_DIR"/"$TYPE"-unencrypted-pkcs8.pem \
    -out "$DEST_DIR"/"$TYPE"-self-signed-cert.pem
done


# CMS data

echo "$MESSAGE" | "$OPENSSL" cms -data_create \
   -outform PEM -out "$DEST_DIR"/cms-data.pem


# CMS signed data

(
  for TYPE in rsa dsa ecdsa-p256 ecdsa-epc; do
    echo "$MESSAGE" | "$OPENSSL" cms -sign -outform PEM \
      -stream -indef -md sha256 \
      -inkey "$DEST_DIR"/"$TYPE"-unencrypted-pkcs8.pem \
      -signer "$DEST_DIR"/"$TYPE"-self-signed-cert.pem
  done

  for MODE in pss; do
    echo "$MESSAGE" | "$OPENSSL" cms -sign -outform PEM \
      -stream -indef -md sha256 \
      -inkey "$DEST_DIR"/rsa-unencrypted-pkcs8.pem \
      -signer "$DEST_DIR"/rsa-self-signed-cert.pem \
      -keyopt rsa_padding_mode:"$MODE"
  done
) > "$DEST_DIR"/cms-signed-data.pem


# CMS enveloped data (key transport)

(
  for cipher_key in $CIPHER_KEYS_ENVELOPED; do
    cipher=`expr "$cipher_key" : '\([^:]*\):[^:]*'`

    for TYPE in rsa; do
      echo "$MESSAGE" | "$OPENSSL" cms -encrypt -outform PEM \
        -stream -indef $cipher \
        -recip "$DEST_DIR"/"$TYPE"-self-signed-cert.pem
    done

    for MODE in oaep; do
      echo "$MESSAGE" | "$OPENSSL" cms -encrypt -outform PEM \
        -stream -indef $cipher \
        -recip "$DEST_DIR"/rsa-self-signed-cert.pem \
        -keyopt rsa_padding_mode:"$MODE"
    done
  done
) > "$DEST_DIR"/cms-enveloped-ktri-data.pem


# CMS enveloped data (key agreement)

(
  for cipher_key in $CIPHER_KEYS_ENVELOPED; do
    cipher=`expr "$cipher_key" : '\([^:]*\):[^:]*'`

    for TYPE in ecdsa-p256; do
      for MD in sha1 sha224 sha256 sha384 sha512; do
        echo "$MESSAGE" | "$OPENSSL" cms -encrypt -outform PEM \
          -stream -indef $cipher \
          -recip "$DEST_DIR"/"$TYPE"-self-signed-cert.pem \
          -keyopt ecdh_kdf_md:"$MD" -keyopt ecdh_cofactor_mode:0
      done
    done
  done
) > "$DEST_DIR"/cms-enveloped-kari-data.pem


# CMS enveloped data (key encryption key)

(
  for cipher_key in $CIPHER_KEYS_ENVELOPED; do
    cipher=`expr "$cipher_key" : '\([^:]*\):[^:]*'`
    key=`expr "$cipher_key" : '[^:]*:\([^:]*\)'`

    echo "$MESSAGE" | "$OPENSSL" cms -encrypt -outform PEM \
      -stream -indef $cipher -secretkey $key -secretkeyid 30
  done
) > "$DEST_DIR"/cms-enveloped-kekri-data.pem


# CMS enveloped data (password)

(
  for cipher_key in $CIPHER_KEYS_ENVELOPED; do
    cipher=`expr "$cipher_key" : '\([^:]*\):[^:]*'`
    key=`expr "$cipher_key" : '[^:]*:\([^:]*\)'`

    echo "$MESSAGE" | "$OPENSSL" cms -encrypt -outform PEM \
      -stream -indef $cipher -pwri_password "$PASSWORD"
  done
) > "$DEST_DIR"/cms-enveloped-pwri-data.pem


# CMS digested data

(
  for digest in MD5 SHA1 SHA224 SHA256 SHA384 SHA512; do
    echo "$MESSAGE" | "$OPENSSL" cms -digest_create -md $digest \
      -outform PEM
  done
) > "$DEST_DIR"/cms-digested-data.pem


# CMS encrypted data

(
  for cipher_key in $CIPHER_KEYS_ENCRYPTED; do
    cipher=`expr "$cipher_key" : '\([^:]*\):[^:]*'`
    key=`expr "$cipher_key" : '[^:]*:\([^:]*\)'`

    echo "$MESSAGE" | "$OPENSSL" cms -EncryptedData_encrypt -outform PEM \
      -stream -indef $cipher -secretkey $key
  done
) > "$DEST_DIR"/cms-encrypted-data.pem
