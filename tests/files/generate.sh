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
  -rc2-cbc:000102030405060708090a0b0c0d0e0f \
  -aes-128-ecb:000102030405060708090a0b0c0d0e0f \
  -aes-192-ecb:000102030405060708090a0b0c0d0e0f1011121314151617 \
  -aes-256-ecb:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -camellia-128-ecb:000102030405060708090a0b0c0d0e0f"

CIPHER_KEYS_ENVELOPED_CBC=" \
  -des-ede3-cbc:000102030405060708090a0b0c0d0e0f1011121314151617 \
  -aes-128-cbc:000102030405060708090a0b0c0d0e0f \
  -aes-192-cbc:000102030405060708090a0b0c0d0e0f1011121314151617 \
  -aes-256-cbc:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -cast5-cbc:000102030405060708090a0b0c0d0e0f \
  -camellia-128-cbc:000102030405060708090a0b0c0d0e0f \
  -rc2-cbc:000102030405060708090a0b0c0d0e0f"

CIPHER_KEYS_ENCRYPTED=" \
  -des-cbc:0001020304050607 \
  -des-ede3-cbc:000102030405060708090a0b0c0d0e0f1011121314151617 \
  -aes-128-cbc:000102030405060708090a0b0c0d0e0f \
  -aes-192-cbc:000102030405060708090a0b0c0d0e0f1011121314151617 \
  -aes-256-cbc:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -cast5-cbc:0001020304 \
  -cast5-cbc:000102030405060708090a0b0c0d0e0f \
  -camellia-128-cbc:000102030405060708090a0b0c0d0e0f \
  -rc2-40-cbc:0001020304 \
  -rc2-64-cbc:0001020304050607 \
  -rc2-cbc:000102030405060708090a0b0c0d0e0f \
  -des-ecb:0001020304050607 \
  -aes-128-ecb:000102030405060708090a0b0c0d0e0f \
  -aes-192-ecb:000102030405060708090a0b0c0d0e0f1011121314151617 \
  -aes-256-ecb:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -camellia-128-ecb:000102030405060708090a0b0c0d0e0f"

PKCS12_INTEGRITY="sha1 sha256 sha384"

PKCS12_PRIVACY=" \
  aes-128-cbc \
  PBE-SHA1-RC2-128 \
  PBE-SHA1-RC2-40"

if [ -z "$OPENSSL" ]; then
  OPENSSL=openssl
fi

"$OPENSSL" version || exit $?

PROVIDERS="-provider default -provider legacy"

function der_to_pem () {
  echo "-----BEGIN $1-----"
  "$OPENSSL" base64 -e
  echo "-----END $1-----";
}

function encrypt() {
  local TYPE="$1"

  # PBES1
  (
    for cipher in pbeWithMD5AndDES-CBC \
                  pbeWithSHA1AndDES-CBC \
                  PBE-SHA1-RC4-128 \
                  PBE-SHA1-RC4-40 \
                  pbeWithSHA1And3-KeyTripleDES-CBC \
                  pbeWithSHA1And2-KeyTripleDES-CBC \
                  PBE-SHA1-RC2-128 \
                  PBE-SHA1-RC2-40; do
      "$OPENSSL" pkcs8 -topk8 -in "$DEST_DIR"/"$TYPE"-unencrypted-pkcs8.pem \
        -v1 $cipher -passout pass:"$PASSWORD" \
        $PROVIDERS
    done
  ) > "$DEST_DIR"/"$TYPE"-encrypted-pbes1.pem

  # PBES2 with PBKDF2
  (
    for cipher in des des3 cast camellia128 rc2 rc2-40-cbc rc2-64-cbc; do
      "$OPENSSL" pkcs8 -topk8 -in "$DEST_DIR"/"$TYPE"-unencrypted-pkcs8.pem \
        -v2 $cipher -passout pass:"$PASSWORD" \
        $PROVIDERS
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
  -traditional -out "$DEST_DIR"/rsa-unencrypted-trad.pem

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


# X25519

"$OPENSSL" genpkey -algorithm x25519 \
  -out "$DEST_DIR"/x25519-unencrypted-pkcs8.pem

encrypt x25519


# X448

"$OPENSSL" genpkey -algorithm x448 \
  -out "$DEST_DIR"/x448-unencrypted-pkcs8.pem

encrypt x448


# Ed25519

"$OPENSSL" genpkey -algorithm ed25519 \
  -out "$DEST_DIR"/ed25519-unencrypted-pkcs8.pem

encrypt ed25519


# Ed448

"$OPENSSL" genpkey -algorithm ed448 \
  -out "$DEST_DIR"/ed448-unencrypted-pkcs8.pem

encrypt ed448


# Public keys

for TYPE in rsa dsa ecdsa-p256 x25519 x448 ed25519 ed448; do
  "$OPENSSL" pkey -pubout \
    -in "$DEST_DIR"/"$TYPE"-unencrypted-pkcs8.pem \
    -out "$DEST_DIR"/"$TYPE"-public.pem
done

"$OPENSSL" rsa -RSAPublicKey_out \
  -in "$DEST_DIR"/rsa-unencrypted-pkcs8.pem \
  >> "$DEST_DIR"/rsa-public.pem


# Certificates

for TYPE in rsa dsa ecdsa-p256 ecdsa-epc ed25519 ed448; do
  "$OPENSSL" req -x509 -new -subj /emailAddress=test@example.com \
    -key "$DEST_DIR"/"$TYPE"-unencrypted-pkcs8.pem \
    -out "$DEST_DIR"/"$TYPE"-self-signed-cert.pem
done

for TYPE in x25519 x448; do
  "$OPENSSL" req -new -subj /emailAddress=test@example.com \
    -key "$DEST_DIR"/rsa-unencrypted-pkcs8.pem \
  | "$OPENSSL" x509 -req \
    -CA "$DEST_DIR"/rsa-self-signed-cert.pem \
    -CAkey "$DEST_DIR"/rsa-unencrypted-pkcs8.pem \
    -force_pubkey "$DEST_DIR"/"$TYPE"-public.pem \
    -set_serial 1 \
    -out "$DEST_DIR"/"$TYPE"-self-signed-cert.pem # FIXME: misleading filename
done


# PKCS #12

for TYPE in rsa ed25519; do
  (
    "$OPENSSL" pkcs12 -export -passout pass:"$PASSWORD" \
    -inkey "$DEST_DIR"/"$TYPE"-unencrypted-pkcs8.pem \
    -in "$DEST_DIR"/"$TYPE"-self-signed-cert.pem \
    -name "PKCS12 ($TYPE) -nomac" -nomac | der_to_pem PKCS12

    for macalg in $PKCS12_INTEGRITY; do
      "$OPENSSL" pkcs12 -export -passout pass:"$PASSWORD" \
      -inkey "$DEST_DIR"/"$TYPE"-unencrypted-pkcs8.pem \
      -in "$DEST_DIR"/"$TYPE"-self-signed-cert.pem \
      -name "PKCS12 ($TYPE) -macalg $macalg" -macalg $macalg \
      | der_to_pem PKCS12
    done

    for certpbe in NONE $PKCS12_PRIVACY; do
      "$OPENSSL" pkcs12 -export -passout pass:"$PASSWORD" \
      -inkey "$DEST_DIR"/"$TYPE"-unencrypted-pkcs8.pem \
      -in "$DEST_DIR"/"$TYPE"-self-signed-cert.pem \
      -name "PKCS12 ($TYPE) -certpbe $certpbe" -certpbe $certpbe \
      $PROVIDERS \
      | der_to_pem PKCS12
    done

    for keypbe in NONE $PKCS12_PRIVACY; do
      "$OPENSSL" pkcs12 -export -passout pass:"$PASSWORD" \
      -inkey "$DEST_DIR"/"$TYPE"-unencrypted-pkcs8.pem \
      -in "$DEST_DIR"/"$TYPE"-self-signed-cert.pem \
      -name "PKCS12 ($TYPE) -keypbe $keypbe" -keypbe $keypbe \
      $PROVIDERS \
      | der_to_pem PKCS12
    done
  ) > "$DEST_DIR"/"$TYPE"-pkcs12.pem
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
      -nodetach -md sha256 \
      -inkey "$DEST_DIR"/rsa-unencrypted-pkcs8.pem \
      -signer "$DEST_DIR"/rsa-self-signed-cert.pem \
      -keyopt rsa_padding_mode:"$MODE"
  done
) > "$DEST_DIR"/cms-signed-data.pem


# CMS signed data (detached)

(
  for TYPE in rsa dsa ecdsa-p256 ecdsa-epc; do
    echo "$MESSAGE" | "$OPENSSL" cms -sign -outform PEM \
      -md sha256 \
      -inkey "$DEST_DIR"/"$TYPE"-unencrypted-pkcs8.pem \
      -signer "$DEST_DIR"/"$TYPE"-self-signed-cert.pem
  done

  for MODE in pss; do
    echo "$MESSAGE" | "$OPENSSL" cms -sign -outform PEM \
      -md sha256 \
      -inkey "$DEST_DIR"/rsa-unencrypted-pkcs8.pem \
      -signer "$DEST_DIR"/rsa-self-signed-cert.pem \
      -keyopt rsa_padding_mode:"$MODE"
  done
) > "$DEST_DIR"/cms-signed-data-detached.pem


# CMS enveloped data (key transport)

(
  for cipher_key in $CIPHER_KEYS_ENVELOPED; do
    cipher=`expr "$cipher_key" : '\([^:]*\):[^:]*'`

    for TYPE in rsa; do
      echo "$MESSAGE" | "$OPENSSL" cms -encrypt -outform PEM \
        -stream -indef $cipher \
        -recip "$DEST_DIR"/"$TYPE"-self-signed-cert.pem \
        $PROVIDERS
    done

    for MODE in oaep; do
      echo "$MESSAGE" | "$OPENSSL" cms -encrypt -outform PEM \
        -stream -indef $cipher \
        -recip "$DEST_DIR"/rsa-self-signed-cert.pem \
        -keyopt rsa_padding_mode:"$MODE" \
        $PROVIDERS
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
          -keyopt ecdh_kdf_md:"$MD" -keyopt ecdh_cofactor_mode:0 \
          $PROVIDERS
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
      -stream -indef $cipher -secretkey $key -secretkeyid 30 \
      $PROVIDERS
  done
) > "$DEST_DIR"/cms-enveloped-kekri-data.pem


# CMS enveloped data (password)

(
  for cipher_key in $CIPHER_KEYS_ENVELOPED_CBC; do
    cipher=`expr "$cipher_key" : '\([^:]*\):[^:]*'`
    key=`expr "$cipher_key" : '[^:]*:\([^:]*\)'`

    echo "$MESSAGE" | "$OPENSSL" cms -encrypt -outform PEM \
      -stream -indef $cipher -pwri_password "$PASSWORD" \
      $PROVIDERS
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
      -stream -indef $cipher -secretkey $key \
      $PROVIDERS
  done
) > "$DEST_DIR"/cms-encrypted-data.pem
