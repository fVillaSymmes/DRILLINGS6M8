# Construcción del HEADER
jwt_header=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | sed s/\+/-/g | sed 's/\//_/g' | sed -E s/=+$//)

echo "HEADER: "$jwt_header

# Construcción del Payload

payload=$(echo -n '{"iss":"midominio.com","exp":1540839345,"name":"Pedro Perez","email":"pedroperez@midominio.com","iat":1516239022}' | base64 | sed s/\+/-/g | sed 's/\//_/g' | sed -E s/=+$//)

echo "PAYLOAD: "$payload

clave_secreta='W9nhLz7rDkWqHZSm' #Rescatada del ejercicio Rebound

echo "CLAVE ALFANUMÉRICA URL FRIENDLY: "$clave_secreta

# Convertir la clave secreta a hexadecimal (no base64)
Hexsecreta=$(echo -n "$clave_secreta" | xxd -p | tr -d '\n')
echo "\nClave en Hexadecimal: " $Hexsecreta

# Generar la firma hmac -- se debe notar que se esta pasando key como bytes hexadecimal
hmac_signatureHex=$(echo -n "${jwt_header}.${payload}" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$Hexsecreta -binary | base64 | sed 's/\+/-/g' | sed 's/\//_/g' | sed -E 's/=+$//')

echo "\nFirma o SIGNATURE: "$hmac_signatureHex

# Creando el token completo
# Y = Base64URLEncode(HEADER) + ‘.’ + Base64URLEncode(PAYLOAD)
# JWT = Y + ‘.’ + Base64URLEncode(HMACSHA256(Y))
jwt="${jwt_header}.${payload}.${hmac_signatureHex}"
echo "JSON Web Token (JWT): "$jwt