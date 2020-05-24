# testssl

testssl generate self signed certificates for local development purposes.

# Features
- generates wildcard x509 certificates which covers *.domain.tld and domain.tld.
- outputs root authority and domain/server CA
- 10 years validity
- fallback to use `.test` as TLD if you don't input any specific TLD (https://tools.ietf.org/html/rfc6761)
 
# Usage
- `testssl --domain=example` - generates CA for example.test in ssl subfolder
- `testssl --domain=mylocal.loc --dir=site` - generates CA for mylocal.loc in folder site
- `testssl --domain=mydoman.test --dir=` - does not output any files
- `testssl.GenerateCert("mydomain_name", "")` - if you use from other package but don't want to generate files

# How to use root CA
- import root CA in your browser 
- Firefox -> open in browser tab about:preferences#privacy, click View Certificates and click Import -> select rootCA.pem
- Chrome -> open in browser tab chrome://settings/certificates?search=authorities and click Import -> select rootCA.pem

or 

- MacOS - import PEM trough keychain on MacOS and mark as trusted
- Ubuntu - as root CA on Ubuntu (you need to convert PEM to CRT).
`openssl x509 -in rootCA.pem -inform PEM -out rootCA.crt`
  
