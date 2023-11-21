# AAA (Access Authentication and Authorization server.)

You will need __NEW__ pair of key for this. They are both
PKIC#1 encrypted PKI RSA keys.

**PRIVATE** key : used for signing the Access && Refresh Token  So all token
released by this server would be vaditeable from this server only.

while the ...

**PUBLIC** key : use for verifying the generated Access and Refresh token
. so those token signed by the PRIVATE key can be validated.

Server operator **MUST NOT** distribute the PRIVATE key to any one.
while PUBLIC key must be distributed to any system that will validate a speciffic key.

The following is how you generate both keys...

## Generating SSH Key

You have to create `private` and `public.key` separately, First, the private key
and public key the second time.

### First generate the Private key..

The command is `openssl genrsa -out private.pem -traditional 2048`
it with generate a private key in PEM format.

You need to notice the header:

```azure
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY----
```

for PKCS#1 and its important for this to work. As oppose to PKCS#8 one.

```azure
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY----
```

```bash
$ openssl genrsa -out private.pem -traditional 2048
$ cat private.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQEAsZ6vq7T+E6UnFHf1i5wljs4c+dpXTsIa1fk6S6Z74v/V7AjW
qXzJ52aI+N18yf+PD4HuZN/AvDOqIjQgaGUJH9W5F4Ppz1dNIJBU5qYsJOEwIl1/
uRkBPtKPRtYESVbYPPU6va7ttZv0lZEvPpJ1l+axo5ULaBnWW0IJqYipMU58IlVR
c+sJEV0sC4vvPHk62/VixpjskHuGeD0fmNu8U+cnv7wav+N/2G4hSgakYJofhkx+
watP2wHBCrSDMq8rc4socdWebmISQhoCkwI/Gr1F29l4A1wGjQt0oA3eTATFng+j
D0MLmR3lP7elATNTmHawpBH6IqWX9eKVSJ8M9wIDAQABAoIBAAnuJUQkSlAu25B5
ZHD5ud/SBiyx2E++6mEsHeY82JBIXV1k4Rt4rpERWncPavqgHw9u5DUfjVb4THq9
D1LG00vEVyTJazj8WIOJjjWW9MDbFiXVtF5U14z7mKcNMBApms1NqIsSTJfqsDHs
fAeziH+Flkje/FRFnYZcms2vpkXrVUd191Rr2Zwc0m8vLroAq5LGE9uFbNM5z1mL
FTUaESnQdNf+Pg6It9p/eJ+jXbN98dbNCd2xObD+LrPLeSMpy2o41Bqk6vLN7pwN
zI5jGMgaIC7SHZHiU5O+mnsbQ2kBknubXgKxm6SuaVp13TCd9tNW7Wu74MznUJ3T
AQsZeoECgYEA+Ay0grNBnNWTejg20zVexO4t3etvd+NpHu268kIf87L9NX16hYAd
IZvAXzlu0Y0hzA9SA/xygtTXdm6HZhl+4VFjLfLwudVVLFPf2RqinJdyrI6lbgE9
ksUBpFL2dtzCmPQ70Rj791u9Ai1k6/zh6XqDL0ITAg70KrL5iDHmWVUCgYEAt1AX
Y9Nxqkeiq2WqN1VmFqqW/FwwsqybuggaTKCQ3Zj5sNR8aMIYpY7kUTf/+Xk5Wdcy
VAMMr824SVqgeNyd8YnTIn9htRs5g/moO5+GQrVk2YPR6m1x6drj7c5d74VEubdk
ech4Yg25Vra1roC+cvgZdgSPa7mxmZ5TVMRhHRsCgYEAy2wP9UfwvR/iLE9BlwCj
0bjK4L4d0iIrqXOo5tgXwBG/2kgnXKhuO4uxveYp3axyVRkTV7WGa4kFklierbqm
9T17qskbZitwCERYxYE0bls9bgol3QsjZeQuroZjHaN561oQXDCzIm6XmNuFcosW
8hTI1M7JK9z7nLDeNzVFBWkCgYAls7RL1MYw9nDPfaZnoQnRKZ7KIo/lf7i7p0T5
c6C34umf4+P+i8UT7/KnfbQI9FTGVItGWiY21kHL3HbaxM07S1SAaOCIpiPLMALY
2HN9rt8iGYmIBKCEL3/nfiU1yRwcckqY/ZE84YO4APYXAOWqsbpS2pdA2b1cUgLj
kUxD9wJ/BrLnevv6y7BA/oOsf5yl9WvgCaYgFKiUxTwgZmjDP/W36HYDV9is8MwQ
9VRjLLMXN1p/UYxNjFJlUJwjLMmGcKR9rVtJxFI+I65I1wrCGl9A8vsyS/oKZVKy
hMmtM9D7v/lK/yBAJzHLA7QD+EiDuEk26Xob30B7mk5PuNLRDQ==
-----END RSA PRIVATE KEY-----
```

### Second, you generate the Public key.

Here you run `openssl rsa -in private.pem -outform PEM -pubout -out public.pem -traditional`.
Here you see the `-traditional` argument. Its non mandatory to have this argument, its for the sake
of compatibility.

```bash
$ openssl rsa -in private.pem -outform PEM -pubout -out public.pem -traditional
writing RSA key
$ cat public.pem
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsZ6vq7T+E6UnFHf1i5wl
js4c+dpXTsIa1fk6S6Z74v/V7AjWqXzJ52aI+N18yf+PD4HuZN/AvDOqIjQgaGUJ
H9W5F4Ppz1dNIJBU5qYsJOEwIl1/uRkBPtKPRtYESVbYPPU6va7ttZv0lZEvPpJ1
l+axo5ULaBnWW0IJqYipMU58IlVRc+sJEV0sC4vvPHk62/VixpjskHuGeD0fmNu8
U+cnv7wav+N/2G4hSgakYJofhkx+watP2wHBCrSDMq8rc4socdWebmISQhoCkwI/
Gr1F29l4A1wGjQt0oA3eTATFng+jD0MLmR3lP7elATNTmHawpBH6IqWX9eKVSJ8M
9wIDAQAB
-----END PUBLIC KEY-----
```

There you have two ready to use key.

*** WARNING !!!, the key shown here are only demonstrational purpose ***

## Configuring the Server