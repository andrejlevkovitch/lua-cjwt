local cjwt = require("cjwt")
local cjson = require("cjson")

local private_key = [[
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAszI+Xv1vZQnCnoPbM2xduqUURdFAh58Vnlvdt+JW6/YPOY9n
Y+blgiln1vOyvhlfcczl+1QEHMWgZrmmF5TFvU8daAlvzxt4fCZW1eX8kp6Ngggs
qNtpqGPT+3qLhDIBMh9NDmLPkjSeZsBqFKf1Oqz+85Bmjf5hZqJa6QkYcMgQ27OJ
DhHnBTNfvmHh99yYWKmgOf+7H88kSAVzzycCUx204TMkqLq/BQlqPQI/qJK+Lc+f
uTND5A8T5paolaoKVBnlB5Wdzxi8g8GglLX5F10acrs3z0fPy0imv4JGP5LBNXBY
cNTd1cHOuofUkHa8Xr4DDh8aiqOhnzZu94sC9wIDAQABAoIBAHVytuJ3ZS1p6j8O
2PqpSf1s+Q6RiaPaJsc2GunM1X+uNGhbjz4xNbfL/50o+LwT0TS7QPkrJc7d0LXD
dBL8lWXwlqt7k+bAcIWec0eah6JpfQH+7ZZ2yJdvZp7qwMqSI6qATXbiWH3RMwjR
kDWdp+MfQ7LLsAvc8GXef4tBRN2VihROtxp5ONVKHUXiJPD1HJTSM5Oy06Om2IRx
uQmy4ZwJAhTf9D663p+VLrsv+qUQQFgY5ggmVoX8FNdAdPRLi7LTo9csgq+qpH0/
Hfyyq6l2+CTmuMExvHPVRzg1sARu8Boabdl1E+PxgieS/HmZ6LP2oFtBc46WJPkY
8mQbQsECgYEA4naQ5IMoK813oV0rq6dZBURzU3u+DO3u2RjpvhvnCV15lBhChbBr
0VgdT1t0Wc61+eMdZaSs28CCLdpHWM+WmpLWySCYDRRiGUxhr2R5LWuSDsAZ2O4I
UqEITxITctU3VQWSySTzc/TyGTmW8poGkNijvIRq89SZZOPr1LqVEMcCgYEAypF4
022BToTG35OBK6C7wUSvWqqAz6+4xFEHxWnxrQmOKMikR8Xnsgzgk6ZJALlK1kna
urYtnNufhjSdVkDq6+J/j9c06NO2jZ5Q3kXeLLVxweEyEPYLhWFbm8ozpJ4tq+dU
rIMooDzrLvKEabBoUCdnhn/3aM5GSpxWG6sNrFECgYEA23njZMPD++euqEGe4EZY
nSVAy8jiYK97ywU9C5UJLWddO+zjE6Puaj4GcfGFasBOVvcId4jISlVhFMU2XlkZ
cYccCGLBWfPGOxRum8g5NI7LR+ZfZoESqdoNLmyrUqBXdtvm7XAVTe03cMECjO4/
rMN4tGx1JwiE/WVzGoEVlOMCgYBv3nDMyp/rnfY6iLqAPo8SB/2TY7ApglDW0i0p
f/3A4xMIQO5A2PHA6c2onN+aL7o9p6HNFUkRZFSwCCSP+uACDx8FcAM/RZR+l1zv
s8QkCrxdJyHALjFkosS1v7BPjC+KzQF9GB36iEoVrkckGxEwmuJYbBlVXv2AvN/s
/cVaUQKBgQC6T4UY9I5kexwQebZrEophR7EqH5Pk2iB+uStSMH287OTbMx5hUM+E
T0uFLaaxGZ2ys7t5lEdXDZJEL0+ClSyUr8q1xjPMetSo5bb7x96wG+i6R5qrEcwi
TGTVYpN50yiOnY62/+IdhEMNkjBylEtSD5fScICJoqstOlvFRwbqyw==
-----END RSA PRIVATE KEY-----
]]

local public_key = [[
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAszI+Xv1vZQnCnoPbM2xd
uqUURdFAh58Vnlvdt+JW6/YPOY9nY+blgiln1vOyvhlfcczl+1QEHMWgZrmmF5TF
vU8daAlvzxt4fCZW1eX8kp6NgggsqNtpqGPT+3qLhDIBMh9NDmLPkjSeZsBqFKf1
Oqz+85Bmjf5hZqJa6QkYcMgQ27OJDhHnBTNfvmHh99yYWKmgOf+7H88kSAVzzycC
Ux204TMkqLq/BQlqPQI/qJK+Lc+fuTND5A8T5paolaoKVBnlB5Wdzxi8g8GglLX5
F10acrs3z0fPy0imv4JGP5LBNXBYcNTd1cHOuofUkHa8Xr4DDh8aiqOhnzZu94sC
9wIDAQAB
-----END PUBLIC KEY-----
]]

local header = {alg = "RS256"}
local claim = {
  iss = "iss",
  sub = "sub",
  aud = "https://aud.com",
  iat = os.time(),
  exp = os.time() + 3600,
}

local token, err = cjwt.encode(header, claim, private_key)
if (token == nil) then
  print(err)
  return
end

local out_header, out_claim = cjwt.decode(token, public_key)

print(cjson.encode(out_header))
print(cjson.encode(out_claim))
print(token)
