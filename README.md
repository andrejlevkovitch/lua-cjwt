# lua-cjwt

Provides functionality for creating and validating jwt tokens in lua.
Wrap around [libjwt](https://github.com/benmcollins/libjwt)


## Usage

For using in lua you need call

```lua
local cjwt = require("cjwt")
```

Module provides only two functions:

- `cjwt.encode(headers, claims, private_key)` - return token in case of success,
otherwise return nil and error string. `headers` and `claims` must be a lua tables.
`headers` must contains field `alg` for valid sign algoritm

- `cjwt.decode(token [, public_key])` - if public_key is set, then also verify
the token. Return `headers` and `claims` as lua tables in case of success,
otherwise return `nil` and error message as string
