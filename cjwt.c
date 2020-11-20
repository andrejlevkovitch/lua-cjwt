// cjwt.c

#include <jansson.h>
#include <jwt.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <stdlib.h>
#include <string.h>


#define DEAD_BEAF (void *)0xdeadbeaf


#define CHECK_JWT_ERROR(val)                                                   \
  {                                                                            \
    int err = val;                                                             \
    if (err) {                                                                 \
      const char *err_message = strerror(err);                                 \
      lua_pushnil(state);                                                      \
      lua_pushstring(state, err_message);                                      \
      count = 2;                                                               \
      goto final;                                                              \
    }                                                                          \
  }


static void json_object_to_table(const json_t *json, lua_State *state);
static void json_array_to_table(const json_t *json, lua_State *state);

static void table_to_json_object(json_t *json, lua_State *state);
static void table_to_json_array(json_t *json, lua_State *state);


/**
 * Decode jwt token. Apply 2 arguments: encoded jwt token and public key. Second
 * argument is not required. If second parameter is set, then token will be
 * verified. Return header and claim as tables or nil and error string in case
 * of failure
 */
static int lua_decode_jwt(lua_State *state) {
  const char *token = luaL_checkstring(state, 1);

  const unsigned char *private_key        = NULL;
  size_t               private_key_length = 0;

  if (lua_gettop(state) == 2) {
    private_key =
        (const unsigned char *)luaL_checklstring(state, 2, &private_key_length);
  }

  jwt_t *jwt = NULL;
  int    err = jwt_decode(&jwt, token, private_key, private_key_length);
  if (err) {
    const char *err_message = strerror(err);

    lua_pushnil(state);
    lua_pushstring(state, err_message);

    return 2;
  }


  // iterate over header and grants and push it to lua tables
  const json_t *headers = jwt_get_headers(jwt);
  const json_t *grants  = jwt_get_grants(jwt);

  // header
  json_object_to_table(headers, state);

  // claim
  json_object_to_table(grants, state);

  jwt_free(jwt);
  return 2;
}


/**
 * Encode jwt token. Required 3 arguments: header and claim as tables, and
 * private_key as string. Return encoded jwt token as string or nil and error
 * string in case of error
 */
static int lua_encode_jwt(lua_State *state) {
  if ((lua_istable(state, 1) && lua_istable(state, 2)) == 0) {
    luaL_error(state, "invalid header or claim");
  }

  size_t               key_length = 0;
  const unsigned char *private_key =
      (const unsigned char *)luaL_checklstring(state, 3, &key_length);


  lua_getfield(state, 1, "alg");
  const char *alg = lua_tostring(state, -1);
  if (alg == NULL) {
    luaL_error(state, "algorithm doesn't set");
  }


  int count = 0;


  json_t *j_header = NULL;
  json_t *j_claim  = NULL;
  jwt_t * jwt      = NULL;
  char *  token    = NULL;

  jwt_alg_t jwt_alg = jwt_str_alg(alg);
  if (jwt_alg == JWT_ALG_INVAL) {
    lua_pushnil(state);
    lua_pushstring(state, "not supported alg");

    count = 2;
    goto final;
  }


  j_header = json_object();
  j_claim  = json_object();
  if (j_header == NULL || j_claim == NULL) {
    lua_pushnil(state);
    lua_pushstring(state, "allocate memory error");

    count = 2;
    goto final;
  }

  lua_pushvalue(state, 1);
  table_to_json_object(j_header, state);
  lua_pushvalue(state, 2);
  table_to_json_object(j_claim, state);


  CHECK_JWT_ERROR(jwt_new(&jwt));

  CHECK_JWT_ERROR(jwt_set_alg(jwt, jwt_alg, private_key, key_length));

  CHECK_JWT_ERROR(jwt_add_headers(jwt, j_header));
  CHECK_JWT_ERROR(jwt_add_grants(jwt, j_claim));


  token = jwt_encode_str(jwt);
  if (token == NULL) {
    lua_pushnil(state);
    lua_pushstring(state, "can't encode jwt token");

    count = 2;
    goto final;
  }


  lua_pushstring(state, token);
  count = 1;


final:
  jwt_free_str(token);
  jwt_free(jwt);

  json_decref(j_header);
  json_decref(j_claim);
  return count;
}


int luaopen_cjwt(lua_State *state) {
  luaL_Reg cjwt[] = {{"decode", lua_decode_jwt},
                     {"encode", lua_encode_jwt},
                     {NULL, NULL}};

  luaL_register(state, "cjwt", cjwt);
  return 1;
}


///////////////////////////////////////////////////////////////////////////////


static void json_object_to_table(const json_t *json, lua_State *state) {
  lua_newtable(state);

  json_t *json_ = (json_t *)json; // XXX need for getting iterator. We doesn't
                                  // change original object, so it is safe
  const char *key;
  json_t *    val;
  json_object_foreach(json_, key, val) {
    switch (json_typeof(val)) {
    case JSON_FALSE:
      lua_pushboolean(state, 0);
      lua_setfield(state, -2, key);
      break;
    case JSON_TRUE:
      lua_pushboolean(state, 1);
      lua_setfield(state, -2, key);
      break;
    case JSON_STRING: {
      const char *str = json_string_value(val);
      lua_pushstring(state, str);
      lua_setfield(state, -2, key);
    } break;
    case JSON_INTEGER:
    case JSON_REAL: {
      double num = json_number_value(val);
      lua_pushnumber(state, num);
      lua_setfield(state, -2, key);
    } break;
    case JSON_OBJECT:
      json_object_to_table(val, state);
      lua_setfield(state, -2, key);
      break;
    case JSON_ARRAY:
      json_array_to_table(val, state);
      lua_setfield(state, -2, key);
    case JSON_NULL:
      // does nothing
      break;
    }
  }
}

static void json_array_to_table(const json_t *json, lua_State *state) {
  lua_newtable(state);

  size_t  index;
  json_t *val;
  json_array_foreach(json, index, val) {
    int lua_index = index + 1;

    switch (json_typeof(val)) {
    case JSON_FALSE:
      lua_pushnumber(state, lua_index);
      lua_pushboolean(state, 0);
      lua_settable(state, -3);
      break;
    case JSON_TRUE:
      lua_pushnumber(state, lua_index);
      lua_pushboolean(state, 1);
      lua_settable(state, -3);
      break;
    case JSON_STRING: {
      const char *str = json_string_value(val);
      lua_pushnumber(state, lua_index);
      lua_pushstring(state, str);
      lua_settable(state, -3);
    } break;
    case JSON_INTEGER:
    case JSON_REAL: {
      double num = json_number_value(val);
      lua_pushnumber(state, lua_index);
      lua_pushnumber(state, num);
      lua_settable(state, -3);
    } break;
    case JSON_OBJECT:
      lua_pushnumber(state, lua_index);
      json_object_to_table(val, state);
      lua_settable(state, -3);
      break;
    case JSON_ARRAY:
      lua_pushnumber(state, lua_index);
      json_array_to_table(val, state);
      lua_settable(state, -3);
    case JSON_NULL:
      // does nothing
      break;
    }
  }
}


/**
 * Convert lua table to json object. Note that converted table must be on top of
 * stack
 */
static void table_to_json_object(json_t *json, lua_State *state) {
  lua_pushnil(state);
  while (lua_next(state, -2) != 0) {
    const char *key = luaL_checkstring(state, -2);

    switch (lua_type(state, -1)) {
    case LUA_TBOOLEAN: {
      int val = lua_toboolean(state, -1);
      json_object_set_new(json, key, val ? json_true() : json_false());
    } break;
    case LUA_TSTRING: {
      const char *val = lua_tostring(state, -1);
      json_object_set_new(json, key, json_string(val));
    } break;
    case LUA_TNUMBER: {
      double val = lua_tonumber(state, -1);
      json_object_set_new(json, key, json_real(val));
    } break;
    case LUA_TTABLE: {
      int     len    = lua_objlen(state, -1);
      json_t *nested = NULL;
      if (len == 0) { // then table encode to object
        nested = json_object();
        table_to_json_object(nested, state);
      } else { // then table encode to array
        nested = json_array();
        table_to_json_array(nested, state);
      }

      if (nested == NULL) {
        break;
      }

      json_object_set_new(json, key, nested);
    } break;
    default:
      break;
    }

    lua_pop(state, 1);
  }
}

/**
 * Same as table_to_json_object, but encode to array
 */
static void table_to_json_array(json_t *json, lua_State *state) {
  lua_pushnil(state);
  while (lua_next(state, -2) != 0) {
    switch (lua_type(state, -1)) {
    case LUA_TBOOLEAN: {
      int val = lua_toboolean(state, -1);
      json_array_append_new(json, val ? json_true() : json_false());
    } break;
    case LUA_TSTRING: {
      const char *val = lua_tostring(state, -1);
      json_array_append_new(json, json_string(val));
    } break;
    case LUA_TNUMBER: {
      double val = lua_tonumber(state, -1);
      json_array_append_new(json, json_real(val));
    } break;
    case LUA_TTABLE: {
      int     len    = lua_objlen(state, -1);
      json_t *nested = NULL;
      if (len == 0) { // then table encode to object
        nested = json_object();
        table_to_json_object(nested, state);
      } else { // then table encode to array
        nested = json_array();
        table_to_json_array(nested, state);
      }

      if (nested == NULL) {
        break;
      }

      json_array_append_new(json, nested);
    } break;
    default:
      break;
    }

    lua_pop(state, 1);
  }
}
