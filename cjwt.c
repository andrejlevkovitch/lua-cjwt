// cjwt.c

#include <jansson.h>
#include <jwt.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <stdlib.h>
#include <string.h>

#define OUTPUT

#define DEAD_BEAF(ptr) ptr = (void *)0xdeadbeaf


/**\
 * Push decoded json to lua stack as table
 */
static void json_object_to_table(lua_State *state, const json_t *json);
/**\
 * Same as json_object_to_table, but works with arrays
 */
static void json_array_to_table(lua_State *state, const json_t *json);

/**\
 * Get table from top of stack and put data from it to json_t object
 */
static void table_to_json_object(lua_State *state, OUTPUT json_t *json);
/**\
 * Same as table_to_json_object but works with arrays
 */
static void table_to_json_array(lua_State *state, OUTPUT json_t *json);


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


  // XXX after successful decoding jwt token we can be confident, that we got
  // valid json objects in headers and grants
  char *headers_json = jwt_get_headers_json(jwt, NULL);
  char *grants_json  = jwt_get_grants_json(jwt, NULL);

  json_t *headers = json_loads(headers_json, 0, NULL);
  json_t *grants  = json_loads(grants_json, 0, NULL);


  // header
  json_object_to_table(state, headers);

  // claim
  json_object_to_table(state, grants);


  json_decref(headers);
  json_decref(grants);

  jwt_free_str(headers_json);
  jwt_free_str(grants_json);

  jwt_free(jwt);

  DEAD_BEAF(headers);
  DEAD_BEAF(grants);
  DEAD_BEAF(headers_json);
  DEAD_BEAF(grants_json);
  DEAD_BEAF(jwt);

  return 2;
}


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

/**
 * Encode jwt token. Required 3 arguments: header and claim as tables, and
 * private_key as string. Return encoded jwt token as string or nil and error
 * string in case of error
 */
static int lua_encode_jwt(lua_State *state) {
  luaL_checktype(state, 1, LUA_TTABLE);
  luaL_checktype(state, 2, LUA_TTABLE);

  size_t               key_length = 0;
  const unsigned char *private_key =
      (const unsigned char *)luaL_checklstring(state, 3, &key_length);


  lua_getfield(state, 1, "alg");
  const char *alg = lua_tostring(state, -1);
  if (alg == NULL) {
    lua_pushnil(state);
    lua_pushstring(state, "algorithm doesn't set");
    return 2;
  }


  int count = 0;


  json_t *headers      = NULL;
  json_t *grants       = NULL;
  jwt_t * jwt          = NULL;
  char *  headers_json = NULL;
  char *  grants_json  = NULL;
  char *  token        = NULL;

  jwt_alg_t jwt_alg = jwt_str_alg(alg);
  if (jwt_alg == JWT_ALG_INVAL) {
    lua_pushnil(state);
    lua_pushstring(state, "not supported alg");

    count = 2;
    goto final;
  }


  headers = json_object();
  grants  = json_object();

  lua_pushvalue(state, 1);
  table_to_json_object(state, headers);
  lua_pushvalue(state, 2);
  table_to_json_object(state, grants);


  headers_json = json_dumps(headers, JSON_COMPACT | JSON_ENSURE_ASCII);
  grants_json  = json_dumps(grants, JSON_COMPACT | JSON_ENSURE_ASCII);


  CHECK_JWT_ERROR(jwt_new(&jwt));

  CHECK_JWT_ERROR(jwt_set_alg(jwt, jwt_alg, private_key, key_length));

  CHECK_JWT_ERROR(jwt_add_headers_json(jwt, headers_json));
  CHECK_JWT_ERROR(jwt_add_grants_json(jwt, grants_json));


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

  free(headers_json);
  free(grants_json);

  json_decref(headers);
  json_decref(grants);

  DEAD_BEAF(token);
  DEAD_BEAF(jwt);
  DEAD_BEAF(headers_json);
  DEAD_BEAF(grants_json);
  DEAD_BEAF(headers);
  DEAD_BEAF(grants);

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


static void json_object_to_table(lua_State *state, const json_t *json) {
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
      json_object_to_table(state, val);
      lua_setfield(state, -2, key);
      break;
    case JSON_ARRAY:
      json_array_to_table(state, val);
      lua_setfield(state, -2, key);
    case JSON_NULL:
      // does nothing
      break;
    }
  }
}

static void json_array_to_table(lua_State *state, const json_t *json) {
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
      json_object_to_table(state, val);
      lua_settable(state, -3);
      break;
    case JSON_ARRAY:
      lua_pushnumber(state, lua_index);
      json_array_to_table(state, val);
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
static void table_to_json_object(lua_State *state, OUTPUT json_t *json) {
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
        table_to_json_object(state, nested);
      } else { // then table encode to array
        nested = json_array();
        table_to_json_array(state, nested);
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
static void table_to_json_array(lua_State *state, OUTPUT json_t *json) {
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
        table_to_json_object(state, nested);
      } else { // then table encode to array
        nested = json_array();
        table_to_json_array(state, nested);
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
