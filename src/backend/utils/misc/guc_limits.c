#include "postgres.h"

#include <unistd.h>

#include "access/xact.h"
#include "miscadmin.h"
#include "storage/fd.h"
#include "utils/builtins.h"
#include "utils/acl.h"
#include "utils/elog.h"
#include "utils/jsonapi.h"
#include "utils/memutils.h"
#include "utils/fmgrprotos.h"
#include "utils/guc.h"
#include "utils/guc_tables.h"

#define PG_CONF_LIMITS_FILENAME		"guc_limits.json"

/* The file raw text. */
static char	*limits_file = NULL;

/* Bytes of the file already residing in limits_file. */
static Size limits_file_size = 0;

/* Size of memory allocated for the file. */
static Size	limits_file_mem_size = 0;

/*
 * The amount of memory added by each realloc() when reading the limits file.
 */
#define MEM_SIZE_UNIT	1024

/* Have we parsed and validated the most recent version that we had read? */
static bool limits_file_processed = false;

/*
 * Array indexes to store limit fields.
 */
typedef enum LimitField
{
	LIMIT_FIELD_VAR_NAME = 0,
	LIMIT_FIELD_ROLES,
	LIMIT_FIELD_MIN,
	LIMIT_FIELD_MAX,
	LIMIT_FIELD_INCLUDE_MIN,
	LIMIT_FIELD_INCLUDE_MAX,
	LIMIT_FIELD_VALUE,
	LIMIT_FIELD_VALUES,
	LIMIT_FIELD_ALLOW_EMPTY,

	/* This determines the array size, i.e. not actual index */
	LIMIT_FIELDS_TOTAL
} LimitField;

/* Names of the fields enumerated above. */
static char	*limit_field_names[LIMIT_FIELDS_TOTAL] = {
	"var_name", "roles", "min", "max", "include_min", "include_max", "value",
	"values", "allow_empty"};

/*
 * Here we declare for each limit data type which fields it can have set in
 * the input file.
 */
static bool limit_fields_allowed[][LIMIT_FIELDS_TOTAL] =
{
	/* PGC_BOOL */
	{true, true, false, false, false, false, true, false, false},

	/* PGC_INT */
	{true, true, true, true, false, false, false, false, false},

	/* PGC_REAL */
	{true, true, true, true, true, true, false, false, false},

	/* PGC_STRING */
	{true, true, false, false, false, false, true, false, true},

	/* PGC_ENUM */
	{true, true, false, false, false, false, false, true, false}
};

/*
 * Limit on boolean GUC.
 */
typedef struct GUCLimitBool
{
	bool	value;
} GUCLimitBool;

/*
 * Limit on integer GUC.
 */
typedef struct GUCLimitInt
{
	int		min;
	int		max;

	/* Auxiliary fields, not expected in the input file. */
	bool	has_min;
	bool	has_max;
} GUCLimitInt;

/*
 * Limit on real number GUC.
 */
typedef struct GUCLimitReal
{
	double	min;
	double	max;

	/* Are the min and max values allowed themselves? */
	double	include_min;
	double	include_max;

	/* Auxiliary fields, not expected in the input file. */
	bool	has_min;
	bool	has_max;
} GUCLimitReal;

/*
 * Limit on string GUC.
 */
typedef struct GUCLimitString
{
	char	*value;
	bool	allow_empty;
} GUCLimitString;

/*
 * Limit on enumeration GUC.
 */
typedef struct GUCLimitEnum
{
	List	*values;
} GUCLimitEnum;

/*
 *
 * TODO
 *
 * 1. Let user specify whether the boundaries are inclusive.
 *
 * 2. Design more generic structure if we want to support GUCs of other types.
 *
 * 3. For boolean vars, check the JSON_TOKEN_TRUE and JSON_TOKEN_FALSE tokens
 * (if "true" and "false" JSON_TOKEN_STRING, these should also be considered
 * valid?)
 */
typedef struct GUCLimit
{
	char	*var_name;
	enum config_type vartype;
	int		var_flags;

	/* List of roles to which the limit applies. */
	List	*roles;

	union
	{
		GUCLimitBool	b;
		GUCLimitInt		i;
		GUCLimitReal	r;
		GUCLimitString	s;
		GUCLimitEnum	e;
	} value;
} GUCLimit;

/* Array of limits. */
/* TODO Add an array of pointers, sorted by var_name, but keep in mind that
 * there can be multiple entries of the same var_name. Also make sure that the
 * array is in guc_limits_context. */
static GUCLimit	*guc_limits = NULL;
/* Size of the array. */
static int guc_limits_count = 0;

/* Memory context to store the limits. */
static MemoryContext   guc_limits_ctx = NULL;

/*
 * Since there seems to be no exported function to return the in-memory
 * representation of jsonb data type (JsonbValue), it still seems simpler to
 * implement parser here than to use both jsonb and jsonpath API.
 *
 * JsonNode is a node of an AST that we eventually turn to the array of
 * GUCLimit structures.
 */
typedef enum JsonNodeKind
{
	JSON_NODE_ARRAY,
	JSON_NODE_OBJECT,
	JSON_NODE_OBJECT_FIELD,			/* key/value pair */
	JSON_NODE_SCALAR
} JsonNodeKind;

typedef struct JsonNode
{
	JsonNodeKind	kind;

	/*
	 * For JSON_NODE_ARRAY, this is a list of elements, for JSON_NODE_OBJECT
	 * it's a list of JSON_NODE_FIELD nodes, for JSON_NODE_OBJECT_FIELD it's a
	 * 2 element list containing the key and the value and for
	 * JSON_NODE_SCALAR it's a 1-element list containing the scalar value
	 * (unparsed, i.e. still string).
	 */
	List	*fields;

	/* Pointer to the parent node - only needed during parsing. */
	struct JsonNode	*parent;
} JsonNode;

static void process_limits_file(void);
static void guc_limits_error_callback(void *arg);
static bool validate_limit(GUCLimit *limit, JsonNode *node);
static bool validate_limit_bool(GUCLimit *limit, void *fields_raw[]);
static bool validate_limit_int(GUCLimit *limit, void *fields_raw[]);
static bool validate_limit_real(GUCLimit *limit, void *fields_raw[]);
static bool validate_limit_string(GUCLimit *limit, void *fields_raw[]);
static bool validate_limit_enum(GUCLimit *limit, void *fields_raw[],
								const struct config_enum_entry *options);
static bool add_limit_field(void *fields_raw[], char *var_name, char *key,
							void *value, LimitField index);
static void *get_limit_field(void *fields_raw[], LimitField index);
static bool parse_limit_field_bool(char *value_str, char *var_name,
								   bool *success);
static int parse_limit_field_int(char *value_str, char *var_name,
								 int var_flags, bool *success);
static double parse_limit_field_real(char *value_str, char *var_name,
									 int var_flags, bool *success);
static void discard_limits(MemoryContext parse_ctx, MemoryContext old_ctx);
static void report_int_limit_violation(int new_value, char *var_name,
									   int var_flags, int limit_value,
									   char *role, bool is_min, int elevel);
static void report_real_limit_violation(double new_value, char *var_name,
										int var_flags,
										double limit_value, char *role,
										bool is_min, bool is_inclusive,
										int elevel);

/*
 * Reset the state variables before trying to read the file again.
 */
static void
limits_file_reset(void)
{
	if (limits_file)
		free(limits_file);
	limits_file = NULL;
	limits_file_size = 0;
	limits_file_mem_size = 0;
	limits_file_processed = false;
}

/*
 * Read PG_CONF_LIMITS_FILENAME file if there's one in DataDir.
 *
 * Memory to store the actual file needs to be allocated using malloc() /
 * realloc(). Caller is supposed to set memory context for any other
 * (temporary) allocations that might be needed, and eventually to delete it.
 */
void
read_limits_file(void)
{
	char		lf_path[MAXPGPATH];
	int	fd;
	int	nread;
	Size	nread_total = 0;

	/*
	 * If the previous read was successful, make sure the corresponding memory
	 * is freed.
	 */
	limits_file_reset();

	/* This should only happen during postmaster startup. */
	if (DataDir == NULL)
		return;

	strlcpy(lf_path, DataDir, sizeof(lf_path));
	join_path_components(lf_path, lf_path, PG_CONF_LIMITS_FILENAME);
	canonicalize_path(lf_path);

	fd = OpenTransientFile(lf_path, O_RDONLY);
	if (fd < 0)
	{
		ereport(DEBUG2, (errmsg("could not open limits file \"%s\"", lf_path)));
		return;
	}

	limits_file_mem_size = MEM_SIZE_UNIT;
	limits_file = (char *) malloc(limits_file_mem_size);
	if (limits_file == NULL)
		goto fail;

	while ((nread = read(fd, limits_file + nread_total,
						 limits_file_mem_size - 1 - nread_total)) > 0)
	{
		if (nread < 0)
			goto fail;
		else if (nread == 0)
			/* EOF */
			break;

		nread_total += nread;

		/*
		 * Make sure there's enough space for the next read, as well for the
		 * terminating NULL character.
		 */
		if (nread_total >= limits_file_mem_size - 1)
		{
			limits_file_mem_size += MEM_SIZE_UNIT;
			limits_file = (char *) realloc(limits_file, limits_file_mem_size);
		}

		if (limits_file == NULL)
			goto fail;
	}
	Assert(nread_total < limits_file_mem_size);
	limits_file[nread_total] = '\0';

	CloseTransientFile(fd);
	ereport(DEBUG1, (errmsg("limits file \"%s\" read", lf_path)));
	return;

fail:
	/*
	 * ERROR is not suitable here because the function can be run by signal
	 * handler.
	 */
	ereport(LOG, (errmsg("failed to read data from \"%s\"", lf_path)));
	CloseTransientFile(fd);

	/*
	 * Reset the state variables so that we don't try to parse the fragment
	 * that might have been read.
	 */
	limits_file_reset();
}

/*
 * Check if value violates a limit on GUC variable imposed on role, and if the
 * value passed is outside the limit. If role is InvalidOid, CurrentUserId is
 * checked.
 *
 * Returns true if all checks passed or skipped, false if at least one check
 * failed. Sometimes it's easier to pass elevel=ERROR, in which case the
 * function does not return.
 */
bool
check_guc_limits(const char *var_name, union config_var_val *value,
				 Oid role, enum config_type var_type, int elevel)
{
	int	i;
	char	*role_str;

	/*
	 * Database will be accessed so we need a transaction. Caller needs to
	 * ensure that the function is called at the appropriate stage of startup.
	 */
	if (!IsTransactionState())
		return true;

	/*
	 * Parse the input file if not done yet since the last reading.
	 */
	/*
	 * TODO Remove this when no more debugging is needed.
	 */
	limits_file_processed = false;

	if (!limits_file_processed)
	{
		/* No limit information available? */
		if (limits_file == NULL)
			return true;

		process_limits_file();
	}

	/* The file could have been empty. */
	if (guc_limits_count == 0)
		return true;

	if (!OidIsValid(role))
		role = GetUserId();

	/* Allow ERROR because the role can be dropped concurrently. */
	role_str = GetUserNameFromId(role, false);

	/* Is there any limit for this variable? */
	for (i = 0; i < guc_limits_count; i++)
	{
		GUCLimit	*limit = &guc_limits[i];
		ListCell	*lc;
		bool	match = false;

		if (strcmp(limit->var_name, var_name) != 0)
			continue;

		/* Does the limit apply to the current user? */
		foreach(lc, limit->roles)
		{
			char	*limit_role_str = (char *) lfirst(lc);
			Oid	limit_role_oid = get_role_oid(limit_role_str, true);

			if (!OidIsValid(limit_role_oid))
			{
				/*
				 * Always use LOG here (XXX shouldn't it be WARNING?) because
				 * elevel can be ERROR and we don't consider invalid role id
				 * to be the actual limit violation.
				 *
				 * We might want to remove the role from the list, but DBA
				 * might have added new role to the file that he's going to
				 * create in the catalog soon.
				 */
				ereport(LOG,
						(errmsg("role \"%s\" is mentioned in the \"%s\" file but does not exist in the system catalog",
								limit_role_str,
								PG_CONF_LIMITS_FILENAME)));
				continue;
			}

			/*
			 * Does this limit affect "role"?
			 *
			 * Since superuser is member of any role, we ignore superusers
			 * here so that no limits apply to them.
			 */
			if (is_member_of_role(role, limit_role_oid) &&
				!superuser_arg(role))
			{
				match = true;
				break;
			}
		}

		if (!match)
			continue;

		Assert(var_type == limit->vartype);
		switch (var_type)
		{
			case PGC_BOOL:
				{
					int	val_bool = value->boolval;
					GUCLimitBool	*lim_bool = &limit->value.b;

					if (lim_bool->value != val_bool)
					{
						ereport(elevel,
								(errmsg("\"%s\" role can only set value of the \"%s\" configuration variable to %s",
										role_str,
										var_name,
										lim_bool->value ? "true" : "false")));

						return false;
					}
				}
			break;

			case PGC_INT:
				{
					int	val_int = value->intval;
					GUCLimitInt	*lim_int = &limit->value.i;

					if (lim_int->has_min && val_int < lim_int->min)
					{
						report_int_limit_violation(val_int,
												   limit->var_name,
												   limit->var_flags,
												   lim_int->min,
												   role_str,
												   true,
												   elevel);

						return false;
					}

					if (lim_int->has_max && val_int > lim_int->max)
					{
						report_int_limit_violation(val_int,
												   limit->var_name,
												   limit->var_flags,
												   lim_int->max,
												   role_str,
												   false,
												   elevel);

						return false;
					}
				}
				break;

			case PGC_REAL:
				{
					double	val_real = value->realval;
					GUCLimitReal	*lim_real = &limit->value.r;

					if (lim_real->has_min &&
						((lim_real->include_min && val_real < lim_real->min)
						 ||
						 (!lim_real->include_min && val_real <= lim_real->min)))
					{
						report_real_limit_violation(val_real,
													limit->var_name,
													limit->var_flags,
													lim_real->min,
													role_str,
													true,
													lim_real->include_min,
													elevel);

						return false;
					}

					if (lim_real->has_max &&
						((lim_real->include_max && val_real > lim_real->max)
						 ||
						 (!lim_real->include_max && val_real >= lim_real->max)))
					{
						report_real_limit_violation(val_real,
													limit->var_name,
													limit->var_flags,
													lim_real->max,
													role_str,
													false,
													lim_real->include_max,
													elevel);

						return false;
					}
				}
				break;

			case PGC_STRING:
				{
					char	*val_str = value->stringval;
					GUCLimitString	*lim_str = &limit->value.s;

					if (lim_str->allow_empty && strlen(val_str) == 0)
						return true;

					if (strcmp(lim_str->value, val_str) != 0)
					{
						/* TODO Escape the variable values. */
						ereport(elevel,
								(errmsg("\"%s\" role can only set value of the \"%s\" configuration variable to \"%s\" but %s tried",
										role_str,
										var_name,
										lim_str->value,
										val_str)));

						return false;
					}
				}
				break;

			case PGC_ENUM:
				{
					struct config_enum *en;
					GUCLimitEnum	*lim_enum;
					const struct config_enum_entry *entry;
					const char	*entry_str = NULL;
					ListCell	*lc;
					bool	found = false;

					en = (struct config_enum *) get_guc_variable(var_name);
					for (entry = en->options; entry && entry->name; entry++)
					{
						if (entry->val == value->enumval)
						{
							entry_str = entry->name;
							break;
						}

					}
					/*
					 * If value->enumval was not valid, the GUC subsystem
					 * messed up.
					 */
					Assert(entry_str != NULL);

					/*
					 * Finally check if the value is in the list of
					 * role-specific values.
					 */
					lim_enum = &limit->value.e;
					foreach(lc, lim_enum->values)
					{
						char	*lim_entry_str = (char *) lfirst(lc);

						if (strcmp(lim_entry_str, entry_str) == 0)
						{
							found = true;
							break;
						}
					}

					if (!found)
					{
						/* TODO Escape the variable value. */
						ereport(elevel,
								(errmsg("\"%s\" role cannot set the \"%s\" configuration variable to \"%s\"",
										role_str,
										var_name,
										entry_str)));

						return false;
					}
				}
				break;

#ifdef USE_ASSERT_CHECKING
			default:
				/* Should not happen. */
				Assert(false);
#endif	/* USE_ASSERT_CHECKING */
		}

		/* XXX Should we disallow multiple limits per variable and role? */
	}
	pfree(role_str);

	return true;
}

/*
 * Call check_guc_limits() for all configuration variables and raise ERROR
 * error if any limit is violated.
 *
 * Besides backend startup the function is called before each command
 * execution because GRANT command could have imposed new restrictions on some
 * GUC variable(s).
 */
void
check_guc_limits_all(Oid role)
{
	struct config_generic **vars_all = get_guc_variables();
	int	nvars = GetNumConfigOptions();
	int	i;

	for (i = 0; i < nvars; i++)
	{
		struct config_generic *var = vars_all[i];
		union config_var_val	val;

		switch (var->vartype)
		{
			case PGC_BOOL:
				{
					struct config_bool	*var_bool;

					var_bool = (struct config_bool *) var;
					val.boolval = *var_bool->variable;
				}
				break;

			case PGC_INT:
				{
					struct config_int	*var_int;

					var_int = (struct config_int *) var;
					val.intval = *var_int->variable;
				}
				break;

			case PGC_REAL:
				{
					struct config_real	*var_real;

					var_real = (struct config_real *) var;
					val.realval = *var_real->variable;
				}
				break;

			case PGC_STRING:
				{
					struct config_string	*var_string;

					var_string = (struct config_string *) var;
					val.stringval = *var_string->variable;
				}
				break;

			case PGC_ENUM:
				{
					struct config_enum	*var_enum;

					var_enum = (struct config_enum *) var;
					val.enumval = *var_enum->variable;
				}
				break;

#ifdef USE_ASSERT_CHECKING
			default:
				/* Should not happen */
				Assert(false);
				break;
#endif	/* USE_ASSERT_CHECKING */
		}

		check_guc_limits(var->name, &val, role, var->vartype, ERROR);
	}
}

/*
 * Create a new node and add it to the parent's children.
 */
static JsonNode *
makeJsonNode(JsonNodeKind kind, JsonNode *parent)
{
	JsonNode	*result = palloc0(sizeof(JsonNode));

	result->kind = kind;
	result->parent = parent;

	if (parent)
		parent->fields = lappend(parent->fields, result);

	return result;
}

/*
 * State to be passed by the parser to the semantic actions below.
 */
typedef struct JsonParseState
{
	JsonNode	*node;			/* The node being parsed. */
	JsonNode	*result;		/* The tree. Once set, parsing stops. */
} JsonParseState;

/*
 * Semantic actions for our json parser.
 */
static void
json_object_start(void *pstate)
{
	JsonParseState	*state = (JsonParseState *) pstate;

	/* state->node is NULL if this is the root object. */
	state->node = makeJsonNode(JSON_NODE_OBJECT, state->node);
}

static void
json_object_end(void *pstate)
{
	JsonParseState	*state = (JsonParseState *) pstate;

	if (state->node->parent == NULL)
	{
		/* Parsing of the 2nd top-level object shouldn't have started. */
		Assert(state->result == NULL);

		state->result = state->node;
	}

	state->node = state->node->parent;
}

static void
json_array_start(void *pstate)
{
	JsonParseState	*state = (JsonParseState *) pstate;

	state->node = makeJsonNode(JSON_NODE_ARRAY, state->node);
}

static void
json_array_end(void *pstate)
{
	JsonParseState	*state = (JsonParseState *) pstate;

	if (state->node->parent == NULL)
	{
		/* Parsing of the 2nd top-level array shouldn't have started. */
		Assert(state->result == NULL);

		state->result = state->node;
	}

	state->node = state->node->parent;
}

static void
json_obj_field_start(void *pstate, char *fname, bool isnull)
{
	JsonParseState	*state = (JsonParseState *) pstate;

	if (isnull)
		return;

	/*
	 * If there's no name, the object will be a direct child of the upper
	 * object and this is handledb by json_object_start().
	 */
	if (fname == NULL || strlen(fname) == 0)
		return;

	state->node = makeJsonNode(JSON_NODE_OBJECT_FIELD, state->node);

	/*
	 * Field name is the first child, value will be the second one. If the
	 * value is NULL, there will be no 2nd value.
	 */
	state->node->fields = lappend(state->node->fields, pstrdup(fname));
}

static void
json_obj_field_end(void *pstate, char *fname, bool isnull)
{
	JsonParseState	*state = (JsonParseState *) pstate;

	/*
	 * If object field contains null value, the whole field is omitted.
	 */
	if (isnull)
		return;

	/* See json_obj_field_start(). */
	if (fname == NULL || strlen(fname) == 0)
		return;

	state->node = state->node->parent;
}

static void
json_scalar(void *pstate, char *token, JsonTokenType tokentype)
{
	JsonParseState	*state = (JsonParseState *) pstate;
	JsonNode	*node = state->node;
	JsonNode	*child;

	/*
	 * If the field is not within any JSON object, just create an empty
	 * "scalar node" and let the AST verification fail later.
	 */
	if (state->node == NULL)
	{
		if (state->result == NULL)
			state->result = makeJsonNode(JSON_NODE_SCALAR, NULL);
		return;
	}

	/*
	 * If object field contains null value, the whole field is omitted, see
	 * json_obj_field_end().
	 */
	if (tokentype == JSON_TOKEN_NULL)
		return;

	Assert(node->kind == JSON_NODE_OBJECT_FIELD ||
		   node->kind == JSON_NODE_ARRAY);

	/*
	 * If the node is a field (key/value pair), exactly the field name must
	 * already be there.
	 */
	Assert(list_length(node->fields) == 1 || node->kind == JSON_NODE_ARRAY);

	child = makeJsonNode(JSON_NODE_SCALAR, node);
	child->fields = lappend(child->fields, pstrdup(token));
}

/*
 * Return value of JSON_NODE_SCALAR node (supposedly a child of
 * JSON_NODE_OBJECT_FIELD node) as a string. NULL is returned if wrong kind of
 * node is passed. var_name, key and is_array_element arguments are passed
 * only for logging purposes.
 */
static char *
get_json_scalar_value(JsonNode *node, char *var_name, char *key,
					 bool is_array_element)
{
	char	*result;

	if (node->kind != JSON_NODE_SCALAR)
	{
		char	*expected_node_msg;

		expected_node_msg = is_array_element ? "JSON array of scalar values" :
			"JSON scalar value";

		ereport(LOG,
				(errmsg("field \"%s\" of the limit on variable \"%s\" in the \"%s\" file must be passed as a %s",
						key,
						var_name,
						PG_CONF_LIMITS_FILENAME,
						expected_node_msg)));

		return NULL;
	}

	/* See json_scalar(). */
	Assert(list_length(node->fields) == 1);

	result = (char *) linitial(node->fields);
	Assert(result);
	return result;
}

/*
 * Return value of JSON_NODE_ARRAY node as a list of strings. NULL is returned
 * if wrong kind of node is passed. var_name and key arguments are passed only
 * for logging purposes.
 */
static List *
get_json_array_value(JsonNode *node, char *var_name, char *key)
{
	ListCell	*lc;
	List	*result = NIL;

	if (node->kind != JSON_NODE_ARRAY)
	{
		ereport(LOG,
				(errmsg("field \"%s\" of the limit on variable \"%s\" in the \"%s\" file must be passed as a JSON array",
						key,
						var_name,
						PG_CONF_LIMITS_FILENAME)));

		return NIL;
	}

	foreach(lc, node->fields)
	{
		JsonNode	*role_node = (JsonNode *) lfirst(lc);
		char	*role;

		role = get_json_scalar_value(role_node, var_name, key, true);

		if (role == NULL || strlen(role) == 0)
		{
			ereport(LOG,
					(errmsg("field \"%s\" of the limit on variable \"%s\" in the \"%s\" file must be passed as a JSON array of valid strings",
							key,
							var_name,
							PG_CONF_LIMITS_FILENAME)));
			return NIL;
		}

		result = lappend(result, pstrdup(role));
	}

	return result;
}

/*
 * Parse the GUC limits file and setup the guc_limits array.
 */
static void
process_limits_file(void)
{
	JsonSemAction sem;
	JsonLexContext *lex;
	JsonParseState	*pstate;
	MemoryContext	parse_ctx, old_ctx;
	JsonNode	*raw_tree;
	int	n, i;
	ListCell	*lc;
	GUCLimit *limits_new, *limit_current, *src, *dst;
	bool	parsed = false;
	MemoryContext ccxt = CurrentMemoryContext;
	ErrorContextCallback	errcallback;

	/*
	 * We don't want an extra variable to test whether the current processing
	 * succeeded, so just require caller to clear this one. It makes no sense
	 * anyway to process the same file more than once.
	 */
	Assert(!limits_file_processed);

	/* First time here? */
	if (guc_limits_ctx == NULL)
		guc_limits_ctx = AllocSetContextCreate(TopMemoryContext,
											   "GUCLimitsContext",
											   ALLOCSET_DEFAULT_SIZES);

	/*
	 * Separate memory context is used for the parsing. It's a child of
	 * TopTransactionContext so that we don't have to care about cleanup on
	 * error. (We actually don't raise ERRORs, but some subroutine might do.)
	 */
	parse_ctx = AllocSetContextCreate(TopTransactionContext,
									  "GUCLimitsParseContext",
									  ALLOCSET_DEFAULT_SIZES);
	old_ctx = MemoryContextSwitchTo(parse_ctx);

	/* Setup error traceback support for ereport() */
	errcallback.callback = guc_limits_error_callback;
	errcallback.arg = (void *) NULL;
	errcallback.previous = error_context_stack;
	error_context_stack = &errcallback;

	lex = makeJsonLexContextCstringLen(limits_file, strlen(limits_file),
									   true);
	pstate = palloc0(sizeof(JsonParseState));
	memset(&sem, 0, sizeof(sem));
	sem.semstate = (void *) pstate;
	sem.object_start = json_object_start;
	sem.object_end = json_object_end;
	sem.array_start = json_array_start;
	sem.array_end = json_array_end;
	sem.object_field_start = json_obj_field_start;
	sem.object_field_end = json_obj_field_end;
	sem.scalar = json_scalar;

	PG_TRY();
	{
		pg_parse_json(lex, &sem);
		parsed = true;
	}
	PG_CATCH();
	{
		ErrorData  *errdata;
		MemoryContext	ecxt PG_USED_FOR_ASSERTS_ONLY;;

		/* Copy the error data to the current context. */
		ecxt = MemoryContextSwitchTo(ccxt);
		Assert(ecxt == ErrorContext);
		errdata = CopyErrorData();

		FlushErrorState();

		/*
		 * Retrieve details from the error stack, but output it as LOG, not
		 * ERROR.
		 */
		ereport(LOG, (errmsg("%s", errdata->message)));

		FreeErrorData(errdata);
	}
	PG_END_TRY();

	/* Pop the error context stack */
	error_context_stack = errcallback.previous;

	if (!parsed)
	{
		discard_limits(parse_ctx, old_ctx);
		/* No parsing until the file is loaded again. */
		limits_file_reset();
		return;
	}

	/*
	 * Validate the data and setup guc_limits array.
	 */
	raw_tree = pstate->result;

	/* Was the file empty? */
	if (raw_tree == NULL)
	{
		discard_limits(parse_ctx, old_ctx);
		/* No parsing until the file is loaded again. */
		limits_file_reset();
		return;
	}

	/* Parser should not allow this, but an extra check doesn't hurt. */
	if (raw_tree->kind != JSON_NODE_ARRAY)
	{
		ereport(LOG, (errmsg("json array must be the root element")));
		goto fail;
	}

	/*
	 * Perform preliminary checks and find out the number of restrictions.
	 */
	n = 0;
	foreach(lc, raw_tree->fields)
	{
		JsonNode	*obj_var = (JsonNode *) lfirst(lc);

		if (obj_var->kind != JSON_NODE_OBJECT)
		{
			ereport(LOG,
					(errmsg("the top-level array may only contain JSON objects")));
			goto fail;
		}

		if (list_length(obj_var->fields) == 0)
		{
			/* An empty object is legal. XXX Should it be? */
			continue;
		}

		n++;
	}

	/* An empty array is legal. */
	if (n == 0)
	{
		discard_limits(parse_ctx, old_ctx);
		/* No parsing until the file is loaded again. */
		limits_file_reset();
		return;
	}

	/*
	 * Allocate the array to be used by the actual checks of variable
	 * values, still in parse_ctx.
	 */
	limits_new = limit_current = (GUCLimit *) palloc0(n * sizeof(GUCLimit));

	/* Initialize the array. */
	foreach(lc, raw_tree->fields)
	{
		JsonNode	*obj_var = (JsonNode *) lfirst(lc);

		/* Process the single restriction or an array of them. */
		if (!validate_limit(limit_current++, obj_var))
			goto fail;
	}

	/*
	 * Processed with success, so replace guc_limits with the new version.
	 */
	MemoryContextReset(guc_limits_ctx);
	MemoryContextSwitchTo(guc_limits_ctx);
	guc_limits_count = n;
	guc_limits = (GUCLimit *) palloc0(n * sizeof(GUCLimit));

	/* Copy the data to guc_limits_ctx so that parse_ctx can be deleted. */
	src = limits_new;
	dst = guc_limits;
	for (i = 0; i < n; i++)
	{
		List	*roles = src->roles;

		*dst = *src;
		dst->var_name = pstrdup(src->var_name);
		dst->roles = NIL;
		if (roles)
		{
			foreach(lc, roles)
				dst->roles = lappend(dst->roles, pstrdup(lfirst(lc)));
		}

		if (src->vartype == PGC_STRING)
		{
			GUCLimitString	*str_src, *str_dst;

			str_src = (GUCLimitString *) &src->value.s;
			str_dst = (GUCLimitString *) &dst->value.s;
			str_dst->value = pstrdup(str_src->value);
			str_dst->allow_empty = str_src->allow_empty;
		}
		else if (src->vartype == PGC_ENUM)
		{
			GUCLimitEnum	*enum_src, *enum_dst;
			ListCell	*lc;

			enum_src = (GUCLimitEnum *) &src->value.e;
			enum_dst = (GUCLimitEnum *) &dst->value.e;
			enum_dst->values = NIL;

			foreach(lc, enum_src->values)
			{
				char	*val_src = (char *) lfirst(lc);

				enum_dst->values = lappend(enum_dst->values,
										   pstrdup(val_src));
			}
		}

		dst++;
		src++;
	}
	limits_file_processed = true;
	ereport(DEBUG2,
			(errmsg("limits file \"%s\" processed",
					PG_CONF_LIMITS_FILENAME)));

fail:
	MemoryContextSwitchTo(old_ctx);
	MemoryContextDelete(parse_ctx);

	if (!limits_file_processed)
	{
		ereport(LOG,
				(errmsg("\"%s\" file contains error(s), no active restriction changed",
						PG_CONF_LIMITS_FILENAME)));

		/*
		 * The parsing / validation should not be retried until the file is
		 * reloaded.
		 */
		limits_file_reset();
	}
}

static void
guc_limits_error_callback(void *arg)
{
	errcontext(PG_CONF_LIMITS_FILENAME);
}

/*
 * Validate a single restriction and initialize the corresponding GUCLimit
 * structure.
 *
 * The return value tells whether all the checks succeeded.
 */
static bool
validate_limit(GUCLimit *limit, JsonNode *node)
{
	struct config_generic *var;
	ListCell	*lc;
	JsonNode	*restr_field;
	char	*restr_field_key;
	void *fields_raw[LIMIT_FIELDS_TOTAL];
	int	i;
	bool	*fields_allowed;

	Assert(node->kind == JSON_NODE_OBJECT);

	/*
	 * Variable name is important for the following processing so find it
	 * first.
	 */
	limit->var_name = NULL;
	foreach(lc, node->fields)
	{
		restr_field = (JsonNode *) lfirst(lc);
		if (restr_field->kind != JSON_NODE_OBJECT_FIELD)
		{
			ereport(LOG,
					(errmsg("restriction object can only contain object fields")));
			return false;
		}

		/* Not sure if parser can produce anything else. */
		if (list_length(restr_field->fields) != 2)
		{
			ereport(LOG,
					(errmsg("each field of a restriction object must have the form key:value")));
			return false;
		}

		restr_field_key = (char *) linitial(restr_field->fields);
		if (restr_field_key == NULL || strlen(restr_field_key) == 0)
		{
			ereport(LOG,
					(errmsg("each field key of a restriction object must be a valid string")));
			return false;
		}

		if (strcmp(restr_field_key, "var_name") == 0)
		{
			JsonNode	*name_node = (JsonNode *) lsecond(restr_field->fields);

			if (name_node->kind != JSON_NODE_SCALAR)
			{
				ereport(LOG,
						(errmsg("variable name must be passed as JSON scalar value")));

				return false;
			}

			/* See json_scalar(). */
			Assert(list_length(name_node->fields) == 1);

			limit->var_name = pstrdup(linitial(name_node->fields));

			/*
			 * Do not break the loop so that all fields are subject to the
			 * checks above.
			 */
		}
	}

	if (limit->var_name == NULL)
	{
		ereport(LOG,
				(errmsg("each restriction object must have valid \"var_name\" field")));
		return false;
	}

	/* Check that option of this name exists. */
	var = get_guc_variable(limit->var_name);
	if (var == NULL)
	{
		ereport(LOG,
				(errmsg("unrecognized configuration variable \"%s\"",
						limit->var_name)));
		return false;
	}

	/*
	 * It makes no sense to limit variables that user cannot set anyway, nor
	 * do we want to check those that only superuser can set.
	 */
	if (var->context != PGC_BACKEND && var->context != PGC_USERSET)
	{
		ereport(LOG,
				(errmsg("configuration variable \"%s\" cannot have per-user limit",
						limit->var_name)));
		return false;
	}

	limit->var_flags = var->flags;

	for (i = 0; i < LIMIT_FIELDS_TOTAL; i++)
		fields_raw[i] = NULL;

	foreach(lc, node->fields)
	{
		void	*value;
		int	field_index = -1;

		restr_field = (JsonNode *) lfirst(lc);

		/* Checked in the previous loop. */
		Assert(restr_field->kind == JSON_NODE_OBJECT_FIELD);
		Assert(list_length(restr_field->fields) == 2);

		restr_field_key = (char *) linitial(restr_field->fields);

		/* "roles" is a special case because it's not a JSON scalar. */
		if (strcmp(restr_field_key, "roles") == 0)
		{
			value = get_json_array_value((JsonNode *) lsecond(restr_field->fields),
										 limit->var_name,
										 "roles");
			if (!add_limit_field(fields_raw, limit->var_name, restr_field_key,
							 value, LIMIT_FIELD_ROLES))
				return false;

			continue;
		}

		/* Likewise, the "values" field for enumeration variables. */
		if (strcmp(restr_field_key, "values") == 0)
		{
			value = get_json_array_value((JsonNode *) lsecond(restr_field->fields),
										 limit->var_name,
										 "values");
			if (!add_limit_field(fields_raw, limit->var_name, restr_field_key,
								 value, LIMIT_FIELD_VALUES))
				return false;

			continue;
		}

		/*
		 * The other fields can be processed in an uniform way.
		 */
		for (i = 0; i < LIMIT_FIELDS_TOTAL; i++)
		{
			if (strcmp(restr_field_key, limit_field_names[i]) == 0)
			{
				field_index = i;
				break;
			}
		}
		if (field_index < 0)
		{
			ereport(LOG,
					(errmsg("limit on variable \"%s\" has unrecognized field \"%s\"",
							limit->var_name, restr_field_key)));
			return false;
		}

		if ((value = get_json_scalar_value((JsonNode *) lsecond(restr_field->fields),
										   limit->var_name,
										   restr_field_key,
										   false)) == NULL)
			return false;

		if (!add_limit_field(fields_raw, limit->var_name, restr_field_key,
							 value, field_index))
			return false;
	}

	/*
	 * All limits need to have role list so check it here.
	 *
	 * We don't check whether the roles exist in database because a role can
	 * be dropped anytime. If we rejected the configuration file due to
	 * missing role, we'd also (in order to be consistent) have to drop the
	 * whole guc_limits array if any role referenced by the file was dropper.
	 */
	limit->roles = get_limit_field(fields_raw, LIMIT_FIELD_ROLES);
	if (limit->roles == NIL)
	{
		ereport(LOG,
				(errmsg("limit on variable \"%s\" specifies no role",
						limit->var_name)));
		return false;
	}

	/*
	 * Check if all the field names are valid for given data type.
	 *
	 * While fields not appropriate to any type should have been caught above
	 * (see the search for field_index), we also need to check whether field
	 * appropriate to some type(s) is not used for another type(s).
	 */
	limit->vartype = var->vartype;
	fields_allowed = limit_fields_allowed[limit->vartype];
	for (i = 0; i < LIMIT_FIELDS_TOTAL; i++)
	{
		if (fields_raw[i] && !fields_allowed[i])
		{
			ereport(LOG,
					(errmsg("limit on variable \"%s\" has unrecognized field \"%s\"",
							limit->var_name, limit_field_names[i])));
			return false;
		}
	}

	/* Finally perform the type-specific checks. */
	switch (limit->vartype)
	{
		case PGC_BOOL:
			if (!validate_limit_bool(limit, fields_raw))
				return false;
			break;

		case PGC_INT:
			if (!validate_limit_int(limit, fields_raw))
				return false;
			break;

		case PGC_REAL:
			if (!validate_limit_real(limit, fields_raw))
				return false;
			break;

		case PGC_STRING:
			if (!validate_limit_string(limit, fields_raw))
				return false;
			break;

		case PGC_ENUM:
			{
				struct config_enum *en = (struct config_enum *) var;

				if (!validate_limit_enum(limit, fields_raw, en->options))
					return false;
			}
			break;

		default:
#ifdef USE_ASSERT_CHECKING
			/* Should not happen. */
			Assert(false);
#endif	/* USE_ASSERT_CHECKING */
	}

	return true;
}

/*
 * Validate fields specific for integer type and finalize the limit instance.
 */
static bool
validate_limit_bool(GUCLimit *limit, void *fields_raw[])
{
	char	*val_str;
	bool	parsed;

	val_str = (char *) get_limit_field(fields_raw, LIMIT_FIELD_VALUE);

	if (val_str == NULL)
	{
		ereport(LOG,
				(errmsg("limit on \"%s\" variable specifies no value",
						limit->var_name)));
		return false;
	}

	limit->value.b.value = parse_limit_field_bool(val_str, limit->var_name,
												  &parsed);
	if (!parsed)
		return false;

	return true;
}

/*
 * Validate fields specific for integer type and finalize the limit instance.
 */
static bool
validate_limit_int(GUCLimit *limit, void *fields_raw[])
{
	char	*min_str, *max_str;
	bool	parsed;
	GUCLimitInt	*lim_int = (GUCLimitInt *) &limit->value.i;

	min_str = (char *) get_limit_field(fields_raw, LIMIT_FIELD_MIN);
	max_str = (char *) get_limit_field(fields_raw, LIMIT_FIELD_MAX);

	if (min_str == NULL && max_str == NULL)
	{
		ereport(LOG,
				(errmsg("\"%s\" variable specifies neither minimum nor maximum value",
						limit->var_name)));
		return false;
	}

	if (min_str)
	{
		lim_int->min = parse_limit_field_int(min_str, limit->var_name,
											 limit->var_flags, &parsed);
		if (!parsed)
			return false;

		lim_int->has_min = true;
	}

	if (max_str)
	{
		lim_int->max = parse_limit_field_int(max_str, limit->var_name,
											 limit->var_flags, &parsed);
		if (!parsed)
			return false;

		lim_int->has_max = true;
	}

	if (min_str && max_str && lim_int->min >= lim_int->max)
	{
		ereport(LOG,
				(errmsg("maximum value of the \"%s\" variable must be greater than the minimum value",
					limit->var_name)));
		return false;
	}

	return true;
}

/*
 * Validate fields specific for real type and finalize the limit instance.
 */
static bool
validate_limit_real(GUCLimit *limit, void *fields_raw[])
{
	char	*min_str, *max_str, *include_min_str, *include_max_str;
	bool	parsed;
	GUCLimitReal	*lim_real = (GUCLimitReal *) &limit->value.r;

	min_str = (char *) get_limit_field(fields_raw, LIMIT_FIELD_MIN);
	max_str = (char *) get_limit_field(fields_raw, LIMIT_FIELD_MAX);

	include_min_str = (char *) get_limit_field(fields_raw,
											   LIMIT_FIELD_INCLUDE_MIN);
	include_max_str = (char *) get_limit_field(fields_raw,
											   LIMIT_FIELD_INCLUDE_MAX);

	if (min_str == NULL && max_str == NULL)
	{
		ereport(LOG,
				(errmsg("\"%s\" variable specifies neither minimum nor maximum value",
						limit->var_name)));
		return false;
	}

	if (min_str)
	{
		lim_real->min = parse_limit_field_real(min_str, limit->var_name,
											   limit->var_flags, &parsed);
		if (!parsed)
			return false;

		lim_real->has_min = true;
	}

	if (max_str)
	{
		lim_real->max = parse_limit_field_real(max_str, limit->var_name,
											   limit->var_flags, &parsed);
		if (!parsed)
			return false;

		lim_real->has_max = true;
	}

	if (include_min_str)
	{
		lim_real->include_min = parse_limit_field_bool(include_min_str,
													   limit->var_name,
													   &parsed);
		if (!parsed)
			return false;
	}
	else
		lim_real->include_min = true;

	if (include_max_str)
	{
		lim_real->include_max = parse_limit_field_bool(include_max_str,
													   limit->var_name,
													   &parsed);
		if (!parsed)
			return false;
	}
	else
		lim_real->include_max = true;

	if (lim_real->has_min && lim_real->has_max && lim_real->min >= lim_real->max)
	{
		ereport(LOG,
				(errmsg("maximum value of the \"%s\" variable must be greater than the minimum value",
					limit->var_name)));
		return false;
	}

	return true;
}

/*
 * Validate fields specific for string type and finalize the limit instance.
 */
static bool
validate_limit_string(GUCLimit *limit, void *fields_raw[])
{
	char	*val_str, *allow_opt_str;
	GUCLimitString	*lim_string = (GUCLimitString *) &limit->value.s;

	val_str = (char *) get_limit_field(fields_raw, LIMIT_FIELD_VALUE);
	if (val_str == NULL || strlen(val_str) == 0)
	{
		ereport(LOG,
				(errmsg("\"%s\" variable does not specify valid accepted value",
						limit->var_name)));
		return false;
	}
	lim_string->value = val_str;

	lim_string->allow_empty = true;
	allow_opt_str = (char *) get_limit_field(fields_raw,
											 LIMIT_FIELD_ALLOW_EMPTY);
	if (allow_opt_str)
	{
		bool	parsed;

		limit->value.s.allow_empty = parse_limit_field_bool(allow_opt_str,
															limit->var_name,
															&parsed);

		if (!parsed)
			return false;
	}

	return true;
}

/*
 * Validate fields specific for enum type and finalize the limit instance.
 */
static bool
validate_limit_enum(GUCLimit *limit, void *fields_raw[],
					const struct config_enum_entry *options)
{
	List	*value_strs;
	GUCLimitEnum	*lim_enum;
	ListCell	*lc;

	lim_enum = (GUCLimitEnum *) &limit->value.e;
	Assert(lim_enum->values == NIL);

	value_strs = (List *) get_limit_field(fields_raw, LIMIT_FIELD_VALUES);
	if (value_strs == NIL)
	{
		ereport(LOG,
				(errmsg("\"%s\" variable does not specify the accepted values",
						limit->var_name)));
		return false;
	}

	foreach(lc, value_strs)
	{
		const struct config_enum_entry *entry;
		bool	found = false;
		char	*entry_str = (char *) lfirst(lc);

		/* Is this a recognized entry? */
		for (entry = options; entry && entry->name; entry++)
		{
			if (strcmp(entry->name, entry_str) == 0)
			{
				found = true;
				break;
			}
		}

		if (!found)
		{
			/* TODO Escape the value. */
			ereport(LOG,
					(errmsg("\"%s\" is not valid value of \"%s\" variable",
							entry_str,
							limit->var_name)));
			return false;
		}

		lim_enum->values = lappend(lim_enum->values, entry_str);
	}

	return true;
}

/*
 * Add limit field to an array of strings / lists. Return true if succeeded,
 * false if the field is already there. var_name and key arguments are passed
 * only for logging purposes.
 */
static bool
add_limit_field(void *fields_raw[], char *var_name, char *key, void *value,
				LimitField index)
{
	Assert(index < LIMIT_FIELDS_TOTAL);

	if (fields_raw[index])
	{
		ereport(LOG,
				(errmsg("the limit on variable \"%s\" in the \"%s\" file has field \"%s\" specified multiple times",
						var_name,
						PG_CONF_LIMITS_FILENAME,
						key)));
		return false;
	}

	fields_raw[index] = value;
	return true;
}

/* Retrieve limit field from an array. */
static void *
get_limit_field(void *fields_raw[], LimitField index)
{
	Assert(index < LIMIT_FIELDS_TOTAL);

	return fields_raw[index];
}

/*
 * Parse a boolean value.
 *
 * Set *success to true if the value was valid, false otherwise. The return
 * value is only defined on success.
 *
 * XXX Is it worth checking whether the boundary is within the GUC
 * range?
 */
static bool
parse_limit_field_bool(char *value_str, char *var_name, bool *success)
{
	bool	result;

	*success = parse_bool(value_str, &result);
	if (!*success)
	{
		ereport(LOG,
				(errmsg("limit on \"%s\" is not a valid boolean value",
						var_name)));
		return false;
	}
	else
	{
		return result;
	}
}

/*
 * Parse an integer value.
 *
 * See parse_limit_field_bool() for explanation of arguments.
 *
 * XXX Is it worth checking whether the boundary is within the GUC
 * range?
 */
static int
parse_limit_field_int(char *value_str, char *var_name, int var_flags,
					  bool *success)
{
	int	result;
	const char	*msg;

	*success = parse_int(value_str, &result, var_flags, &msg);
	if (!*success)
	{
		if (msg)
			ereport(LOG, (errmsg("%s", msg)));
		else
			ereport(LOG, (errmsg("%s is not a valid integer, please check \"%s\" variable in the \"%s\" file",
								 value_str,
								 var_name,
								 PG_CONF_LIMITS_FILENAME)));
		return 0;
	}

	return result;
}

/*
 * Parse a real value.
 *
 * See parse_limit_field_bool() for explanation of arguments.
 */
static double
parse_limit_field_real(char *value_str, char *var_name, int var_flags,
					  bool *success)
{
	double	result;
	const char	*msg;

	*success = parse_real(value_str, &result, var_flags, &msg);
	if (!*success)
	{
		if (msg)
			ereport(LOG, (errmsg("%s", msg)));
		else
			ereport(LOG, (errmsg("%s is not a valid real number, please check \"%s\" variable in the \"%s\" file",
								 value_str,
								 var_name,
								 PG_CONF_LIMITS_FILENAME)));
		return 0.0;
	}

	return result;
}

/*
 * Discard the active limits and do memory cleanup. This should be called when
 * the limits file is empty.
 */
static void
discard_limits(MemoryContext parse_ctx, MemoryContext old_ctx)
{
	MemoryContextSwitchTo(old_ctx);
	MemoryContextDelete(parse_ctx);
	MemoryContextReset(guc_limits_ctx);
	guc_limits = NULL;
	guc_limits_count = 0;
}

/*
 * Report that new_value of variable var_name exceeds limit_value for role. If
 * is_min is true, minimum value is violated, otherwise maximum is.
 */
static void
report_int_limit_violation(int new_value, char *var_name, int var_flags,
						   int limit_value, char *role, bool is_min,
						   int elevel)
{
	char	*kind;
	const char	*limit_unit, *new_unit;

	kind = is_min ? "minimum" : "maximum";

	if (var_flags & GUC_UNIT)
	{
		int64	limit_converted, new_converted;

		convert_int_from_base_unit(limit_value,
								   var_flags & GUC_UNIT,
								   &limit_converted,
								   &limit_unit);

		convert_int_from_base_unit(new_value,
								   var_flags & GUC_UNIT,
								   &new_converted,
								   &new_unit);

		ereport(elevel,
				(errmsg("%s value of the \"%s\" configuration variable for role \"%s\" is %zd%s but the value being set is %zd%s",
						kind, var_name, role, limit_converted, limit_unit,
						new_converted, new_unit)));
	}
	else
		ereport(elevel,
				(errmsg("%s value of the \"%s\" configuration variable for role \"%s\" is %d but the value being set is %d",
						kind, var_name, role, limit_value, new_value)));
}

/*
 * Like report_int_limit_violation() but for real numbers. In addition,
 * is_inclusive tells whether limit_value itself is acceptable.
 */
static void
report_real_limit_violation(double new_value, char *var_name, int var_flags,
							double limit_value, char *role, bool is_min,
							bool is_inclusive, int elevel)
{
	char	*kind, *incl_excl;
	const char	*limit_unit, *new_unit;

	kind = is_min ? "minimum" : "maximum";
	incl_excl = is_inclusive ? "inclusive" : "exclusive";

	if (var_flags & GUC_UNIT)
	{
		convert_real_from_base_unit(limit_value,
									var_flags & GUC_UNIT,
									&limit_value,
									&limit_unit);

		convert_real_from_base_unit(new_value,
									var_flags & GUC_UNIT,
									&new_value,
									&new_unit);

		ereport(elevel,
				(errmsg("%s value of the \"%s\" configuration variable for role \"%s\" is %g%s (%s) but the value being set is %g%s",
						kind, var_name, role, limit_value, limit_unit,
						incl_excl, new_value, new_unit)));
	}
	else
		ereport(elevel,
				(errmsg("%s value of the \"%s\" configuration variable for role \"%s\" is %g (%s) but the value being set is %g",
						kind, var_name, role, limit_value, incl_excl,
						new_value)));
}
