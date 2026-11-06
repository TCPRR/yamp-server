#include "hmap/hashmap.h"
#include "types.h"
#include <sqlite3.h>
#include "config.h"
// Maps of the current online users
extern hmap UsersByName;
extern hmap UsersByID;

// Map of sessions
extern hmap UserSessionsByFD;

extern sqlite3 *DB;
extern MainRespOverride* respoverrides;
extern int nrespoverrides;
extern int IPCSockets[MAX_IPC_CLIENTS];