#include "hmap/hashmap.h"
#include "types.h"
#include <sqlite3.h>
#include "config.h"
extern hmap UsersByName;
extern hmap UsersByFD;
extern hmap UsersByID;
extern sqlite3 *DB;
extern MainRespOverride* respoverrides;
extern int nrespoverrides;
extern int IPCSockets[MAX_IPC_CLIENTS];