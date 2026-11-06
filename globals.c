#include "globals.h"
hmap UsersByName;
hmap UserSessionsByFD;
hmap UsersByID;

MainRespOverride* respoverrides = NULL;
int nrespoverrides = 0;