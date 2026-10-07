#include "types.h"
int ProcessRequest(char *payload, char **response, int sockid, Connection* con);
char** CollectRelatedUserIDs(const char* username, const char* selfid,
									int* count);