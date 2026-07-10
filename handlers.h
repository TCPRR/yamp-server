#include <cjson/cJSON.h>
#include "types.h"
#include "globals.h"
#include "network.h"
cJSON *CreateUserObject(const char *name, const char *description, const char *display_name, const char* pfp,
                        status* status);
int CreateSpaceObjectFromName(char *name, cJSON **output);
int CreateUserObjectFromUsername(char *name, cJSON **output);
int CreateFriendsListFromUsername(const char *name, cJSON **output);
int CreateSpacesListFromUsername(const char *name, cJSON **output);
int CreateChannelsListFromName(const char *name, cJSON **output);
int CreateUsersOwnObjectFromUsername(char *name, cJSON **output);
char **ListSpaceMembersNames(char *name, int *outputlen);
cJSON* CreateMessageObject(char* author, char* content, char* where);
void InsertMessage(char *where, char *author, char *content);
cJSON* GetMessageHistory(char* where);
int PushEvent(int fd, char *event, cJSON *data);
int PushRecvIM(char *toWho, char *where, char *fromWho, char *content);