#include <cjson/cJSON.h>
#include "types.h"
#include "globals.h"
#include "network.h"
typedef struct {
    char *username;     // the other mf
    int   outgoing;     // 1 = you sent it, 0 = you received it
} FriendReqEntry;

int GenerateID(char** id);
int RegisterUserAccount(char* name, char* passwd);
cJSON *CreateUserObject(user *user);
int CreateSpaceObjectFromName(char *name, cJSON **output);
int CreateSpaceObjectFromID(char* id, cJSON** output);
int CreateUserObjectFromUsername(const char *name, cJSON **output);
int CreateFriendsListFromUserID(const char* name, cJSON** output);
int CreateConvListFromUserID(const char *name, cJSON **output);
int CreateSpacesListFromID(const char* name, cJSON** output);
int CreateSpacesListFromUsername(const char* name, cJSON** output);
int CreateChannelsListFromName(const char *name, cJSON **output);
int CreateUsersOwnObjectFromUsername(char *name, cJSON **output);
char* CreateSpaceInvite(const char* space, int uses);
cJSON* GetSpaceDetailsFromInvite(const char* invite);
cJSON* ListSpaceMembersFromID(char* id);
cJSON* CreateMessageObject(char* author, char* content, char* where);
void InsertMessage(char *where, char *author, char *content);
cJSON* GetMessageHistory(char* where);
int PushEvent(Connection con, char *event, cJSON *data);
int PushRecvIM(char *toWho, char *where, char *fromWho, char *content);
int PushStatusUpdate(char *toWho, char *who, status status);
int PushFQ(char *toWho, char *fromWho);
int PushProfileUpdate(char* toID, char* fromID);
void CreateFriendReq(char* sender, char* receiver);
int DestroyFriendReq(char* sender, char* receiver);
void CreateFriendship(char* sender, char* receiver);
int ListFriendReqs(const char *user, FriendReqEntry **out);
int IsInSpaceViaUserID(char* userid, char* spaceid);
int AreFriends(const char* user1, const char* user2);
int IsUserNameExisting(const char* user);
int IsSpaceNameExisting(const char* space);
const char* GetSpaceIDFromName(char* name);
const char* GetUserIDFromName(char* name);
int PushNewSpace(char* who, char* space_id);
int PushUpdatedChannelsList(char* who, char* space_id);
int PushNewFriend(char* who, char* user_id);
user ParseUserObject(cJSON* rawusr);
int UpdateUserProfile(char* id, user newprofile);


void CreateGC(user creator, int ninitmember, user* initmembers);
int UpdateGC(YampChannel* conv);
int IsGCOwner(char* uid, char* gcid);
int IsInGC(char* uid, char* gcid);
cJSON* ListGCMembersFromID(const char* id);
int AddMemberToGC(char* uid, char* gcid);

void CreateDM(char* starter, char* recipient);
int HasDMs(char* starter, char* recipient);

int CreateUserTypeFromID(const char* id, user* output);