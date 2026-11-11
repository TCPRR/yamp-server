#pragma once
#include <cjson/cJSON.h>
#include "types.h"
#include "globals.h"
#include "network.h"
typedef struct {
    char *username;     // the other mf
    int   outgoing;     // 1 = you sent it, 0 = you received it
} FriendReqEntry;

// Identifier generators
int GenerateID(char** id);
int GenerateID_Inline(char* id);
int GenerateToken_Inline(char* id);
int GenerateUploadToken_Inline(char* id);

// Status Objects
YampStatus* CreateOfflineStatus();
YampStatus* CreateOnlineStatus();
void FreeStatusObject(YampStatus* stat);

// User Objects
YampUser* ParseUserJSON(cJSON* rawusr);
cJSON *CreateUserJSON(YampUser *user);
int CreateUserJSONFromUsername(const char *name, cJSON **output);

int CreateUserObjectFromID(const char* id, YampUser** output);
int CreateUserSelfJSONFromID(char* name, cJSON** output);
int CreateUserSelfJSONFromUsername(char* name, cJSON** output);
void FreeUserObject(YampUser* u);


// Functions
char* RegisterUserAccount(char* email, char* name, char* passwd);
int CreateSpaceObjectFromName(char *name, cJSON **output);
int CreateSpaceObjectFromID(char* id, cJSON** output);
int CreateFriendsListFromUserID(const char* name, cJSON** output);
int CreateConvListFromUserID(const char *name, cJSON **output);
int CreateSpacesListFromID(const char* name, cJSON** output);
int CreateSpacesListFromUsername(const char* name, cJSON** output);
int CreateChannelsListFromName(const char *name, cJSON **output);
int CreateUsersOwnObjectFromUsername(char *name, cJSON **output);
char* CreateSpaceInvite(const char* space, int uses);
cJSON* GetSpaceDetailsFromInvite(const char* invite);

// Member listing funcs
cJSON* ListSpaceMembersJSONFromID(char* id);
int ListSpaceMembersObjectsFromID(char* id, YampUser*** out);

cJSON* CreateMessageObject(YampMessage* msg);
void InsertMessage(YampMessage* msg);
cJSON* GetMessageHistoryPage(const char* where, const char* before, int limit);
cJSON* GetMessageHistory(char* where);
int PushEvent(Connection con, char *event, cJSON *data);
int PushRecvIM(char* toID, char* channel, YampMessage* msg, int nonce);
int PushStatusUpdate(char* toWho, char* who, YampStatus* status);
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
char* GetSpaceIDFromName(char* name);
char* GetUserIDFromName(char* name);
int PushNewSpace(char* who, char* space_id);
int PushUpdatedChannelsList(char* who, char* space_id);
int PushNewFriend(char* who, char* user_id);
YampUser ParseUserObject(cJSON* rawusr);
int UpdateUserProfile(char* id, YampUser newprofile);

int PushNewConversation(char* userid, YampChannel conv);

// Group chat funcs
void CreateGC(YampUser* creator, int ninitmember, YampUser** initmembers);
int UpdateGC(YampChannel* conv);
int IsGCOwner(char* uid, char* gcid);
int IsInGC(char* uid, char* gcid);
cJSON* ListGCMembersJSONFromID(const char* id);
int ListGCMembersObjectsFromID(char* id, YampUser*** out);
void FreeUserArray(YampUser** arr, int n);
int AddMemberToGC(char* uid, char* gcid);

YampChannel CreateDM(char* starter, char* recipient);
int HasDMs(char* starter, char* recipient);

int PushJoinChannel(char* toID, char* fromID, char* channel);
int PushLeftChannel(char* toID, char* fromID, char* channel);
int PushTyping(char* toID, char* fromID, char* channel);

YampMessage* CreateMessageTypeFromID(char* id);
int DeleteMessage(char* id);
void FreeMessageFields(YampMessage* msg);
void FreeMessageObject(YampMessage* msg);
int PushMessageDeleted(char* toID, char* message);

int CanAccessChat(const YampUser* usr, char* id);

char* GetSpaceFromChannelID(char* channel_id);


YampAttachment* ParseAttachmentJSON(cJSON* json);
void FreeAttachmentTypeFields(YampAttachment* attach);
YampAttachment* DupAttachmentObject(YampAttachment* attachment);


// Reactions
cJSON* CreateReactionJSON(const YampReaction* r);
int ListReactionObjectsForID(const char* msg_id, YampReaction*** out);
void FreeReactionArray(YampReaction** arr, int n);
void FreeReactionObject(YampReaction* r);
void DeleteReactionsForMessageID(const char* msg_id);
int RemoveReaction(const char* msg_id, const char* user_id,
				   const char* codepoint);
int InsertReactionForMessageID(const char* msg_id, const char* user_id,
				    const char* codepoint);

// Space invites
int JoinSpaceViaInvite(const char* user_id, const char* code,
					   char** space_out);