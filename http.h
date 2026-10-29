int InitYAMPHTTP(void);

typedef struct UploadToken{
	struct UploadToken* before; // private
	struct UploadToken* after; // private
	char tok[257];
} UploadToken;

UploadToken* RegisterUploadToken();