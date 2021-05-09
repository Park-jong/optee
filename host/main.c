/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	
	int opt;
	FILE* rfp;
	FILE* wfp;
	char* buf;
	int fileSize;
	int len;
	char key;

	if(strcmp(argv[1], "-e") == 0)
		opt = 1;
	else if(strcmp(argv[1], "-d") == 0)
		opt = 0;
	else{
		printf("Select option -e or -d\n");
		return 0;
	}
	
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	
	memset(&op, 0, sizeof(op));
	
	if(opt){
		//file open and read
		rfp = fopen(argv[2], "r");

		fseek(rfp, 0, SEEK_END);
		fileSize = ftell(rfp);
		len = fileSize + 1;
		buf = malloc(len);
		memset(buf, 0, len);

		fseek(rfp, 0, SEEK_SET);
		fread(buf, len, 1, rfp);
		fclose(rfp);
		
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = buf;
		op.params[0].tmpref.size = len;

		printf("=============================Encryption==========================\n");
		printf("%s\n",buf);
		
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",	res, err_origin);
		memcpy(buf, op.params[0].tmpref.buffer, len);
		key = op.params[1].value.a;
		printf("===> %skey:%c\n", buf, key);
		
		//file write
		wfp = fopen("/root/encryptresult.txt","w");
		fwrite(buf, 1, len, wfp);
		fclose(wfp);
		
		wfp = fopen("/root/key.txt","w");
		fprintf(wfp, "%c", key);
		fclose(wfp);

		free(buf);
	}
	else{
		//file open and read
		rfp = fopen(argv[2], "r");

		fseek(rfp, 0, SEEK_END);
		fileSize = ftell(rfp);
		len = fileSize + 1;
		buf = malloc(len);
		memset(buf, 0, len);

		fseek(rfp, 0, SEEK_SET);
		fread(buf, len, 1, rfp);
		fclose(rfp);

		rfp = fopen(argv[3], "r");
		fscanf(rfp, "%c", &key);
		fclose(rfp);
		
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = buf;
		op.params[0].tmpref.size = len;
		op.params[1].value.a = key;

		printf("=============================decryption==========================\n");
		printf("%s\n%c\n",buf, key);
		
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",	res, err_origin);
		memcpy(buf, op.params[0].tmpref.buffer, len);
		printf("===> %s\n", buf);
		
		//file write
		wfp = fopen("/root/decryptresult.txt","w");
		fwrite(buf, 1, len, wfp);
		fclose(wfp);

		free(buf);
	}
	

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
