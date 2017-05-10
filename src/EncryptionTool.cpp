//============================================================================
// Name        : EncryptionTool.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <stdint.h>
#include <stdio.h>
#include<cstring>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string>
#include <sstream>
#include <vector>
#include <iostream>
#include <fstream>

using namespace std;

char* enc_key;
const uint32_t KEY_LEN = 16; //Bytes

char* iv;
const uint32_t IV_LEN = 12; //Bytes

const uint32_t TAG_LEN = 16; //Bytes

int input_file_size = 0;
void handleErrors(void) {
	unsigned long errCode;

	printf("An error occurred\n");
	while (errCode = ERR_get_error()) {
		char *err = ERR_error_string(errCode, NULL);
		printf("%s\n", err);
	}
	abort();
}
char* get_key_iv(const char* file_name, int key) {
//	cout<<file_name<<endl;
	uint32_t len = key == 1 ? KEY_LEN : IV_LEN;
	ifstream file(file_name, std::ios::binary | std::ios::ate);
	if (!file.is_open()) {
		cout << "Could not open the file: " << file_name << endl;
		exit(1);
	}
	streamsize size = file.tellg();
	if (size != len) {
		cout << "length is not valid";
		exit(1);
	}
	char* content = new char[len + 1];
	content[len] = '\0';
	file.seekg(0, std::ios::beg);
	file.read(content, size);
//	cout<<strlen(content)<<endl;
	file.close();
	return content;
}

int aes_128_gcm_encrypt(const char* plain, const char* key, char* cipher,
		char* tag) {

//	EVP_CIPHER_CTX *ctx = NULL;
//	int len = 0, ciphertext_len = 0;
//
//	/* Create and initialise the context */
//	if (!(ctx = EVP_CIPHER_CTX_new()))
//		handleErrors();
//
//	/* Initialise the encryption operation. */
//	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
//		handleErrors();
//
//	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
//	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL))
//		handleErrors();
//
//	/* Initialise key and IV */
//	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, (unsigned char*)key, (unsigned char*)iv))
//		handleErrors();
//
//	/* Provide the message to be encrypted, and obtain the encrypted output.
//	 * EVP_EncryptUpdate can be called multiple times if necessary
//	 */
//	if (plain) {
//		if (1
//				!= EVP_EncryptUpdate(ctx, (unsigned char*) cipher, &len,
//						(unsigned char*) plain, input_file_size)) {
//			handleErrors();
//		}
//		ciphertext_len = len;
//	}
//
//	/* Finalise the encryption. Normally ciphertext bytes may be written at
//	 * this stage, but this does not occur in GCM mode
//	 */
//	if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char*) cipher + len, &len)) {
//		handleErrors();
//	}
//	ciphertext_len += len;
//
//	/* Get the tag */
//	if (1
//			!= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN,
//					(unsigned char*) tag))
//		handleErrors();
//
//	/* Clean up */
//	EVP_CIPHER_CTX_free(ctx);
//
//	return ciphertext_len;

	int actual_size = 0, final_size = 0;

	 EVP_CIPHER_CTX* e_ctx = EVP_CIPHER_CTX_new();
	 //	EVP_CIPHER_CTX_ctrl(e_ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
	 EVP_EncryptInit(e_ctx, EVP_aes_128_gcm(), (const unsigned char*) key,
	 (const unsigned char*) iv);
	 EVP_EncryptUpdate(e_ctx, (unsigned char*) cipher, &actual_size,
	 (const unsigned char*) plain, input_file_size);
	 EVP_EncryptFinal(e_ctx, (unsigned char*) &cipher[actual_size], &final_size);
	 final_size += actual_size;
	 EVP_CIPHER_CTX_ctrl(e_ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN,
	 (unsigned char*) tag);
	 EVP_CIPHER_CTX_free(e_ctx);

	 return final_size;
}

int aes_128_gcm_decrypt(const char* cipher, char* tag, const char* key,
		char* plain) {


//	EVP_CIPHER_CTX *ctx = NULL;
//	int len = 0, plaintext_len = 0, ret;
//
//	/* Create and initialise the context */
//	if (!(ctx = EVP_CIPHER_CTX_new()))
//		handleErrors();
//
//	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
//	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL))
//		handleErrors();
//
//	/* Initialise key and IV */
//	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, (unsigned char*) key,
//			(unsigned char*) iv)) {
//		handleErrors();
//	}
//
//	/* Provide the message to be decrypted, and obtain the plaintext output.
//	 * EVP_DecryptUpdate can be called multiple times if necessary
//	 */
//	if (cipher) {
//		if (!EVP_DecryptUpdate(ctx, (unsigned char*)plain, &len, (unsigned char*)cipher,
//				input_file_size-TAG_LEN))
//			handleErrors();
//
//		plaintext_len = len;
//	}
//	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
//	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag))
//		handleErrors();
//
//	/* Finalise the decryption. A positive return value indicates success,
//	 * anything else is a failure - the plaintext is not trustworthy.
//	 */
//	ret = EVP_DecryptFinal_ex(ctx, (unsigned char*)plain + len, &len);
//
//    /* Clean up */
//    EVP_CIPHER_CTX_free(ctx);
//
//    if(ret > 0)
//    {
//        /* Success */
//        plaintext_len += len;
//        return plaintext_len;
//    }
//    else
//    {
//        /* Verify failed */
//        return -1;
//    }









	int actual_size = 0, final_size = 0;
	int ret_val = 0;
	EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();
//	EVP_CIPHER_CTX *d_ctx;
//	ret_val = EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
	EVP_DecryptInit(d_ctx, EVP_aes_128_gcm(), (const unsigned char*) key,
			(const unsigned char*) iv);
	EVP_DecryptUpdate(d_ctx, (unsigned char*) plain, &actual_size,
			(const unsigned char*) cipher, input_file_size-TAG_LEN);

//	final_size = actual_size;
	EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
			(unsigned char*) tag);
	EVP_DecryptFinal(d_ctx, (unsigned char*) plain + actual_size, &final_size);
	final_size += actual_size;
	EVP_CIPHER_CTX_free(d_ctx);
	return final_size;
}

void print_help() {
	cout
			<< "Options are:\n\tEncryptionTool -t [enc|dec] -k private_key -v IV_vector -i inputfile -o outputfile"
			<< "\n\tif used correctly, after encryption, the first 16 bytes is tag(GMAC) and the rest is the actual cipher."
			<< "\n\tthere is !NO! ADATA in this implementation" << endl;
}

char* read_inputfile(const char* file_name) {
	ifstream file(file_name, std::ios::binary | std::ios::ate);
	if (!file.is_open()) {
		cout << "Could not open the file: " << file_name << endl;
		exit(1);
	}
	input_file_size = file.tellg();

	char* content = new char[input_file_size + 1];
	content[input_file_size] = '\0';
	file.seekg(0, std::ios::beg);
	file.read(content, input_file_size);
//	cout<<strlen(content)<<endl;
	file.close();
	return content;
}

void write_outputfile(const char* file_name, const char* content, int append,
		bool op) {
	if (op && append != 0) {
		fstream file(file_name, std::ios::binary | std::ios::app);
		if (!file.is_open()) {
			cout << "Could not open the file: " << file_name << endl;
			exit(1);
		}
		file.write(content, input_file_size);
		file.close();
	} else if (op && append == 0) {
		fstream file(file_name, std::ios::binary | std::ios::out);
		if (!file.is_open()) {
			cout << "Could not open the file: " << file_name << endl;
			exit(1);
		}
		file.write(content, TAG_LEN);
		file.close();
	} else if (!op) {
		fstream file(file_name, std::ios::binary | std::ios::out);
		if (!file.is_open()) {
			cout << "Could not open the file: " << file_name << endl;
			exit(1);
		}
		file.write(content, input_file_size - TAG_LEN);
		file.close();
	}
}

int main(int argc, char **argv) {
	//Preprocess key and ivs from cmd
	char *input_file, *output_file, *pk_file, *iv_file;
	bool enc_operation = false;
	if (argc != 11) {
		print_help();
		exit(1);
	}

	for (int i = 1; i < argc; i++) {
//		cout<<i<<"=>"<<argv[i]<<endl;
		if (strcmp("-k", argv[i]) == 0) {
			pk_file = argv[i + 1];
			++i;
		} else if (strcmp("-t", argv[i]) == 0) {
			if (strcmp("enc", argv[i + 1]) == 0) {
				enc_operation = true;
			} else if (strcmp("dec", argv[i + 1]) == 0) {
				enc_operation = false;
			}
			++i;
		} else if (strcmp("-v", argv[i]) == 0) {
			iv_file = argv[i + 1];
			++i;
		} else if (strcmp("-i", argv[i]) == 0) {
			input_file = argv[i + 1];
			++i;
		} else if (strcmp("-o", argv[i]) == 0) {
			output_file = argv[i + 1];
			++i;
		} else {
			print_help();
			exit(1);
		}
	}
//	exit(1);
	//Read Key and IV
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	enc_key = get_key_iv((const char*) pk_file, 1);
#ifdef DEBUG
	cout<<"Enc key is read!"<<endl;
	cout<<enc_key<<endl;
	cout<<strlen(enc_key)<<endl;
#endif
	iv = get_key_iv((const char*) iv_file, 0);
#ifdef DEBUG
	cout<<"IV is read!"<<endl;
	cout<<iv<<endl;
	cout<<strlen(iv)<<endl;
#endif
	/////////////////////////////////////////////////////////////////////
	//Encryption
	if (enc_operation) {
		char* pt = read_inputfile(input_file);
//	const int plain_size = strlen(pt);
#ifdef DEBUG
		cout<<"Plaintext is: "<<pt<<endl;
		cout<<"Plaintext size is "<<input_file_size<<endl;
#endif

		char* mycipher = new char[input_file_size + 1];
		mycipher[input_file_size] = '\0';
		char mytag[TAG_LEN + 1];
		mytag[TAG_LEN] = '\0';

		int mycipher_size = aes_128_gcm_encrypt(pt, enc_key, mycipher, mytag);
		if (mycipher_size != input_file_size) {
			cout
					<< "Encryption problem: cipher size does not match plaintext size!"
					<< endl;
			exit(1);
		}
#ifdef DEBUG
		cout<<"Returned ciphertext size is "<<mycipher_size<<endl;
#endif DEBUG
		write_outputfile(output_file, mytag, 0, true);
		write_outputfile(output_file, mycipher, 1, true);
		if (pt != NULL) {
			delete[] pt;
		}
		if (mycipher != NULL) {
			delete[] mycipher;
		}
	}
	//////////////////////////////////////////////////////////////////////
	//Decryption
	else {
		char* mycipher = read_inputfile(input_file);
//		char my_cipher_tag[TAG_LEN+1];
//		my_cipher_tag[TAG_LEN] = '\0';

//		memcpy(my_cipher_tag,mycipher,TAG_LEN);
#ifdef DEBUG
		cout<<"Ciphertext is: "<<pt<<endl;
		cout<<"Ciphertext size is "<<input_file_size<<endl;
#endif
		char *pt = new char[input_file_size - TAG_LEN+1];
		pt[input_file_size - TAG_LEN] = '\0';
//		char mytag[TAG_LEN + 1];
//		mytag[TAG_LEN] = '\0';
		int my_plain_text_size_plus_tag = aes_128_gcm_decrypt(
				&mycipher[TAG_LEN], mycipher, enc_key, pt);
//		cout << "Reached here!" << endl;
		if (my_plain_text_size_plus_tag != input_file_size-TAG_LEN) {
			cout
					<< "Decryption problem: plain size does not match plaintext size! "
					<< endl;
			exit(1);
		}
#ifdef DEBUG
		cout<<"Returned plaintext size is "<<my_plain_text_size<<endl;
#endif DEBUG
		write_outputfile(output_file, pt, 0, false);
		if (mycipher != NULL) {
			delete[] mycipher;
		}
		if (pt != NULL) {
			delete[] pt;
		}
	}
	//Remove pointers
	////////////////////////////////////////////////////////
	delete[] enc_key;
	delete[] iv;
	ERR_free_strings();
	return 0;
}

