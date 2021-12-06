/****************************************/
/* SEAL BFV */
/* Parts of code borrowed from:         */
/* 1_bfv_basics.cpp and 2_encoders.cpp  and github*/
/* final e= y(x+z)*/
/****************************************/

#include <iostream>
#include <time.h>
#include <stdlib.h>
#include <vector>
#include "seal/seal.h"
#include "examples.h"

using namespace std;
using namespace seal;

int main()
{
	/*****Choose Parameters*****/
	clock_t cc_clock;
	cc_clock = clock();

	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = 8192;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

	//Enable batching
	parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

	auto context = SEALContext::Create(parms);
	//print_parameters(context);
	
	//Verify that batching is enabled
	//auto qualifiers = context->first_context_data()->qualifiers();
	//cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

	/*****Generate keys and functions*****/
	clock_t key_clock;
	key_clock = clock();

	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();
	RelinKeys relin_keys = keygen.relin_keys();

	key_clock = clock() - key_clock;

	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);

	//Set up batch encoder
	BatchEncoder batch_encoder(context);
	size_t slot_count = batch_encoder.slot_count();
	size_t row_size = slot_count / 2;
	
	
	cc_clock = clock() - cc_clock - key_clock;
	
	clock_t enc_clock;
	enc_clock = clock();
	//Generate the matrices of values 
	int N = 2760; //or 100 or 1000
	vector<uint64_t> first_x(slot_count, 0ULL);    
	vector<uint64_t> second_y(slot_count, 0ULL);               
	vector<uint64_t> third_z(slot_count, 0ULL);                 

	for(int r = 0; r < 2; r++)
	{
		for(int c = 0; c < N/2; c++) 
		{
			unsigned long long int a = rand() % 25;
			first_x[r*row_size + c] = a;

			unsigned long long int b = rand() % 50;
			second_y[r*row_size + c] = b;

			unsigned long long int d = rand() % 30;
			third_z[r*row_size + c] = d;
		}
	}
	
	
	
	/*****Encode*****/
	Plaintext plain_first_x;
	Plaintext plain_second_y;
	Plaintext plain_third_z;

	batch_encoder.encode(first_x, plain_first_x);
	batch_encoder.encode(second_y, plain_second_y);
	batch_encoder.encode(third_z, plain_third_z);

	/*****Encrypt*****/
	Ciphertext enc_first_x;
	Ciphertext enc_second_y;
	Ciphertext enc_third_z;

	encryptor.encrypt(plain_first_x, enc_first_x);
	encryptor.encrypt(plain_second_y, enc_second_y);
	encryptor.encrypt(plain_third_z, enc_third_z);

	enc_clock = clock() - enc_clock;

	/*****Evaluate*****/
	clock_t eval_clock;
	eval_clock = clock();

	Ciphertext enc_final_e;

	evaluator.add(enc_first_x, enc_third_z, enc_final_e);
	evaluator.multiply_inplace(enc_final_e, enc_second_y);

	eval_clock = clock() - eval_clock;

	/*****Decrypt*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_final_e;

	decryptor.decrypt(enc_final_e, plain_final_e);
	
	dec_clock = clock() - dec_clock;

	/*****Decode*****/
	vector<uint64_t> final_e;
	batch_encoder.decode(plain_final_e, final_e);
	
	/*****Print*****/
	cout << "Solving Equation for " << N << " instances. "<< endl << endl;
	cout << "Value_X: " << endl;
	print_matrix(first_x, 10);

	cout << "Value_Y: " << endl;
	print_matrix(second_y, 10);

	cout << "Value_Z: " << endl;
	print_matrix(third_z, 10);

	cout << " Final Equation: " << endl;
	print_matrix(final_e, 10);

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation (e = y(x+z)) : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;

	return 0;
}
