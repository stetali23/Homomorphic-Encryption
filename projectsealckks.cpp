/****************************************/
/* SEAL CKKS */
/* Parts of code borrowed from:         */
/* 4_CKKS_basics.cpp   and github                 */
/* final Equation e = y(x+z) */
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
	/*****Set Parameters and Context*****/
	clock_t cc_clock;
	cc_clock = clock();

	EncryptionParameters parms(scheme_type::CKKS);

	 size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, { 60, 40, 40, 60 }));

	double scale = pow(2.0, 40);

    auto context = SEALContext::Create(parms);

	/*****Key Generation*****/
	clock_t key_clock;
	key_clock = clock();

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
	cc_clock = clock() - cc_clock - key_clock;

	/*****Encode and Encrypt*****/
	clock_t enc_clock;
	enc_clock = clock();

    int N = 2760; 
	vector<double> first_x; 
	vector<double> second_y; 
	vector<double> third_z;   

	for(int i = 0; i < N; i++)
	{
		double a = (rand()/(double(RAND_MAX))*50);
		first_x.push_back(a);

		double b = (rand()/(double(RAND_MAX))*50);
		second_y.push_back(b);

		double c = (rand()/(double(RAND_MAX))*50);
		third_z.push_back(c);
	}



    Plaintext plain_first_x, plain_second_y, plain_third_z;
    encoder.encode(first_x, scale, plain_first_x);
    encoder.encode(second_y, scale, plain_second_y);
    encoder.encode(third_z, scale, plain_third_z);

    Ciphertext enc_first_x, enc_second_y, enc_third_z;
    	encryptor.encrypt(plain_first_x, enc_first_x);
	encryptor.encrypt(plain_second_y, enc_second_y);
	encryptor.encrypt(plain_third_z, enc_third_z);

	enc_clock = clock() - enc_clock;

    /*****Evaluate*****/
	clock_t eval_clock;
	eval_clock = clock();

    Ciphertext enc_final_e, enc_mul;

                evaluator.multiply(enc_first_x, enc_second_y, enc_final_e);
	evaluator.relinearize_inplace(enc_final_e, relin_keys);
	evaluator.rescale_to_next_inplace(enc_final_e);

                evaluator.multiply(enc_third_z, enc_second_y, enc_mul);
	evaluator.relinearize_inplace(enc_mul, relin_keys);
	evaluator.rescale_to_next_inplace(enc_mul);

	
	enc_final_e.scale() = pow(2.0,40);
	enc_mul.scale() = pow(2.0,40);

	parms_id_type last_parms_id = enc_final_e.parms_id();
	evaluator.mod_switch_to_inplace(enc_mul, last_parms_id);
	evaluator.add_inplace(enc_final_e, enc_mul);
	
	eval_clock = clock() - eval_clock;

	/*****Decrypt*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_final_e;
	decryptor.decrypt(enc_final_e, plain_final_e);

	dec_clock = clock() - dec_clock;

	/*****Decode*****/
	vector<double> final_e;
	encoder.decode(plain_final_e, final_e);

	/*****Print*****/
	cout << "Solving Equation for " << N << " instances. "<< endl << endl;
	cout << "Value_X: " << endl;
	print_vector(first_x, 10, 4);

	cout << "Value_Y: " << endl;
	print_vector(second_y, 10, 4);

	cout << "Value_z: " << endl;
	print_vector(third_z, 10, 4);

	cout << " Final Equation: " << endl;
	print_vector(final_e, 15, 4);

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation (e=y(x+z)) : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;

}
