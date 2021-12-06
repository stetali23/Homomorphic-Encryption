/***************************************/
/* Parts of code borrowed from:        */
/* demo-simple-real-numbers.cpp        */
/* examples from Github */
/* final Equation e= y(x+z)    */
/***************************************/
#include "palisade.h"
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>
using namespace std;
using namespace lbcrypto;

void print(Plaintext v, int length)
{

    int print_size = 20;
    int end_size = 2;

    cout << endl;
    cout << "    [";

    for (int i = 0; i < print_size; i++)
    {
        cout << setw(3) << right << v->GetCKKSPackedValue()[i].real() << ",";
    }

    cout << setw(3) << " ...,";

    for (int i = length - end_size; i < length; i++)
    {
        cout << setw(3) << v->GetCKKSPackedValue()[i].real() << ((i != length - 1) ? "," : " ]\n");
    }
    
    cout << endl;
}

int main()
{
	/*****Setup CryptoContext*****/
	clock_t cc_clock;
	cc_clock = clock();

	uint32_t multDepth = 1;
	uint32_t scaleFactorBits = 50;
	uint32_t batchSize = 2000; //num plaintext slots
	SecurityLevel securityLevel = HEStd_128_classic;

	CryptoContext<DCRTPoly> cc =
			CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
			   multDepth,
			   scaleFactorBits,
			   batchSize,
			   securityLevel);

	//cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << endl << endl;

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	cc_clock = clock() - cc_clock;

	/*****Key Generation*****/
	clock_t key_clock;
	key_clock = clock();

	auto keys = cc->KeyGen();
	cc->EvalMultKeyGen(keys.secretKey);
	cc->EvalAtIndexKeyGen(keys.secretKey, { 1, -2 });

	key_clock = clock() - key_clock;

	/*****Encoding*****/

	clock_t enc_clock;
	enc_clock = clock();

	int N = 2760; 
	vector<complex<double>> first_x; 
	vector<complex<double>> second_y; 
	vector<complex<double>> third_z;   

	for(int i = 0; i < N; i++)
	{
                double a = (rand()/(double(RAND_MAX))*25);
		first_x.push_back(a);

		double b = (rand()/(double(RAND_MAX))*50);
		second_y.push_back(b);

		double c = (rand()/(double(RAND_MAX))*30);
		third_z.push_back(c);

                
	}
	

	Plaintext plain_first_x = cc->MakeCKKSPackedPlaintext(first_x);
	Plaintext plain_second_y = cc->MakeCKKSPackedPlaintext(second_y);
	Plaintext plain_third_z = cc->MakeCKKSPackedPlaintext(third_z);

	// Encrypt the encoded vectors
	auto enc_first_x = cc->Encrypt(keys.publicKey, plain_first_x );
	auto enc_second_y = cc->Encrypt(keys.publicKey, plain_second_y );
	auto enc_third_z = cc->Encrypt(keys.publicKey, plain_third_z );

	enc_clock = clock() - enc_clock;

	/*****Evaluation*****/
	clock_t eval_clock;
	eval_clock = clock();

               auto cAdd = cc->EvalAdd(enc_first_x , enc_third_z );
               auto cMult = cc->EvalMult(cAdd , enc_second_y);
	eval_clock = clock() - eval_clock;

	/*****Decryption and output*****/
	clock_t dec_clock;
	dec_clock = clock();
	
	Plaintext plain_final_e;
	cout.precision(6);

	cc->Decrypt(keys.secretKey, cMult, &plain_final_e);

	dec_clock = clock() - dec_clock;

	/*****Print*****/
	cout << "Solving Equation for" << N << " instances. "<< endl << endl;

	cout << "Value_X: " << endl;
	print(plain_first_x, N);

	cout << "Value_Y: " << endl;
	print(plain_second_y, N);

	cout << "Value_Z: " << endl;
	print(plain_third_z, N);

	cout << " Final Equation: " << endl;
	print(plain_final_e, N);

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation (e = y(x+z) ) : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;

	return 0;
}
