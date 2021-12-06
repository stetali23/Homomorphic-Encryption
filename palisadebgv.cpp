#include "palisade.h"
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>
#include <fstream>
#include <random>
#include <iterator>
using namespace std;
using namespace lbcrypto;

int main() {
  // Sample Program: Step 1 - Set CryptoContext
  clock_t cryptoContext_clock;
  cryptoContext_clock = clock();
  // Set the main parameters
  int plaintextModulus = 65537;
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = 2;

  // Instantiate the crypto context
  CryptoContext<DCRTPoly> cryptoContext =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          depth, plaintextModulus, securityLevel, sigma, depth, OPTIMIZED, BV);
// Enable features that you wish to use
  cryptoContext->Enable(ENCRYPTION);
  cryptoContext->Enable(SHE);
  cryptoContext->Enable(LEVELEDSHE);

  cryptoContext_clock = clock() - cryptoContext_clock;

        /*****KeyGen*****/
        clock_t key_clock;
        key_clock = clock();

        LPKeyPair<DCRTPoly> kp = cryptoContext->KeyGen();
        cryptoContext->EvalSumKeyGen(kp.secretKey);
        cryptoContext->EvalMultKeyGen(kp.secretKey);

        key_clock = clock() - key_clock;

        /*****Encode and Encrypt*****/
        clock_t enc_clock;
        enc_clock = clock();
        std::vector<int64_t> first_x= { 1,2,3,4,5,6,7,8};
        Plaintext plain_first_x = cryptoContext->MakePackedPlaintext(first_x);
        std::cout << "Value_X\n\t" << first_x<< std::endl;

        std::vector<int64_t> second_y = { 10, 14, 24, 23, 18, 9, 13, 7};
        Plaintext plain_second_y = cryptoContext->MakePackedPlaintext(second_y);

        std::cout << "Value_Y \n\t" << second_y << std::endl;

        std::vector<int64_t> third_z = { 1,2,3,2,1,2,1,2};
        Plaintext plain_third_z = cryptoContext->MakePackedPlaintext(third_z);

        std::cout << "Value_Z \n\t" << third_z << std::endl;

        auto enc_first_x= cryptoContext->Encrypt(kp.publicKey, plain_first_x);
        auto enc_second_y = cryptoContext->Encrypt(kp.publicKey, plain_second_y);
        auto enc_third_z = cryptoContext->Encrypt(kp.publicKey, plain_third_z);

        enc_clock = clock() - enc_clock;
       
       /*****Evaluate*****/
        clock_t eval_clock;
        eval_clock = clock();

        auto enc_final_e= cryptoContext->EvalAdd(enc_first_x, enc_third_z);
        enc_final_e = cryptoContext->EvalMult(enc_final_e, enc_second_y);

        eval_clock = clock() - eval_clock;

        /*****Decrypt*****/
        clock_t dec_clock;
        dec_clock = clock();

        Plaintext plain_final_e;

        cryptoContext->Decrypt(kp.secretKey, enc_final_e, &plain_final_e);

        dec_clock = clock() - dec_clock;

        /*****Print*****/
        std::cout << "Final Equation \n\t" << plain_final_e << std::endl;

        cout << "Times:" <<endl;
        cout << "Parameter Generation  : " << ((float) cryptoContext_clock)/CLOCKS_PER_SEC << endl;
        cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
        cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
        cout << "Evaluation (e= y(x+z)) : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
        cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
}
