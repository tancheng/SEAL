/*
 * ======================================================================
 * 12_matvec.cpp
 * ======================================================================
 * Example of matrix vector multiplication.
 *
 * Author : Cheng Tan, Yilan Zhu
 *   Date : May 6, 2023
 */

#include "examples.h"

using namespace std;
using namespace seal;

void matvec() {

  print_example_banner("Example: CKKS Basics");

  // Setups FHE related parameters.
  size_t poly_modulus_degree = 8192;
  int param_power = 26;

  // Setups the matrix-vector multiplication related parameters.
  // matrix: 12x8, vector: 8x1.
  int mat_num_row = 12;
  int mat_num_col = 8;
  int vec_len = mat_num_col;

  // Initializes params;
  EncryptionParameters params(scheme_type::ckks);
  params.set_poly_modulus_degree(poly_modulus_degree);
  params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree,
        {param_power, param_power, param_power, param_power}));
  double scale = pow(2.0, param_power);
  SEALContext context(params);
  print_parameters(context);

  cout << endl;
  for (int i = 0; i < 4; i++) {
    cout << "coeff_modulus[" << i << "] = " << params.coeff_modulus()[i].value() << endl;
    cout << "coeff_modulus[" << i << "].const_ratio()[0] = " << params.coeff_modulus()[i].const_ratio()[0] << endl;
    cout << "coeff_modulus[" << i << "].const_ratio()[1] = " << params.coeff_modulus()[i].const_ratio()[1] << endl;
  }

  KeyGenerator keygen(context);
  SecretKey secret_key = keygen.secret_key();
  PublicKey public_key;
  keygen.create_public_key(public_key);
  RelinKeys relin_keys;
  keygen.create_relin_keys(relin_keys);
  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);
  Decryptor decryptor(context, secret_key);
  GaloisKeys gal_keys;
  keygen.create_galois_keys(gal_keys);
  CKKSEncoder encoder(context);
  size_t slot_count = encoder.slot_count();
  cout << "Number of slots: " << slot_count << endl;

  // Constructs the input vector that will be encoded and encripted.
  vector<double> vec_in;
  vec_in.reserve(slot_count);
  double cur_point = 1;
  double step_size = 0.25;
  for (size_t i = 0; i < slot_count; i++, cur_point += step_size) {
    if (i < vec_len) {
      vec_in.push_back(cur_point);
    } else {
      vec_in.push_back(0);
    }
  }
  cout << "Input ciphertext vector: " << endl;
  print_vector(vec_in, 10, 7);

  // Constructs the input matrix that will be encoded without
  // being encripted.
  vector<vector<double>> mat_in;
  for (int r = 0; r < mat_num_row; ++r) {
    vector<double> row;
    row.reserve(slot_count);
    for (int i = 0; i < slot_count; ++i) {
      if (i < mat_num_col) {
        row.push_back(r + i * step_size);
      } else {
        row.push_back(0);
      }
    }
    mat_in.push_back(row);
  }

  // Encodes and encrypts the input vector.
  Plaintext vec_plain;
  print_line(__LINE__);
  cout << "Encode input vectors." << endl;
  encoder.encode(vec_in, scale, vec_plain);
  Ciphertext vec_encrypted;
  encryptor.encrypt(vec_plain, vec_encrypted);

  // Encodes the input matrix.
  vector<Plaintext> plain_coeff(mat_num_row);
  for (int r = 0; r < mat_num_row; ++r) {
    encoder.encode(mat_in[r], scale, plain_coeff[r]);
  }

  cout << "vec_encrypted.size() = " << vec_encrypted.size() << endl;
  cout << "vec_encrypted.coeff_modulus_size() = " << vec_encrypted.coeff_modulus_size() << endl;

  std::ofstream input_c("./12-matvec/generate/input_c.dat", ios::out);
  for (size_t k = 0; k < vec_encrypted.size(); k++) {
    for (size_t i = 0; i < vec_encrypted.coeff_modulus_size() * poly_modulus_degree; i++) {
      uint64_t temp;
      temp = vec_encrypted.data(k)[i];
      input_c << temp;
      input_c << endl;
    }
  }
  input_c.close();

  std::ofstream input_12p("./12-matvec/generate/input_12p.dat", ios::out);
  for (size_t r = 0; r < 12; r++) {
      for (size_t i = 0; i < 3 * poly_modulus_degree; i++)
      {
          input_12p << plain_coeff[r].data()[i];
          input_12p << endl;
      }
  }
  input_12p.close();
 
  // Setups galois key.
  int decomp_mod_count = 2;
  int key_mod_count = 4;
  int coeff_count = 8192;
  // TODO(yilan): fixed 12?
  size_t Galois_elt[12] = {
      8193, 4097, 10241, 13313, 14849, 15617, 16001, 5953, 6561, 81, 9, 3 };

  size_t kswitch_keys_index[12] = {
      4096, 2048, 5120,  6656, 7424, 7808, 8000, 2976, 3280, 40, 4, 1 };

  // Performs matrix-vector multiplication. The matrix is encoded and the
  // vector is encoded and encrypted.
  vector<Ciphertext> encrypted_out(mat_num_row);
  for (int r = 0; r < mat_num_row; r++) {

    // Performs multilication.
    evaluator.multiply_plain(vec_encrypted, plain_coeff[r], encrypted_out[r]);
    evaluator.rescale_to_next_inplace(encrypted_out[r]);

    // Rotates intermediate output for accumulation.
    size_t rc = 0;
    size_t step = 2048;
    vector<Ciphertext> rot_tmp(mat_num_row - 1);

    evaluator.rotate_vector(encrypted_out[r], step, gal_keys, rot_tmp[rc]);
    evaluator.add_inplace(rot_tmp[rc], encrypted_out[r]); // rc = 0

    for (; rc < mat_num_row - 2; rc++) {
        step = step >> 1;
        evaluator.rotate_vector(rot_tmp[rc], step, gal_keys, rot_tmp[rc + 1]);
        evaluator.add_inplace(rot_tmp[rc + 1], rot_tmp[rc]);
    }

    step = step >> 1;
    evaluator.rotate_vector(rot_tmp[rc], step, gal_keys, encrypted_out[r]);
    evaluator.add_inplace(encrypted_out[r], rot_tmp[rc]);
  }

  std::ofstream output_12c("./12-matvec/generate/output_12c.dat", ios::out);

  for (size_t r = 0; r < mat_num_row; r++) {
    for (size_t k = 0; k < encrypted_out[r].size(); k++) {
      for (size_t i = 0; i < encrypted_out[r].coeff_modulus_size() * poly_modulus_degree; i++) {
        output_12c << encrypted_out[r].data(k)[i];
        output_12c << endl;
      }
    }
  }

  output_12c.close();

  vector<double> decrypted_output;
  for (int r = 0; r < mat_num_row; ++r) {
    seal::Plaintext plain_result;
    decryptor.decrypt(encrypted_out[r], plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    decrypted_output.push_back(result[0]);
    // cout << "    + Computed result[" << r << "] (size: " << result.size() << "): " << endl;
    // print_vector(result, 10, 7);
  }

  cout << "================= decrypted output ====================" << endl;
  for (int r = 0; r < mat_num_row; ++r) {
    cout << decrypted_output[r] << " ";
  }
  cout << endl;

}
