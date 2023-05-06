/*
 * ======================================================================
 * 12_matvec.cpp
 * ======================================================================
 * Example of matrix vector multiplication.
 *
 * Author : Cheng Tan
 *   Date : May 6, 2023
 */

#include "examples.h"

using namespace std;
using namespace seal;

void matvec()
{


    print_example_banner("Example: CKKS Basics");

    //------
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, { 26, 26, 26, 26 }));

    double scale = pow(2.0, 26);
    // auto context = SEALContext::Create(parms);
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    //--------modulus
    for (int i = 0; i < 4; i++)
    {
        cout << "coeff_modulus[" << i << "] = " << parms.coeff_modulus()[i].value() << endl;
        cout << "coeff_modulus[" << i << "].const_ratio()[0] = " << parms.coeff_modulus()[i].const_ratio()[0] << endl;
        cout << "coeff_modulus[" << i << "].const_ratio()[1] = " << parms.coeff_modulus()[i].const_ratio()[1] << endl;
    }
    //-------
    // KeyGenerator keygen(context);
    // auto public_key = keygen.public_key();
    // auto secret_key = keygen.secret_key();
    // auto relin_keys = keygen.relin_keys();
    // GaloisKeys gal_keys = keygen.galois_keys();
    // Encryptor encryptor(context, public_key);
    // Evaluator evaluator(context);
    // Decryptor decryptor(context, secret_key);
    // CKKSEncoder encoder(context);
    
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

    //----------rootpowers
    /*Plaintext rootpower_pl;
    Ciphertext rootpower;
    encoder.encode(5, scale, rootpower_pl);
    encryptor.encrypt(rootpower_pl, rootpower);
    auto context_data_ptr = context->get_context_data(rootpower.parms_id());
    auto& context_data = *context_data_ptr;
    auto& coeff_small_ntt_tables = context_data.small_ntt_tables();

    std::ofstream rp("D:/Project/CodeSpace/220930-DATA/221017-RescaleData/rootpowers/rp.dat", ios::out);
    for (size_t modulus_index = 0; modulus_index < 6; modulus_index++) {
        for (size_t k = 0; k < 8192; k++) {
            rp << coeff_small_ntt_tables[modulus_index].get_from_root_powers(k);
            rp << endl;
        }
    }
    rp.close();

    std::ofstream idt("D:/Project/CodeSpace/220930-DATA/221017-RescaleData/rootpowers/idt.dat", ios::out);
    for (size_t modulus_index = 0; modulus_index < 6; modulus_index++) {
        for (size_t k = 0; k < 8192; k++) {
            idt << coeff_small_ntt_tables[modulus_index].get_from_inv_root_powers_div_two(k);
            idt << endl;
        }
    }
    idt.close();*/

    //------
    //----[1, 1.25, 1.5, 1.75, 2, 2.25, 2.5, 2.75, 0,0,0,0,0,]
    vector<double> c_input;
    c_input.reserve(slot_count);
    double curr_point = 1;
    double step_size = 0.25;
    for (size_t i = 0; i < 8; i++, curr_point += step_size)
    {
        c_input.push_back(curr_point);
    }
    for (size_t i = 8; i < slot_count; i++)
    {
        c_input.push_back(0);
    }
    cout << "Input ciphertext vector: " << endl;
    print_vector(c_input, 10, 7);

    //-------
    //----[1, 1.25, 1.5, 1.75, 2, 2.25, 2.5, 2.75, 0,0,0,0,0,]
    vector<double> p_input_1, p_input_4, p_input_7, p_input_10;
    p_input_1.reserve(slot_count);
    p_input_4.reserve(slot_count);
    p_input_7.reserve(slot_count);
    p_input_10.reserve(slot_count);
    curr_point = 1;
    step_size = 0.25;
    for (size_t i = 0; i < 8; i++, curr_point += step_size)
    {
        p_input_1.push_back(curr_point);
        p_input_4.push_back(curr_point);
        p_input_7.push_back(curr_point);
        p_input_10.push_back(curr_point);
    }
    for (size_t i = 8; i < slot_count; i++)
    {
        p_input_1.push_back(0);
        p_input_4.push_back(0);
        p_input_7.push_back(0);
        p_input_10.push_back(0);
    }
    cout << "Input plaintext vector 1: " << endl;
    print_vector(p_input_1, 10, 7);

    vector<double> p_input_2, p_input_5, p_input_8, p_input_11;
    p_input_2.reserve(slot_count);
    p_input_5.reserve(slot_count);
    p_input_8.reserve(slot_count);
    p_input_11.reserve(slot_count);
    curr_point = 2; 
    step_size = 0.25;
    for (size_t i = 0; i < 8; i++, curr_point += step_size)
    {
        p_input_2.push_back(curr_point);
        p_input_5.push_back(curr_point);
        p_input_8.push_back(curr_point);
        p_input_11.push_back(curr_point);
    }
    for (size_t i = 8; i < slot_count; i++)
    {
        p_input_2.push_back(0);
        p_input_5.push_back(0);
        p_input_8.push_back(0);
        p_input_11.push_back(0);
    }
    cout << "Input plaintext vector 2: " << endl;
    print_vector(p_input_2, 10, 7);

    vector<double> p_input_3, p_input_6, p_input_9, p_input_12;
    p_input_3.reserve(slot_count);
    p_input_6.reserve(slot_count);
    p_input_9.reserve(slot_count);
    p_input_12.reserve(slot_count);
    curr_point = 3; 
    step_size = 0.25;
    for (size_t i = 0; i < 8; i++, curr_point += step_size)
    {
        p_input_3.push_back(curr_point);
        p_input_6.push_back(curr_point);
        p_input_9.push_back(curr_point);
        p_input_12.push_back(curr_point);
    }
    for (size_t i = 8; i < slot_count; i++)
    {
        p_input_3.push_back(0);
        p_input_6.push_back(0);
        p_input_9.push_back(0);
        p_input_12.push_back(0);
    }
    cout << "Input plaintext vector 3: " << endl;
    print_vector(p_input_3, 10, 7);

    //--------- 
    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(c_input, scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    // auto context_data_ptr = context.get_context_data(x1_encrypted.parms_id());
    // auto& context_data = *context_data_ptr;
    // auto& inv_last_coeff_mod_array = context_data.base_converter()->get_inv_last_coeff_mod_array();

    // for (int i = 0; i < 4; i++)
    // {
    //     cout << "inv_last_coeff_mod_array[" << i << "] = " << inv_last_coeff_mod_array[i] << endl;
    // }

    //
    // Plaintext plain_coeff3;
    vector<Plaintext> plain_coeff(12);
    encoder.encode(p_input_1, scale, plain_coeff[0]);
    encoder.encode(p_input_2, scale, plain_coeff[1]);
    encoder.encode(p_input_3, scale, plain_coeff[2]);
    encoder.encode(p_input_4, scale, plain_coeff[3]);
    encoder.encode(p_input_5, scale, plain_coeff[4]);
    encoder.encode(p_input_6, scale, plain_coeff[5]);
    encoder.encode(p_input_7, scale, plain_coeff[6]);
    encoder.encode(p_input_8, scale, plain_coeff[7]);
    encoder.encode(p_input_9, scale, plain_coeff[8]);
    encoder.encode(p_input_10, scale, plain_coeff[9]);
    encoder.encode(p_input_11, scale, plain_coeff[10]);
    encoder.encode(p_input_12, scale, plain_coeff[11]);
    vector<Ciphertext> encrypted_out(12);

    //
    cout << "x1_encrypted.size() = " << x1_encrypted.size() << endl;
    cout << "x1_encrypted.coeff_modulus_size() = " << x1_encrypted.coeff_modulus_size() << endl;

    std::ofstream input_c("./12-matvec/generate/input_c.dat", ios::out);
    for (size_t k = 0; k < x1_encrypted.size(); k++)
    { 
        for (size_t i = 0; i < x1_encrypted.coeff_modulus_size() * poly_modulus_degree; i++)
        {
            uint64_t temp;
            temp = x1_encrypted.data(k)[i];
            input_c << temp;
            input_c << endl;
        }
    }
    input_c.close();

    std::ofstream input_12p("./12-matvec/generate/input_12p.dat", ios::out);
    for (size_t p_index = 0; p_index < 12; p_index++) {
        for (size_t i = 0; i < 3 * poly_modulus_degree; i++)
        {
            input_12p << plain_coeff[p_index].data()[i];
            input_12p << endl;
        }  
    }
    input_12p.close();
 

    //-------------key----------------------------------------------------------------------------------------

    // galois key
    int decomp_mod_count = 2;
    int key_mod_count = 4;
    int coeff_count = 8192;
    size_t Galois_elt[12] = {
        8193, 4097, 10241, 13313, 14849, 15617, 16001, 5953, 6561, 81, 9, 3 };

    size_t kswitch_keys_index[12] = {
        4096, 2048, 5120,  6656, 7424, 7808, 8000, 2976, 3280, 40, 4, 1 };


    //不从这里打印
   /* for (int rc = 0; rc < 12; rc++)
    {
        auto& key_vector = static_cast<KSwitchKeys&>(gal_keys).data()[kswitch_keys_index[rc]];

        std::ofstream keys_k0("D:/Project/CodeSpace/220930-DATA/230328-MatvecData-big/generate/keys_k0.dat", ios::out);
        for (int i = 0; i < decomp_mod_count; i++)
        {
            for (int index = 0; index < decomp_mod_count; index++)
            {
                for (int l = 0; l < coeff_count; l++)
                {
                    uint64_t temp;
                    temp = key_vector[i].data().data(0)[(index * coeff_count) + l];
                    keys_k0 << temp;
                    keys_k0 << endl;
                }
            }
            for (int index = key_mod_count - 1; index < key_mod_count; index++)
            {
                for (int l = 0; l < coeff_count; l++)
                {
                    uint64_t temp;
                    temp = key_vector[i].data().data(0)[(index * coeff_count) + l];
                    keys_k0 << temp;
                    keys_k0 << endl;
                }
            }
        }
        keys_k0.close();
        std::ofstream keys_k1("D:/Project/CodeSpace/220930-DATA/230328-MatvecData-big/generate/keys_k1.dat", ios::out);
        for (int i = 0; i < decomp_mod_count; i++)
        {
            for (int index = 0; index < decomp_mod_count; index++)
            {
                for (int l = 0; l < coeff_count; l++)
                {
                    uint64_t temp;
                    temp = key_vector[i].data().data(1)[(index * coeff_count) + l];
                    keys_k1 << temp;
                    keys_k1 << endl;
                }
            }
            for (int index = key_mod_count - 1; index < key_mod_count; index++)
            {
                for (int l = 0; l < coeff_count; l++)
                {
                    uint64_t temp;
                    temp = key_vector[i].data().data(1)[(index * coeff_count) + l];
                    keys_k1 << temp;
                    keys_k1 << endl;
                }
            }
        }
        keys_k1.close();
    }*/

    //---------  plaintext 0.75  --------------------------------------------------------
    // pc-mult
    for (int row = 0; row < 12; row++)
    {
        //if (row == 0) {
        //    cout << "p1--ciphertext--multiply_plain" << endl;
        //    cout << x1_encrypted.data()[0] << endl;    // 0
        //    cout << x1_encrypted.data()[1] << endl;    // 1
        //    cout << x1_encrypted.data()[2] << endl;    // 2
        //    cout << x1_encrypted.data()[3] << endl;    // 3
        //    cout << x1_encrypted.data()[7200] << endl; // 7200
        //    cout << x1_encrypted.data()[8191] << endl; // 8191

        //    cout << "p2--plaintext--multiply_plain" << endl;
        //    cout << plain_coeff[row].data()[0] << endl;    // 0
        //    cout << plain_coeff[row].data()[1] << endl;    // 1
        //    cout << plain_coeff[row].data()[2] << endl;    // 2
        //    cout << plain_coeff[row].data()[3] << endl;    // 3
        //    cout << plain_coeff[row].data()[7200] << endl; // 7200
        //    cout << plain_coeff[row].data()[8191] << endl; // 8191
        //}

        evaluator.multiply_plain(x1_encrypted, plain_coeff[row], encrypted_out[row]);

        //if (row == 0)
        //{
        //    cout << "pp--ciphertext--rescale" << endl;
        //    cout << encrypted_out[row].data()[0] << endl;	   // 0
        //    cout << encrypted_out[row].data()[1] << endl;	   // 1
        //    cout << encrypted_out[row].data()[2] << endl;	   // 2
        //    cout << encrypted_out[row].data()[3] << endl;	   // 3
        //    cout << encrypted_out[row].data()[7200] << endl;  // 7200
        //    cout << encrypted_out[row].data()[8191] << endl; // 8191
        //}

        evaluator.rescale_to_next_inplace(encrypted_out[row]);

        // rotation
        size_t rc = 0; 
        size_t step = 2048;
        vector<Ciphertext> rot_tmp(11);

        //if (row == 0) {
        //    cout << "p4--ciphertext--rotate_vector-0" << endl;
        //    cout << encrypted_out[row].data()[0] << endl;    // 0
        //    cout << encrypted_out[row].data()[1] << endl;    // 1
        //    cout << encrypted_out[row].data()[2] << endl;    // 2
        //    cout << encrypted_out[row].data()[3] << endl;    // 3
        //    cout << encrypted_out[row].data()[7200] << endl; // 7200
        //    cout << encrypted_out[row].data()[8191] << endl; // 8191
        //    cout << "i = 1" << endl;
        //    cout << encrypted_out[row].data()[0 + 8192] << endl;    // 0
        //    cout << encrypted_out[row].data()[1 + 8192] << endl;    // 1
        //    cout << encrypted_out[row].data()[2 + 8192] << endl;    // 2
        //    cout << encrypted_out[row].data()[3 + 8192] << endl;    // 3
        //    cout << encrypted_out[row].data()[7200 + 8192] << endl; // 7200
        //    cout << encrypted_out[row].data()[8191 + 8192] << endl; // 8191
        //}
        

        evaluator.rotate_vector(encrypted_out[row], step, gal_keys, rot_tmp[rc]);
        evaluator.add_inplace(rot_tmp[rc], encrypted_out[row]); // rc = 0

       
        for (; rc < 10; rc++)
        { 
            //if (row == 0) {
            //    cout << "p4--ciphertext--rotate_vector-"<< rc+1 << endl;
            //    cout << rot_tmp[rc].data()[0] << endl;    // 0
            //    cout << rot_tmp[rc].data()[1] << endl;    // 1
            //    cout << rot_tmp[rc].data()[2] << endl;    // 2
            //    cout << rot_tmp[rc].data()[3] << endl;    // 3
            //    cout << rot_tmp[rc].data()[7200] << endl; // 7200
            //    cout << rot_tmp[rc].data()[8191] << endl; // 8191
            //    cout << "i = 1" << endl;
            //    cout << rot_tmp[rc].data()[0 + 8192] << endl;    // 0
            //    cout << rot_tmp[rc].data()[1 + 8192] << endl;    // 1
            //    cout << rot_tmp[rc].data()[2 + 8192] << endl;    // 2
            //    cout << rot_tmp[rc].data()[3 + 8192] << endl;    // 3
            //    cout << rot_tmp[rc].data()[7200 + 8192] << endl; // 7200
            //    cout << rot_tmp[rc].data()[8191 + 8192] << endl; // 8191
            //}

            step = step >> 1;
            evaluator.rotate_vector(rot_tmp[rc], step, gal_keys, rot_tmp[rc + 1]);
            evaluator.add_inplace(rot_tmp[rc + 1], rot_tmp[rc]); 
        }

        //if (row == 0) {
        //    cout << "p5--ciphertext--rotate_vector-" << rc + 1 << endl;
        //    cout << rot_tmp[rc].data()[0] << endl;    // 0
        //    cout << rot_tmp[rc].data()[1] << endl;    // 1
        //    cout << rot_tmp[rc].data()[2] << endl;    // 2
        //    cout << rot_tmp[rc].data()[3] << endl;    // 3
        //    cout << rot_tmp[rc].data()[7200] << endl; // 7200
        //    cout << rot_tmp[rc].data()[8191] << endl; // 8191
        //}

        step = step >> 1;
        evaluator.rotate_vector(rot_tmp[rc], step, gal_keys, encrypted_out[row]);
        evaluator.add_inplace(encrypted_out[row], rot_tmp[rc]); 

        //if (row == 0) {
        //    cout << "p6--ciphertext--out--add_inplace" << endl;
        //    cout << encrypted_out[row].data()[0] << endl;    // 0
        //    cout << encrypted_out[row].data()[1] << endl;    // 1
        //    cout << encrypted_out[row].data()[2] << endl;    // 2
        //    cout << encrypted_out[row].data()[3] << endl;    // 3
        //    cout << encrypted_out[row].data()[7200] << endl; // 7200
        //    cout << encrypted_out[row].data()[8191] << endl; // 8191
        //}
    }

    //------
     std::ofstream output_12c("./12-matvec/generate/output_12c.dat", ios::out);

     for (size_t p_index = 0; p_index < 12; p_index++) {
         for (size_t k = 0; k < encrypted_out[p_index].size(); k++)
         {
             for (size_t i = 0; i < encrypted_out[p_index].coeff_modulus_size() * poly_modulus_degree; i++)
             {
                 output_12c << encrypted_out[p_index].data(k)[i];
                 output_12c << endl;
             }
         }
     }
     
     output_12c.close();


    seal::Plaintext plain_result;
    decryptor.decrypt(encrypted_out[0], plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "    + Computed result ...... Correct." << endl;
    print_vector(result, 10, 7);

}
