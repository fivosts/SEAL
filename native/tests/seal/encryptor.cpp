

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/context.h"
#include "seal/encryptor.h"
#include "seal/decryptor.h"
#include "seal/keygenerator.h"
#include "seal/batchencoder.h"
#include "seal/ckks.h"
#include "seal/intencoder.h"
#include "seal/modulus.h"
#include <cstdint>
#include <cstddef>
#include <ctime>

using namespace seal;
using namespace std;

namespace SEALTest
{
    TEST(EncryptorTest, t0)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(0x12345678), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x12345678ULL, encoder.decode_uint64(plain));

        }
    }

    TEST(EncryptorTest, t1)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(0x12345678), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        }
    }

    TEST(EncryptorTest, t2)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(0), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0ULL, encoder.decode_uint64(plain));
        }
    }


    TEST(EncryptorTest, t3)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(0), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EncryptorTest, t4)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(1), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(1ULL, encoder.decode_uint64(plain));
        }
    }

    TEST(EncryptorTest, t5)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(1), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EncryptorTest, t6)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(2), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(2ULL, encoder.decode_uint64(plain));

        }
    }


    TEST(EncryptorTest, t7)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(2), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(2ULL, encoder.decode_uint64(plain));

        }
    }

    TEST(EncryptorTest, t8)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFD)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFDULL, encoder.decode_uint64(plain));

        }
    }

    TEST(EncryptorTest, t9)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFD)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        }
    }


    TEST(EncryptorTest, t10)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFE)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFEULL, encoder.decode_uint64(plain));
        }
    }


    TEST(EncryptorTest, t11)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFE)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EncryptorTest, t12)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFF)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFFULL, encoder.decode_uint64(plain));
        }
    }

    TEST(EncryptorTest, t13)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFF)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }


    TEST(EncryptorTest, t156)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, encoder.decode_uint64(plain));
        }
    }

    TEST(EncryptorTest, t157)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EncryptorTest, t14)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(314159265), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(314159265ULL, encoder.decode_uint64(plain));
        }
    }

    TEST(EncryptorTest, t15)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(314159265), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

////////////////////////////////////////////////////////////// block 1 end

    TEST(EncryptorTest, t16)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(0x12345678), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x12345678ULL, encoder.decode_uint64(plain));

        }
    }

    TEST(EncryptorTest, t17)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(0x12345678), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        }
    }

    TEST(EncryptorTest, t18)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(0), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0ULL, encoder.decode_uint64(plain));
        }
    }


    TEST(EncryptorTest, t19)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(0), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EncryptorTest, t20)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(1), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(1ULL, encoder.decode_uint64(plain));
        }
    }

    TEST(EncryptorTest, t21)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(1), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EncryptorTest, t22)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(2), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(2ULL, encoder.decode_uint64(plain));

        }
    }


    TEST(EncryptorTest, t23)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(2), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(2ULL, encoder.decode_uint64(plain));

        }
    }

    TEST(EncryptorTest, t24)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFD)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFDULL, encoder.decode_uint64(plain));

        }
    }

    TEST(EncryptorTest, t25)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFD)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        }
    }


    TEST(EncryptorTest, t26)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFE)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFEULL, encoder.decode_uint64(plain));
        }
    }


    TEST(EncryptorTest, t27)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFE)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EncryptorTest, t28)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFF)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFFULL, encoder.decode_uint64(plain));
        }
    }

    TEST(EncryptorTest, t29)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFF)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }


    TEST(EncryptorTest, t158)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, encoder.decode_uint64(plain));
        }
    }

    TEST(EncryptorTest, t159)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EncryptorTest, t30)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(314159265), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(314159265ULL, encoder.decode_uint64(plain));
        }
    }

    TEST(EncryptorTest, t31)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, {40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(314159265), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

// block 2 start

///////////////////////////////////////////////////////////// block 2 end

// block 3 stat

    TEST(EncryptorTest, t32)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(0x12345678), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x12345678ULL, encoder.decode_uint64(plain));

        }
    }

    TEST(EncryptorTest, t33)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(0x12345678), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        }
    }

    TEST(EncryptorTest, t34)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(0), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0ULL, encoder.decode_uint64(plain));
        }
    }


    TEST(EncryptorTest, t35)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(0), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EncryptorTest, t36)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(1), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(1ULL, encoder.decode_uint64(plain));
        }
    }

    TEST(EncryptorTest, t37)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(1), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EncryptorTest, t38)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(2), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(2ULL, encoder.decode_uint64(plain));

        }
    }


    TEST(EncryptorTest, t39)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(2), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(2ULL, encoder.decode_uint64(plain));

        }
    }

    TEST(EncryptorTest, t40)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFD)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFDULL, encoder.decode_uint64(plain));

        }
    }

    TEST(EncryptorTest, t41)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFD)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        }
    }


    TEST(EncryptorTest, t42)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFE)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFEULL, encoder.decode_uint64(plain));
        }
    }


    TEST(EncryptorTest, t43)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFE)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EncryptorTest, t160)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFF)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0x7FFFFFFFFFFFFFFFULL, encoder.decode_uint64(plain));
        }
    }

    TEST(EncryptorTest, t161)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFF)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EncryptorTest, t44)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, encoder.decode_uint64(plain));
        }
    }

    TEST(EncryptorTest, t45)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF)), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }


    TEST(EncryptorTest, t46)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(314159265), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(314159265ULL, encoder.decode_uint64(plain));
        }
    }

    TEST(EncryptorTest, t47)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, {40, 40, 40}));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;

            encryptor.encrypt(encoder.encode(314159265), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

//////////////////////////////////////////////////////////// block 3 end


//block 4

    TEST(EncryptorTest, t48)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, { 40, 40, 40 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.secret_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            stringstream stream;

            encryptor.encrypt_symmetric(encoder.encode(314159265), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(314159265ULL, encoder.decode_uint64(plain));
        }
    }

    TEST(EncryptorTest, t49)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, { 40, 40, 40 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.secret_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            stringstream stream;

            encryptor.encrypt_symmetric(encoder.encode(314159265), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EncryptorTest, t50)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, { 40, 40, 40 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.secret_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            stringstream stream;

            encryptor.encrypt_symmetric(encoder.encode(314159265), encrypted);
            decryptor.decrypt(encrypted, plain);

            encryptor.encrypt_symmetric_save(encoder.encode(314159265), stream);
            encrypted.load(context, stream);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(314159265ULL, encoder.decode_uint64(plain));
        }
    }

    TEST(EncryptorTest, t51)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, { 40, 40, 40 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);

            Encryptor encryptor(context, keygen.secret_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            stringstream stream;

            encryptor.encrypt_symmetric(encoder.encode(314159265), encrypted);
            decryptor.decrypt(encrypted, plain);

            encryptor.encrypt_symmetric_save(encoder.encode(314159265), stream);
            encrypted.load(context, stream);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }


/////////////////////////////////////////////////////////// block 4 end


// block 5

    TEST(EncryptorTest, t52)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ASSERT_FALSE(ct.is_ntt_form());
        }
    }

    TEST(EncryptorTest, t53)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ASSERT_FALSE(ct.is_transparent());

        }
    }
    TEST(EncryptorTest, t54)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }

    TEST(EncryptorTest, t55)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            decryptor.decrypt(ct, pt);
            ASSERT_TRUE(pt.is_zero());

        }
    }


    TEST(EncryptorTest, t56)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {

            encryptor.encrypt_zero(next_parms, ct);
            ASSERT_FALSE(ct.is_ntt_form());
        }
    }

    TEST(EncryptorTest, t57)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {

            encryptor.encrypt_zero(next_parms, ct);
            ASSERT_FALSE(ct.is_transparent());
        }
    }


    TEST(EncryptorTest, t58)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {

            encryptor.encrypt_zero(next_parms, ct);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }

    TEST(EncryptorTest, t59)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {

            encryptor.encrypt_zero(next_parms, ct);
            ASSERT_EQ(ct.parms_id(), next_parms);
        }
    }

    TEST(EncryptorTest, t60)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {

            encryptor.encrypt_zero(next_parms, ct);
            decryptor.decrypt(ct, pt);
            ASSERT_TRUE(pt.is_zero());
        }
    }



    TEST(EncryptorTest, t61)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ASSERT_FALSE(ct.is_ntt_form());
        }
    }

    TEST(EncryptorTest, t62)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ASSERT_FALSE(ct.is_transparent());
        }
    }


    TEST(EncryptorTest, t63)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }


    TEST(EncryptorTest, t64)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            decryptor.decrypt(ct, pt);
            ASSERT_TRUE(pt.is_zero());
        }
    }


    TEST(EncryptorTest, t65)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(next_parms, ct);
            ASSERT_FALSE(ct.is_ntt_form());
        }
    }

    TEST(EncryptorTest, t66)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(next_parms, ct);
            ASSERT_FALSE(ct.is_transparent());
        }
    }

    TEST(EncryptorTest, t67)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(next_parms, ct);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }

    TEST(EncryptorTest, t68)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(next_parms, ct);
            ASSERT_EQ(ct.parms_id(), next_parms);
        }
    }

    TEST(EncryptorTest, t69)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(next_parms, ct);
            decryptor.decrypt(ct, pt);
            ASSERT_TRUE(pt.is_zero());
        }
    }

    TEST(EncryptorTest, t70)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ASSERT_FALSE(ct.is_ntt_form());
        }
    }

    TEST(EncryptorTest, t71)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ASSERT_FALSE(ct.is_transparent());
        }
    }

    TEST(EncryptorTest, t72)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }

    TEST(EncryptorTest, t73)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ASSERT_EQ(ct.parms_id(), next_parms);
        }
    }

    TEST(EncryptorTest, t74)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            decryptor.decrypt(ct, pt);
            ASSERT_TRUE(pt.is_zero());
        }
    }

/////////////////////////////////////////////////////////// block 5 end

// block 6

    TEST(EncryptorTest, t75)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ASSERT_FALSE(ct.is_ntt_form());
        }
    }

    TEST(EncryptorTest, t76)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ASSERT_FALSE(ct.is_transparent());
        }
    }


    TEST(EncryptorTest, t77)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }

    TEST(EncryptorTest, t78)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            decryptor.decrypt(ct, pt);
            ASSERT_TRUE(pt.is_zero());
        }
    }

    TEST(EncryptorTest, t79)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            decryptor.decrypt(ct, pt);
            encryptor.encrypt_zero(next_parms, ct);
            ASSERT_FALSE(ct.is_ntt_form());
        }
    }

    TEST(EncryptorTest, t80)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            decryptor.decrypt(ct, pt);
            encryptor.encrypt_zero(next_parms, ct);
            ASSERT_FALSE(ct.is_transparent());
        }
    }

    TEST(EncryptorTest, t81)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            decryptor.decrypt(ct, pt);
            encryptor.encrypt_zero(next_parms, ct);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }

    TEST(EncryptorTest, t82)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            decryptor.decrypt(ct, pt);
            encryptor.encrypt_zero(next_parms, ct);
            ASSERT_EQ(ct.parms_id(), next_parms);
        }
    }

    TEST(EncryptorTest, t83)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            decryptor.decrypt(ct, pt);
            encryptor.encrypt_zero(next_parms, ct);
            decryptor.decrypt(ct, pt);
            ASSERT_TRUE(pt.is_zero());
        }
    }

    TEST(EncryptorTest, t84)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            decryptor.decrypt(ct, pt);
            encryptor.encrypt_zero_symmetric(next_parms, ct);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }

    TEST(EncryptorTest, t85)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ASSERT_FALSE(ct.is_ntt_form());
        }
    }

    TEST(EncryptorTest, t86)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ASSERT_FALSE(ct.is_transparent());
        }
    }

    TEST(EncryptorTest, t87)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }

    TEST(EncryptorTest, t88)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            decryptor.decrypt(ct, pt);
            ASSERT_TRUE(pt.is_zero());
        }
    }

    TEST(EncryptorTest, t89)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            decryptor.decrypt(ct, pt);
            encryptor.encrypt_zero_symmetric(next_parms, ct);
            ASSERT_FALSE(ct.is_ntt_form());
        }
    }

    TEST(EncryptorTest, t90)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            decryptor.decrypt(ct, pt);
            encryptor.encrypt_zero_symmetric(next_parms, ct);
            ASSERT_FALSE(ct.is_transparent());
        }
    }

    TEST(EncryptorTest, t91)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            decryptor.decrypt(ct, pt);
            encryptor.encrypt_zero_symmetric(next_parms, ct);
            ASSERT_EQ(ct.parms_id(), next_parms);
        }
    }

    TEST(EncryptorTest, t92)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            decryptor.decrypt(ct, pt);
            encryptor.encrypt_zero_symmetric(next_parms, ct);
            decryptor.decrypt(ct, pt);
            ASSERT_TRUE(pt.is_zero());
        }
    }

    TEST(EncryptorTest, t93)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            ASSERT_FALSE(ct.is_ntt_form());
        }
    }

    TEST(EncryptorTest, t94)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            ASSERT_FALSE(ct.is_transparent());
        }
    }

    TEST(EncryptorTest, t95)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }

    TEST(EncryptorTest, t96)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            decryptor.decrypt(ct, pt);
            ASSERT_TRUE(pt.is_zero());
        }
    }


    TEST(EncryptorTest, t97)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            decryptor.decrypt(ct, pt);
            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ASSERT_FALSE(ct.is_ntt_form());
        }
    }


    TEST(EncryptorTest, t98)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            decryptor.decrypt(ct, pt);
            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ASSERT_FALSE(ct.is_transparent());
        }
    }


    TEST(EncryptorTest, t99)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            decryptor.decrypt(ct, pt);
            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }


    TEST(EncryptorTest, t100)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            decryptor.decrypt(ct, pt);
            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ASSERT_EQ(ct.parms_id(), next_parms);
        }
    }


    TEST(EncryptorTest, t101)
    {
        EncryptionParameters parms(scheme_type::BFV);
        SmallModulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            decryptor.decrypt(ct, pt);
            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            decryptor.decrypt(ct, pt);
            ASSERT_TRUE(pt.is_zero());
        }
    }

/////////////////////////////////////////////////////////////// block 6 end

    TEST(EncryptorTest, t102)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ASSERT_FALSE(ct.is_transparent());
        }
    }

    TEST(EncryptorTest, t103)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ASSERT_TRUE(ct.is_ntt_form());
        }
    }


    TEST(EncryptorTest, t104)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }


    TEST(EncryptorTest, t105)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            for (auto val : res)
            {
                ASSERT_NEAR(val.real(), 0.0, 0.01);
            }
        }
    }


    TEST(EncryptorTest, t106)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            for (auto val : res)
            {
                ASSERT_NEAR(val.imag(), 0.0, 0.01);
            }
        }
    }


    TEST(EncryptorTest, t107)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero(next_parms, ct);
            ASSERT_FALSE(ct.is_transparent());
        }
    }


    TEST(EncryptorTest, t108)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero(next_parms, ct);
            ASSERT_TRUE(ct.is_ntt_form());
        }
    }


    TEST(EncryptorTest, t109)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero(next_parms, ct);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }


    TEST(EncryptorTest, t110)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero(next_parms, ct);
            ct.scale() = std::pow(2.0, 20);
            ASSERT_EQ(ct.parms_id(), next_parms);
        }
    }


    TEST(EncryptorTest, t111)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero(next_parms, ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            ASSERT_EQ(pt.parms_id(), next_parms);
        }
    }


    TEST(EncryptorTest, t112)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero(next_parms, ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            for (auto val : res)
            {
                ASSERT_NEAR(val.real(), 0.0, 0.01);
            }
        }
    }


    TEST(EncryptorTest, t113)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            encryptor.encrypt_zero(next_parms, ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            for (auto val : res)
            {
                ASSERT_NEAR(val.imag(), 0.0, 0.01);
            }
        }
    }



    TEST(EncryptorTest, t114)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ASSERT_FALSE(ct.is_transparent());
        }
    }

    TEST(EncryptorTest, t115)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ASSERT_TRUE(ct.is_ntt_form());
        }
    }


    TEST(EncryptorTest, t116)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }


    TEST(EncryptorTest, t117)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            for (auto val : res)
            {
                ASSERT_NEAR(val.real(), 0.0, 0.01);
            }
        }
    }


    TEST(EncryptorTest, t118)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            for (auto val : res)
            {
                ASSERT_NEAR(val.imag(), 0.0, 0.01);
            }
        }
    }


    TEST(EncryptorTest, t119)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero_symmetric(next_parms, ct);
            ASSERT_FALSE(ct.is_transparent());
        }
    }


    TEST(EncryptorTest, t120)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero_symmetric(next_parms, ct);
            ASSERT_TRUE(ct.is_ntt_form());
        }
    }


    TEST(EncryptorTest, t121)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero_symmetric(next_parms, ct);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }


    TEST(EncryptorTest, t122)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero_symmetric(next_parms, ct);
            ct.scale() = std::pow(2.0, 20);
            ASSERT_EQ(ct.parms_id(), next_parms);
        }
    }


    TEST(EncryptorTest, t123)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero_symmetric(next_parms, ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            ASSERT_EQ(pt.parms_id(), next_parms);
        }
    }


    TEST(EncryptorTest, t124)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero_symmetric(next_parms, ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            for (auto val : res)
            {
                ASSERT_NEAR(val.real(), 0.0, 0.01);
            }
        }
    }


    TEST(EncryptorTest, t125)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            encryptor.encrypt_zero_symmetric(ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            encryptor.encrypt_zero_symmetric(next_parms, ct);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            for (auto val : res)
            {
                ASSERT_NEAR(val.imag(), 0.0, 0.01);
            }
        }
    }





    TEST(EncryptorTest, t126)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            ASSERT_TRUE(ct.is_ntt_form());
        }
    }

    TEST(EncryptorTest, t127)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }

    TEST(EncryptorTest, t128)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            for (auto val : res)
            {
                ASSERT_NEAR(val.real(), 0.0, 0.01);
            }
        }
    }

    TEST(EncryptorTest, t129)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            for (auto val : res)
            {
                ASSERT_NEAR(val.imag(), 0.0, 0.01);
            }

        }
    }

    TEST(EncryptorTest, t130)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ASSERT_FALSE(ct.is_transparent());
        }
    }

    TEST(EncryptorTest, t131)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ASSERT_TRUE(ct.is_ntt_form());
        }
    }

    TEST(EncryptorTest, t132)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }
    TEST(EncryptorTest, t133)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
        }
    }

    TEST(EncryptorTest, t134)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ct.scale() = std::pow(2.0, 20);
            ASSERT_EQ(ct.parms_id(), next_parms);

        }
    }

    TEST(EncryptorTest, t135)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            ASSERT_EQ(pt.parms_id(), next_parms);
        }
    }

    TEST(EncryptorTest, t136)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            for (auto val : res)
            {
                ASSERT_NEAR(val.real(), 0.0, 0.01);
            }
        }
    }

    TEST(EncryptorTest, t137)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        std::vector<std::complex<double>> res;
        parms_id_type next_parms = context->first_context_data()->next_context_data()->parms_id();
        {
            stringstream stream;
            encryptor.encrypt_zero_symmetric_save(stream);
            ct.load(context, stream);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);

            encryptor.encrypt_zero_symmetric_save(next_parms, stream);
            ct.load(context, stream);
            ct.scale() = std::pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            for (auto val : res)
            {
                ASSERT_NEAR(val.imag(), 0.0, 0.01);
            }
        }
    }





















    TEST(EncryptorTest, t138)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            //input consists of ones
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size, 1.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            encoder.encode(input, context->first_parms_id(), delta, plain);
            encryptor.encrypt(plain, encrypted);

            //check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EncryptorTest, t139)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            //input consists of ones
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size, 1.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            encoder.encode(input, context->first_parms_id(), delta, plain);
            encryptor.encrypt(plain, encrypted);

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);

            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
    }


    TEST(EncryptorTest, t140)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            //input consists of zeros
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size, 0.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            encoder.encode(input, context->first_parms_id(), delta, plain);
            encryptor.encrypt(plain, encrypted);

            //check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }



    TEST(EncryptorTest, t141)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            //input consists of zeros
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size, 0.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            encoder.encode(input, context->first_parms_id(), delta, plain);
            encryptor.encrypt(plain, encrypted);

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);

            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
    }

    TEST(EncryptorTest, t142)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // Input is a random mix of positive and negative integers
            size_t slot_size = 64;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size);
            std::vector<std::complex<double>> output(slot_size);

            srand(static_cast<unsigned>(time(NULL)));
            int input_bound = 1 << 30;
            const double delta = static_cast<double>(1ULL << 50);

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = pow(-1.0, rand() % 2) * static_cast<double>(rand() % input_bound);
                }

                encoder.encode(input, context->first_parms_id(), delta, plain);
                encryptor.encrypt(plain, encrypted);

                //check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
            }
        }
    }


    TEST(EncryptorTest, t143)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // Input is a random mix of positive and negative integers
            size_t slot_size = 64;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size);
            std::vector<std::complex<double>> output(slot_size);

            srand(static_cast<unsigned>(time(NULL)));
            int input_bound = 1 << 30;
            const double delta = static_cast<double>(1ULL << 50);

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = pow(-1.0, rand() % 2) * static_cast<double>(rand() % input_bound);
                }

                encoder.encode(input, context->first_parms_id(), delta, plain);
                encryptor.encrypt(plain, encrypted);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);

                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EncryptorTest, t144)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // Input is a random mix of positive and negative integers
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size);
            std::vector<std::complex<double>> output(slot_size);

            srand(static_cast<unsigned>(time(NULL)));
            int input_bound = 1 << 30;
            const double delta = static_cast<double>(1ULL << 60);

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = pow(-1.0, rand() % 2) * static_cast<double>(rand() % input_bound);
                }

                encoder.encode(input, context->first_parms_id(), delta, plain);
                encryptor.encrypt(plain, encrypted);

                //check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
            }
        }
    }


    TEST(EncryptorTest, t145)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // Input is a random mix of positive and negative integers
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size);
            std::vector<std::complex<double>> output(slot_size);

            srand(static_cast<unsigned>(time(NULL)));
            int input_bound = 1 << 30;
            const double delta = static_cast<double>(1ULL << 60);

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = pow(-1.0, rand() % 2) * static_cast<double>(rand() % input_bound);
                }

                encoder.encode(input, context->first_parms_id(), delta, plain);
                encryptor.encrypt(plain, encrypted);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plain, output);

                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }


    TEST(EncryptorTest, t146)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // Encrypt at lower level
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size, 1.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            auto first_context_data = context->first_context_data();
            ASSERT_NE(nullptr, first_context_data.get());
        }
    }



    TEST(EncryptorTest, t147)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // Encrypt at lower level
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size, 1.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            auto first_context_data = context->first_context_data();
            auto second_context_data = first_context_data->next_context_data();
            ASSERT_NE(nullptr, second_context_data.get());

        }
    }



    TEST(EncryptorTest, t148)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // Encrypt at lower level
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size, 1.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            auto first_context_data = context->first_context_data();
            auto second_context_data = first_context_data->next_context_data();
            auto second_parms_id = second_context_data->parms_id();

            encoder.encode(input, second_parms_id, delta, plain);
            encryptor.encrypt(plain, encrypted);

            // Check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == second_parms_id);
        }
    }



    TEST(EncryptorTest, t149)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // Encrypt at lower level
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            std::vector<std::complex<double>> input(slot_size, 1.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            auto first_context_data = context->first_context_data();
            auto second_context_data = first_context_data->next_context_data();
            auto second_parms_id = second_context_data->parms_id();

            encoder.encode(input, second_parms_id, delta, plain);
            encryptor.encrypt(plain, encrypted);

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);

            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
    }


    TEST(EncryptorTest, t150)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // Encrypt at lower level
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.secret_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;
            stringstream stream;

            std::vector<std::complex<double>> input(slot_size, 1.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            auto first_context_data = context->first_context_data();
            ASSERT_NE(nullptr, first_context_data.get());
        }
    }

    TEST(EncryptorTest, t151)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // Encrypt at lower level
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.secret_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;
            stringstream stream;

            std::vector<std::complex<double>> input(slot_size, 1.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            auto first_context_data = context->first_context_data();
            auto second_context_data = first_context_data->next_context_data();
            ASSERT_NE(nullptr, second_context_data.get());
        }
    }

    TEST(EncryptorTest, t152)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // Encrypt at lower level
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.secret_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;
            stringstream stream;

            std::vector<std::complex<double>> input(slot_size, 1.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            auto first_context_data = context->first_context_data();
            auto second_context_data = first_context_data->next_context_data();
            auto second_parms_id = second_context_data->parms_id();

            encoder.encode(input, second_parms_id, delta, plain);
            encryptor.encrypt_symmetric(plain, encrypted);
            // Check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == second_parms_id);

        }
    }

    TEST(EncryptorTest, t153)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // Encrypt at lower level
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.secret_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;
            stringstream stream;

            std::vector<std::complex<double>> input(slot_size, 1.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            auto first_context_data = context->first_context_data();
            auto second_context_data = first_context_data->next_context_data();
            auto second_parms_id = second_context_data->parms_id();

            encoder.encode(input, second_parms_id, delta, plain);
            encryptor.encrypt_symmetric(plain, encrypted);
            // Check correctness of encryption
            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
    }

    TEST(EncryptorTest, t154)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // Encrypt at lower level
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.secret_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;
            stringstream stream;

            std::vector<std::complex<double>> input(slot_size, 1.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            auto first_context_data = context->first_context_data();
            auto second_context_data = first_context_data->next_context_data();
            auto second_parms_id = second_context_data->parms_id();

            encoder.encode(input, second_parms_id, delta, plain);
            encryptor.encrypt_symmetric(plain, encrypted);
            // Check correctness of encryption
            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
            }

            encoder.encode(input, second_parms_id, delta, plain);
            encryptor.encrypt_symmetric_save(plain, stream);
            encrypted.load(context, stream);
            // Check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == second_parms_id);

        }
    }

    TEST(EncryptorTest, t155)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // Encrypt at lower level
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(2 * slot_size);
            parms.set_coeff_modulus(CoeffModulus::Create(2 * slot_size, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.secret_key());
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;
            stringstream stream;

            std::vector<std::complex<double>> input(slot_size, 1.0);
            std::vector<std::complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);

            auto first_context_data = context->first_context_data();
            auto second_context_data = first_context_data->next_context_data();
            auto second_parms_id = second_context_data->parms_id();

            encoder.encode(input, second_parms_id, delta, plain);
            encryptor.encrypt_symmetric(plain, encrypted);
            // Check correctness of encryption
            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
            }

            encoder.encode(input, second_parms_id, delta, plain);
            encryptor.encrypt_symmetric_save(plain, stream);
            encrypted.load(context, stream);
            // Check correctness of encryption
            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
    }
}



