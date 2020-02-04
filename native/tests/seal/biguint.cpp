
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/biguint.h"
#include "seal/util/defines.h"

using namespace seal;
using namespace std;

namespace SEALTest
{
    TEST(BigUnsignedInt, t0)
    {
        BigUInt uint;
        ASSERT_EQ(0, uint.bit_count());
    }

    TEST(BigUnsignedInt, t1)
    {
        BigUInt uint;
        ASSERT_TRUE(nullptr == uint.data());
    }

    TEST(BigUnsignedInt, t2)
    {
        BigUInt uint;
        ASSERT_EQ(0ULL, uint.byte_count());
    }

    TEST(BigUnsignedInt, t3)
    {
        BigUInt uint;
        ASSERT_EQ(0ULL, uint.byte_count());
    }

    TEST(BigUnsignedInt, t4)
    {
        BigUInt uint;
        ASSERT_EQ(0ULL, uint.uint64_count());
    }

    TEST(BigUnsignedInt, t5)
    {
        BigUInt uint;
        ASSERT_EQ(0, uint.significant_bit_count());
    }

    TEST(BigUnsignedInt, t6)
    {
        BigUInt uint;
        ASSERT_TRUE("0" == uint.to_string());
    }

    TEST(BigUnsignedInt, t7)
    {
        BigUInt uint;
        ASSERT_TRUE(uint.is_zero());

    }

    TEST(BigUnsignedInt, t8)
    {
        BigUInt uint;
        ASSERT_FALSE(uint.is_alias());

    }

    TEST(BigUnsignedInt, t9)
    {
        BigUInt uint;
        uint.set_zero();

        BigUInt uint2;
        ASSERT_TRUE(uint == uint2);
    }

    TEST(BigUnsignedInt, t10)
    {
        BigUInt uint;
        uint.set_zero();

        BigUInt uint2;
        ASSERT_FALSE(uint != uint2);
    }

    TEST(BigUnsignedInt, t11)
    {
        BigUInt uint;
        uint.set_zero();

        BigUInt uint2;

        uint.resize(1);
        ASSERT_EQ(1, uint.bit_count());
    }

    TEST(BigUnsignedInt, t12)
    {
        BigUInt uint;
        uint.set_zero();

        BigUInt uint2;

        uint.resize(1);
        ASSERT_TRUE(nullptr != uint.data());
    }

    TEST(BigUnsignedInt, t13)
    {
        BigUInt uint;
        uint.set_zero();

        BigUInt uint2;

        uint.resize(1);
        ASSERT_FALSE(uint.is_alias());
    }

    TEST(BigUnsignedInt, t14)
    {
        BigUInt uint;
        uint.set_zero();

        BigUInt uint2;

        uint.resize(1);

        uint.resize(0);
        ASSERT_EQ(0, uint.bit_count());
    }

    TEST(BigUnsignedInt, t15)
    {
        BigUInt uint;
        uint.set_zero();

        BigUInt uint2;

        uint.resize(1);

        uint.resize(0);
        ASSERT_TRUE(nullptr == uint.data());
    }

    TEST(BigUnsignedInt, t16)
    {
        BigUInt uint;
        uint.set_zero();
        BigUInt uint2;
        uint.resize(1);
        uint.resize(0);
        ASSERT_FALSE(uint.is_alias());
    }

    TEST(BigUnsignedInt, t17)
    {
        BigUInt uint(64);
        ASSERT_EQ(64, uint.bit_count());
    }

    TEST(BigUnsignedInt, t18)
    {
        BigUInt uint(64);
        ASSERT_TRUE(nullptr != uint.data());
    }

    TEST(BigUnsignedInt, t19)
    {
        BigUInt uint(64);
        ASSERT_EQ(8ULL, uint.byte_count());
    }

    TEST(BigUnsignedInt, t20)
    {
        BigUInt uint(64);
        ASSERT_EQ(1ULL, uint.uint64_count());
    }

    TEST(BigUnsignedInt, t21)
    {
        BigUInt uint(64);
        ASSERT_EQ(0, uint.significant_bit_count());
    }

    TEST(BigUnsignedInt, t22)
    {
        BigUInt uint(64);
        ASSERT_TRUE("0" == uint.to_string());
    }

    TEST(BigUnsignedInt, t23)
    {
        BigUInt uint(64);
        ASSERT_TRUE(uint.is_zero());
    }

    TEST(BigUnsignedInt, t24)
    {
        BigUInt uint(64);
        ASSERT_EQ(static_cast<uint64_t>(0), *uint.data());
    }

    TEST(BigUnsignedInt, t25)
    {
        BigUInt uint(64);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[0]);
    }

    TEST(BigUnsignedInt, t26)
    {
        BigUInt uint(64);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[1]);
    }

    TEST(BigUnsignedInt, t27)
    {
        BigUInt uint(64);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[2]);
    }

    TEST(BigUnsignedInt, t28)
    {
        BigUInt uint(64);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[3]);
    }

    TEST(BigUnsignedInt, t29)
    {
        BigUInt uint(64);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[4]);
    }

    TEST(BigUnsignedInt, t30)
    {
        BigUInt uint(64);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[5]);
    }

    TEST(BigUnsignedInt, t31)
    {
        BigUInt uint(64);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[6]);
    }

    TEST(BigUnsignedInt, t32)
    {
        BigUInt uint(64);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[7]);
    }

    TEST(BigUnsignedInt, t33)
    {
        BigUInt uint(64);
        uint = "1";
        ASSERT_EQ(1, uint.significant_bit_count());
    }

    TEST(BigUnsignedInt, t34)
    {
        BigUInt uint(64);
        uint = "1";
        ASSERT_TRUE("1" == uint.to_string());
    }

    TEST(BigUnsignedInt, t35)
    {
        BigUInt uint(64);
        uint = "1";
        ASSERT_FALSE(uint.is_zero());
    }

    TEST(BigUnsignedInt, t36)
    {
        BigUInt uint(64);
        uint = "1";
        ASSERT_EQ(1ULL, *uint.data());
    }

    TEST(BigUnsignedInt, t37)
    {
        BigUInt uint(64);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(1) == uint[0]);
    }

    TEST(BigUnsignedInt, t38)
    {
        BigUInt uint(64);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[1]);
    }

    TEST(BigUnsignedInt, t39)
    {
        BigUInt uint(64);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[2]);
    }

    TEST(BigUnsignedInt, t40)
    {
        BigUInt uint(64);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[3]);
    }

    TEST(BigUnsignedInt, t41)
    {
        BigUInt uint(64);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[4]);
    }

    TEST(BigUnsignedInt, t42)
    {
        BigUInt uint(64);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[5]);
    }

    TEST(BigUnsignedInt, t43)
    {
        BigUInt uint(64);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[6]);
    }

    TEST(BigUnsignedInt, t44)
    {
        BigUInt uint(64);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[7]);
    }

    TEST(BigUnsignedInt, t45)
    {
        BigUInt uint(64);
        uint = "1";
        uint.set_zero();
        ASSERT_TRUE(uint.is_zero());
    }

    TEST(BigUnsignedInt, t46)
    {
        BigUInt uint(64);
        uint = "1";
        uint.set_zero();
        ASSERT_EQ(static_cast<uint64_t>(0), *uint.data());
    }




    TEST(BigUnsignedInt, t47)
    {
        BigUInt uint(64);
        uint = "7FFFFFFFFFFFFFFF";
        ASSERT_EQ(63, uint.significant_bit_count());
    }

    TEST(BigUnsignedInt, t48)
    {
        BigUInt uint(64);
        uint = "7FFFFFFFFFFFFFFF";
        ASSERT_TRUE("7FFFFFFFFFFFFFFF" == uint.to_string());
    }

    TEST(BigUnsignedInt, t49)
    {
        BigUInt uint(64);
        uint = "7FFFFFFFFFFFFFFF";
        ASSERT_EQ(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFF), *uint.data());
    }

    TEST(BigUnsignedInt, t50)
    {
        BigUInt uint(64);
        uint = "7FFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[0]);
    }

    TEST(BigUnsignedInt, t51)
    {
        BigUInt uint(64);
        uint = "7FFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[1]);
    }

    TEST(BigUnsignedInt, t52)
    {
        BigUInt uint(64);
        uint = "7FFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[2]);
    }

    TEST(BigUnsignedInt, t53)
    {
        BigUInt uint(64);
        uint = "7FFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[3]);
    }

    TEST(BigUnsignedInt, t54)
    {
        BigUInt uint(64);
        uint = "7FFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[4]);
    }

    TEST(BigUnsignedInt, t55)
    {
        BigUInt uint(64);
        uint = "7FFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[5]);
    }

    TEST(BigUnsignedInt, t56)
    {
        BigUInt uint(64);
        uint = "7FFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[6]);
    }

    TEST(BigUnsignedInt, t57)
    {
        BigUInt uint(64);
        uint = "7FFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0x7F) == uint[7]);
    }

    TEST(BigUnsignedInt, t58)
    {
        BigUInt uint(64);
        uint = "7FFFFFFFFFFFFFFF";
        ASSERT_FALSE(uint.is_zero());
    }




    TEST(BigUnsignedInt, t59)
    {
        BigUInt uint(64);
        uint = "FFFFFFFFFFFFFFFF";
        ASSERT_EQ(64, uint.significant_bit_count());
    }

    TEST(BigUnsignedInt, t60)
    {
        BigUInt uint(64);
        uint = "FFFFFFFFFFFFFFFF";
        ASSERT_TRUE("FFFFFFFFFFFFFFFF" == uint.to_string());
    }

    TEST(BigUnsignedInt, t61)
    {
        BigUInt uint(64);
        uint = "FFFFFFFFFFFFFFFF";
        ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), *uint.data());
    }

    TEST(BigUnsignedInt, t62)
    {
        BigUInt uint(64);
        uint = "FFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[0]);
    }

    TEST(BigUnsignedInt, t63)
    {
        BigUInt uint(64);
        uint = "FFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[1]);
    }

    TEST(BigUnsignedInt, t64)
    {
        BigUInt uint(64);
        uint = "FFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[2]);
    }

    TEST(BigUnsignedInt, t65)
    {
        BigUInt uint(64);
        uint = "FFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[3]);
    }

    TEST(BigUnsignedInt, t66)
    {
        BigUInt uint(64);
        uint = "FFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[4]);
    }

    TEST(BigUnsignedInt, t67)
    {
        BigUInt uint(64);
        uint = "FFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[5]);
    }

    TEST(BigUnsignedInt, t68)
    {
        BigUInt uint(64);
        uint = "FFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[6]);
    }

    TEST(BigUnsignedInt, t69)
    {
        BigUInt uint(64);
        uint = "FFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[7]);
    }

    TEST(BigUnsignedInt, t70)
    {
        BigUInt uint(64);
        uint = "FFFFFFFFFFFFFFFF";
        ASSERT_FALSE(uint.is_zero());
    }

    TEST(BigUnsignedInt, t71)
    {
        BigUInt uint(64);
        uint = 0x8001;
        ASSERT_EQ(16, uint.significant_bit_count());
    }

    TEST(BigUnsignedInt, t72)
    {
        BigUInt uint(64);
        uint = 0x8001;
        ASSERT_TRUE("8001" == uint.to_string());
    }

    TEST(BigUnsignedInt, t73)
    {
        BigUInt uint(64);
        uint = 0x8001;
        ASSERT_EQ(static_cast<uint64_t>(0x8001), *uint.data());
    }

    TEST(BigUnsignedInt, t74)
    {
        BigUInt uint(64);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x01) == uint[0]);
    }

    TEST(BigUnsignedInt, t75)
    {
        BigUInt uint(64);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x80) == uint[1]);
    }

    TEST(BigUnsignedInt, t76)
    {
        BigUInt uint(64);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[2]);
    }

    TEST(BigUnsignedInt, t77)
    {
        BigUInt uint(64);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[3]);
    }

    TEST(BigUnsignedInt, t78)
    {
        BigUInt uint(64);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[4]);
    }

    TEST(BigUnsignedInt, t79)
    {
        BigUInt uint(64);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[5]);

    }

    TEST(BigUnsignedInt, t80)
    {
        BigUInt uint(64);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[6]);
    }

    TEST(BigUnsignedInt, t81)
    {
        BigUInt uint(64);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[7]);
    }

    TEST(BigUnsignedInt, t82)
    {
        BigUInt uint(99);
        ASSERT_EQ(99, uint.bit_count());
    }

    TEST(BigUnsignedInt, t83)
    {
        BigUInt uint(99);
        ASSERT_TRUE(nullptr != uint.data());
    }

    TEST(BigUnsignedInt, t84)
    {
        BigUInt uint(99);
        ASSERT_EQ(13ULL, uint.byte_count());
    }

    TEST(BigUnsignedInt, t85)
    {
        BigUInt uint(99);
        ASSERT_EQ(2ULL, uint.uint64_count());
    }

    TEST(BigUnsignedInt, t86)
    {
        BigUInt uint(99);
        ASSERT_EQ(0, uint.significant_bit_count());
    }

    TEST(BigUnsignedInt, t87)
    {
        BigUInt uint(99);
        ASSERT_TRUE("0" == uint.to_string());
    }

    TEST(BigUnsignedInt, t88)
    {
        BigUInt uint(99);
        ASSERT_TRUE(uint.is_zero());
    }

    TEST(BigUnsignedInt, t89)
    {
        BigUInt uint(99);
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[0]);
    }

    TEST(BigUnsignedInt, t90)
    {
        BigUInt uint(99);
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[1]);
    }

    TEST(BigUnsignedInt, t91)
    {
        BigUInt uint(99);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[0]);
    }

    TEST(BigUnsignedInt, t92)
    {
        BigUInt uint(99);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[1]);
    }

    TEST(BigUnsignedInt, t93)
    {
        BigUInt uint(99);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[2]);
    }

    TEST(BigUnsignedInt, t94)
    {
        BigUInt uint(99);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[3]);
    }

    TEST(BigUnsignedInt, t95)
    {
        BigUInt uint(99);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[4]);
    }

    TEST(BigUnsignedInt, t96)
    {
        BigUInt uint(99);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[5]);
    }

    TEST(BigUnsignedInt, t97)
    {
        BigUInt uint(99);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[6]);
    }

    TEST(BigUnsignedInt, t98)
    {
        BigUInt uint(99);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[7]);
    }

    TEST(BigUnsignedInt, t99)
    {
        BigUInt uint(99);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[8]);
    }

    TEST(BigUnsignedInt, t100)
    {
        BigUInt uint(99);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[9]);
    }

    TEST(BigUnsignedInt, t101)
    {
        BigUInt uint(99);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[10]);
    }

    TEST(BigUnsignedInt, t102)
    {
        BigUInt uint(99);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[11]);
    }

    TEST(BigUnsignedInt, t103)
    {
        BigUInt uint(99);
        ASSERT_TRUE(SEAL_BYTE(0) == uint[12]);
    }

    TEST(BigUnsignedInt, t104)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_EQ(1, uint.significant_bit_count());
    }

    TEST(BigUnsignedInt, t105)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_TRUE("1" == uint.to_string());
    }

    TEST(BigUnsignedInt, t106)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_FALSE(uint.is_zero());
    }

    TEST(BigUnsignedInt, t107)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_FALSE(uint.is_zero());
    }

    TEST(BigUnsignedInt, t108)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_EQ(1ULL, uint.data()[0]);
    }

    TEST(BigUnsignedInt, t109)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[1]);
    }

    TEST(BigUnsignedInt, t110)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(1) == uint[0]);
    }

    TEST(BigUnsignedInt, t111)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[1]);
    }

    TEST(BigUnsignedInt, t112)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[2]);
    }

    TEST(BigUnsignedInt, t113)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[3]);
    }

    TEST(BigUnsignedInt, t114)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[4]);
    }

    TEST(BigUnsignedInt, t115)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[5]);
    }

    TEST(BigUnsignedInt, t116)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[6]);
    }

    TEST(BigUnsignedInt, t117)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[7]);
    }

    TEST(BigUnsignedInt, t118)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[8]);
    }

    TEST(BigUnsignedInt, t119)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[9]);
    }

    TEST(BigUnsignedInt, t120)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[10]);
    }

    TEST(BigUnsignedInt, t121)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[11]);
    }

    TEST(BigUnsignedInt, t122)
    {
        BigUInt uint(99);
        uint = "1";
        ASSERT_TRUE(SEAL_BYTE(0) == uint[12]);
    }

    TEST(BigUnsignedInt, t123)
    {
        BigUInt uint(99);
        uint = "1";
        uint.set_zero();
        ASSERT_TRUE(uint.is_zero());
    }

    TEST(BigUnsignedInt, t124)
    {
        BigUInt uint(99);
        uint = "1";
        uint.set_zero();
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[1]);
    }

    TEST(BigUnsignedInt, t125)
    {
        BigUInt uint(99);
        uint = "1";
        uint.set_zero();
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[1]);
    }

    TEST(BigUnsignedInt, t126)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_EQ(99, uint.significant_bit_count());
    }

    TEST(BigUnsignedInt, t127)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_TRUE("7FFFFFFFFFFFFFFFFFFFFFFFF" == uint.to_string());
    }

    TEST(BigUnsignedInt, t128)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), uint.data()[0]);
    }

    TEST(BigUnsignedInt, t129)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_EQ(static_cast<uint64_t>(0x7FFFFFFFF), uint.data()[1]);
    }

    TEST(BigUnsignedInt, t130)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[0]);
    }

    TEST(BigUnsignedInt, t131)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[1]);
    }

    TEST(BigUnsignedInt, t132)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[2]);
    }

    TEST(BigUnsignedInt, t133)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[3]);
    }

    TEST(BigUnsignedInt, t134)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[4]);
    }

    TEST(BigUnsignedInt, t135)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[5]);
    }

    TEST(BigUnsignedInt, t136)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[6]);
    }

    TEST(BigUnsignedInt, t137)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[7]);
    }

    TEST(BigUnsignedInt, t138)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[8]);
    }

    TEST(BigUnsignedInt, t139)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[9]);
    }

    TEST(BigUnsignedInt, t140)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[10]);
    }

    TEST(BigUnsignedInt, t141)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0xFF) == uint[11]);
    }

    TEST(BigUnsignedInt, t142)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_TRUE(SEAL_BYTE(0x07) == uint[12]);
    }

    TEST(BigUnsignedInt, t143)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        ASSERT_FALSE(uint.is_zero());
    }

    TEST(BigUnsignedInt, t144)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        uint.set_zero();
        ASSERT_TRUE(uint.is_zero());
    }

    TEST(BigUnsignedInt, t145)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        uint.set_zero();
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[0]);
    }

    TEST(BigUnsignedInt, t146)
    {
        BigUInt uint(99);
        uint = "7FFFFFFFFFFFFFFFFFFFFFFFF";
        uint.set_zero();
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[1]);
    }

    TEST(BigUnsignedInt, t147)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_EQ(99, uint.significant_bit_count());
    }

    TEST(BigUnsignedInt, t148)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_TRUE("4000000000000000000000000" == uint.to_string());
    }

    TEST(BigUnsignedInt, t149)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_EQ(static_cast<uint64_t>(0x0000000000000000), uint.data()[0]);
    }

    TEST(BigUnsignedInt, t150)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_EQ(static_cast<uint64_t>(0x400000000), uint.data()[1]);
    }

    TEST(BigUnsignedInt, t151)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[0]);
    }

    TEST(BigUnsignedInt, t152)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[1]);
    }

    TEST(BigUnsignedInt, t153)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[2]);
    }

    TEST(BigUnsignedInt, t154)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[3]);
    }

    TEST(BigUnsignedInt, t155)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[4]);
    }

    TEST(BigUnsignedInt, t156)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[5]);
    }

    TEST(BigUnsignedInt, t157)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[6]);
    }

    TEST(BigUnsignedInt, t158)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[7]);
    }

    TEST(BigUnsignedInt, t159)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[8]);
    }

    TEST(BigUnsignedInt, t160)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[9]);
    }

    TEST(BigUnsignedInt, t161)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[10]);
    }

    TEST(BigUnsignedInt, t162)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[11]);
    }

    TEST(BigUnsignedInt, t163)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_TRUE(SEAL_BYTE(0x04) == uint[12]);
    }

    TEST(BigUnsignedInt, t164)
    {
        BigUInt uint(99);
        uint = "4000000000000000000000000";
        ASSERT_FALSE(uint.is_zero());
    }

    TEST(BigUnsignedInt, t165)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_EQ(16, uint.significant_bit_count());
    }

    TEST(BigUnsignedInt, t166)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_TRUE("8001" == uint.to_string());
    }

    TEST(BigUnsignedInt, t167)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_EQ(static_cast<uint64_t>(0x8001), uint.data()[0]);
    }

    TEST(BigUnsignedInt, t168)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[1]);
    }

    TEST(BigUnsignedInt, t169)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x01) == uint[0]);
    }

    TEST(BigUnsignedInt, t170)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x80) == uint[1]);
    }

    TEST(BigUnsignedInt, t171)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[2]);
    }

    TEST(BigUnsignedInt, t172)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[3]);
    }

    TEST(BigUnsignedInt, t173)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[4]);
    }

    TEST(BigUnsignedInt, t174)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[5]);
    }

    TEST(BigUnsignedInt, t175)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[6]);
    }

    TEST(BigUnsignedInt, t176)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[7]);
    }

    TEST(BigUnsignedInt, t177)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[8]);
    }

    TEST(BigUnsignedInt, t178)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[9]);
    }

    TEST(BigUnsignedInt, t179)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[10]);
    }

    TEST(BigUnsignedInt, t180)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[11]);
    }

    TEST(BigUnsignedInt, t181)
    {
        BigUInt uint(99);
        uint = 0x8001;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[12]);
    }

    TEST(BigUnsignedInt, t182)
    {
        BigUInt uint(99);
        BigUInt uint2("123");
        ASSERT_FALSE(uint == uint2);
    }

    TEST(BigUnsignedInt, t183)
    {
        BigUInt uint2("123");
        BigUInt uint(99);
        ASSERT_FALSE(uint2 == uint);
    }

    TEST(BigUnsignedInt, t184)
    {
        BigUInt uint2("123");
        BigUInt uint(99);
        ASSERT_TRUE(uint != uint2);
    }

    TEST(BigUnsignedInt, t185)
    {
        BigUInt uint2("123");
        BigUInt uint(99);
        ASSERT_TRUE(uint2 != uint);
    }

    TEST(BigUnsignedInt, t186)
    {
        BigUInt uint2("123");
        BigUInt uint("123");
        uint = uint2;
        ASSERT_TRUE(uint == uint2);
    }

    TEST(BigUnsignedInt, t187)
    {
        BigUInt uint2("123");
        BigUInt uint("123");
        uint = uint2;
        ASSERT_FALSE(uint != uint2);
    }

    TEST(BigUnsignedInt, t188)
    {
        BigUInt uint2("123");
        BigUInt uint("123");
        uint = uint2;
        ASSERT_EQ(9, uint.significant_bit_count());
    }

    TEST(BigUnsignedInt, t189)
    {
        BigUInt uint2("123");
        BigUInt uint("123");
        uint = uint2;
        ASSERT_TRUE("123" == uint.to_string());
    }

    TEST(BigUnsignedInt, t190)
    {
        BigUInt uint2("123");
        BigUInt uint("123");
        uint = uint2;
        ASSERT_EQ(static_cast<uint64_t>(0x123), uint.data()[0]);
    }

    TEST(BigUnsignedInt, t191)
    {
        BigUInt uint2("123");
        BigUInt uint("123");
        uint = uint2;
        ASSERT_EQ(static_cast<uint64_t>(0), uint.data()[1]);
    }

    TEST(BigUnsignedInt, t192)
    {
        BigUInt uint2("123");
        BigUInt uint("123");
        uint = uint2;
        ASSERT_TRUE(SEAL_BYTE(0x23) == uint[0]);
    }

    TEST(BigUnsignedInt, t193)
    {
        BigUInt uint2("123");
        BigUInt uint("123");
        uint = uint2;
        ASSERT_TRUE(SEAL_BYTE(0x01) == uint[1]);
    }

    TEST(BigUnsignedInt, t194)
    {
        BigUInt uint2 = 0x8001;
        BigUInt uint = 0x8001;
        uint = uint2;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[2]);
    }

    TEST(BigUnsignedInt, t195)
    {
        BigUInt uint2 = 0x8001;
        BigUInt uint = 0x8001;
        uint = uint2;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[3]);
    }

    TEST(BigUnsignedInt, t196)
    {
        BigUInt uint2 = 0x8001;
        BigUInt uint = 0x8001;
        uint = uint2;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[4]);
    }

    TEST(BigUnsignedInt, t197)
    {
        BigUInt uint2 = 0x8001;
        BigUInt uint = 0x8001;
        uint = uint2;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[5]);
    }

    TEST(BigUnsignedInt, t198)
    {
        BigUInt uint2 = 0x8001;
        BigUInt uint = 0x8001;
        uint = uint2;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[6]);
    }

    TEST(BigUnsignedInt, t199)
    {
        BigUInt uint2 = 0x8001;
        BigUInt uint = 0x8001;
        uint = uint2;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[7]);
    }

    TEST(BigUnsignedInt, t200)
    {
        BigUInt uint2 = 0x8001;
        BigUInt uint = 0x8001;
        uint = uint2;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[8]);
    }

    TEST(BigUnsignedInt, t201)
    {
        BigUInt uint2 = 0x8001;
        BigUInt uint = 0x8001;
        uint = uint2;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[9]);
    }

    TEST(BigUnsignedInt, t202)
    {
        BigUInt uint2 = 0x8001;
        BigUInt uint = 0x8001;
        uint = uint2;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[10]);
    }

    TEST(BigUnsignedInt, t203)
    {
        BigUInt uint2 = 0x8001;
        BigUInt uint = 0x8001;
        uint = uint2;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[11]);
    }

    TEST(BigUnsignedInt, t204)
    {
        BigUInt uint2 = 0x8001;
        BigUInt uint = 0x8001;
        uint = uint2;
        ASSERT_TRUE(SEAL_BYTE(0x00) == uint[12]);
    }

    TEST(BigUnsignedInt, t205)
    {
        BigUInt uint("123");
        uint.resize(8);
        ASSERT_EQ(8, uint.bit_count());
    }

    TEST(BigUnsignedInt, t206)
    {
        BigUInt uint("123");
        uint.resize(8);
        ASSERT_EQ(1ULL, uint.uint64_count());
    }

    TEST(BigUnsignedInt, t207)
    {
        BigUInt uint("123");
        uint.resize(8);
        ASSERT_TRUE("23" == uint.to_string());
    }

    TEST(BigUnsignedInt, t208)
    {
        BigUInt uint("123");
        uint.resize(8);

        uint.resize(100);
        ASSERT_EQ(100, uint.bit_count());
    }

    TEST(BigUnsignedInt, t209)
    {
        BigUInt uint("123");
        uint.resize(8);

        uint.resize(100);
        ASSERT_EQ(2ULL, uint.uint64_count());
    }

    TEST(BigUnsignedInt, t210)
    {
        BigUInt uint("123");
        uint.resize(8);

        uint.resize(100);
        ASSERT_TRUE("23" == uint.to_string());
    }

    TEST(BigUnsignedInt, t211)
    {
        BigUInt uint("123");
        uint.resize(8);

        uint.resize(100);

        uint.resize(0);
        ASSERT_EQ(0, uint.bit_count());
    }

    TEST(BigUnsignedInt, t212)
    {
        BigUInt uint("123");
        uint.resize(8);
        uint.resize(100);
        uint.resize(0);
        ASSERT_EQ(0ULL, uint.uint64_count());
    }

    TEST(BigUnsignedInt, t213)
    {
        BigUInt uint("123");
        uint.resize(8);
        uint.resize(100);
        uint.resize(0);
        ASSERT_TRUE(nullptr == uint.data());
    }

    TEST(BigUnsignedInt, t214)
    {
        stringstream stream;

        BigUInt value;
        BigUInt value2("100");
        value.save(stream);
        value2.load(stream);
        ASSERT_TRUE(value == value2);
    }

    TEST(BigUnsignedInt, t215)
    {
        stringstream stream;

        BigUInt value;
        BigUInt value2("100");
        value.save(stream);
        value2.load(stream);

        value = "123";
        value.save(stream);
        value2.load(stream);
        ASSERT_TRUE(value == value2);
    }

    TEST(BigUnsignedInt, t216)
    {
        stringstream stream;

        BigUInt value;
        BigUInt value2("100");
        value.save(stream);
        value2.load(stream);

        value = "123";
        value.save(stream);
        value2.load(stream);

        value = "FFFFFFFFFFFFFFFFFFFFFFFFFF";
        value.save(stream);
        value2.load(stream);
        ASSERT_TRUE(value == value2);
    }

    TEST(BigUnsignedInt, t217)
    {
        stringstream stream;

        BigUInt value;
        BigUInt value2("100");
        value.save(stream);
        value2.load(stream);

        value = "123";
        value.save(stream);
        value2.load(stream);

        value = "FFFFFFFFFFFFFFFFFFFFFFFFFF";
        value.save(stream);
        value2.load(stream);

        value = "0";
        value.save(stream);
        value2.load(stream);
        ASSERT_TRUE(value == value2);
    }


    TEST(BigUnsignedInt, t218)
    {
        BigUInt original(123);
        original = 56789;

        BigUInt target;

        original.duplicate_to(target);
        ASSERT_EQ(target.bit_count(), original.bit_count());
    }

    TEST(BigUnsignedInt, t219)
    {
        BigUInt original(123);
        original = 56789;

        BigUInt target;

        original.duplicate_to(target);
        ASSERT_TRUE(target == original);
    }

    TEST(BigUnsignedInt, t220)
    {
        BigUInt original(123);
        original = 56789;

        BigUInt target;

        target.duplicate_from(original);
        ASSERT_EQ(target.bit_count(), original.bit_count());
    }

    TEST(BigUnsignedInt, t221)
    {
        BigUInt original(123);
        original = 56789;

        BigUInt target;

        target.duplicate_from(original);
        ASSERT_TRUE(target == original);
    }


    TEST(BigUnsignedInt, t222)
    {
        {
            BigUInt p1("123");
            BigUInt p2("456");
            BigUInt p3;

            p1.operator =(p2);
            p3.operator =(p1);
            ASSERT_TRUE(p1 == p2);
        }
    }
  
      TEST(BigUnsignedInt, t223)
    {
        {
            BigUInt p1("123");
            BigUInt p2("456");
            BigUInt p3;

            p1.operator =(p2);
            p3.operator =(p1);
            ASSERT_TRUE(p3 == p1);
        }
    }

    TEST(BigUnsignedInt, t224)
    {
        {
            BigUInt p1("123");
            BigUInt p2("456");
            BigUInt p3;
            BigUInt p4(p2);

            p1.operator =(move(p2));
            p3.operator =(move(p1));
            ASSERT_TRUE(p3 == p4);
        }
    }

    TEST(BigUnsignedInt, t225)
    {
        {
            BigUInt p1("123");
            BigUInt p2("456");
            BigUInt p3;
            BigUInt p4(p2);

            p1.operator =(move(p2));
            p3.operator =(move(p1));
            ASSERT_TRUE(p1 == p2);
        }
    }

    TEST(BigUnsignedInt, t226)
    {
        {
            BigUInt p1("123");
            BigUInt p2("456");
            BigUInt p3;
            BigUInt p4(p2);

            p1.operator =(move(p2));
            p3.operator =(move(p1));
            ASSERT_TRUE(p3 == p1);
        }
    }

    TEST(BigUnsignedInt, t227)
    { 
        {
            uint64_t p1_anchor = 123;
            uint64_t p2_anchor = 456;
            BigUInt p1(64, &p1_anchor);
            BigUInt p2(64, &p2_anchor);
            BigUInt p3;

            p1.operator =(p2);
            p3.operator =(p1);
            ASSERT_TRUE(p1 == p2);
        }
    }

    TEST(BigUnsignedInt, t228)
    { 
        {
            uint64_t p1_anchor = 123;
            uint64_t p2_anchor = 456;
            BigUInt p1(64, &p1_anchor);
            BigUInt p2(64, &p2_anchor);
            BigUInt p3;

            p1.operator =(p2);
            p3.operator =(p1);
            ASSERT_TRUE(p1 == p2);
        }
    }

    TEST(BigUnsignedInt, t229)
    {
        {
            uint64_t p1_anchor = 123;
            uint64_t p2_anchor = 456;
            BigUInt p1(64, &p1_anchor);
            BigUInt p2(64, &p2_anchor);
            BigUInt p3;
            BigUInt p4(p2);

            p1.operator =(move(p2));
            p3.operator =(move(p1));
            ASSERT_TRUE(p3 == p4);
        }
    }

    TEST(BigUnsignedInt, t230)
    {
        {
            uint64_t p1_anchor = 123;
            uint64_t p2_anchor = 456;
            BigUInt p1(64, &p1_anchor);
            BigUInt p2(64, &p2_anchor);
            BigUInt p3;
            BigUInt p4(p2);

            p1.operator =(move(p2));
            p3.operator =(move(p1));
            ASSERT_TRUE(p2 == 456);
        }
    }


    TEST(BigUnsignedInt, t231)
    {
        {
            uint64_t p1_anchor = 123;
            uint64_t p2_anchor = 456;
            BigUInt p1(64, &p1_anchor);
            BigUInt p2(64, &p2_anchor);
            BigUInt p3;
            BigUInt p4(p2);

            p1.operator =(move(p2));
            p3.operator =(move(p1));
            ASSERT_TRUE(p1 == 456);
        }
    }


    TEST(BigUnsignedInt, t232)
    {
        {
            uint64_t p1_anchor = 123;
            uint64_t p2_anchor = 456;
            BigUInt p1(64, &p1_anchor);
            BigUInt p2(64, &p2_anchor);
            BigUInt p3;
            BigUInt p4(p2);

            p1.operator =(move(p2));
            p3.operator =(move(p1));
            ASSERT_TRUE(p3 == 456);
        }
    }
}

