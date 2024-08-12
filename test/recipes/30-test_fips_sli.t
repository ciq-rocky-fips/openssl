#!/usr/bin/env perl
use OpenSSL::Test::Simple;

simple_test("test_fips_sli", "fips_slitest", "fips_sli");
