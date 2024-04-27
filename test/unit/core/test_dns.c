#include "test_dns.h"

#include "lwip/dns.h"
#include "lwip/netdb.h"

/* Setups/teardown functions */

static void
dns_setup(void)
{
}

static void
dns_teardown(void)
{
}

/* Test functions */

START_TEST(test_dns_set_get_server)
{
  int n;
  LWIP_UNUSED_ARG(_i);

  for (n = 0; n < 256; n++) {
    u8_t i = (u8_t)n;
    ip_addr_t server;
    /* Should return a zeroed address for any index */
    fail_unless(dns_getserver(i));
    fail_unless(ip_addr_isany(dns_getserver(i)));

    /* Should accept setting address for any index, and ignore if out of range */
    IP_ADDR4(&server, 10, 0, 0, i);
    dns_setserver(i, &server);
    fail_unless(dns_getserver(i));
    if (i < DNS_MAX_SERVERS) {
      fail_unless(ip_addr_eq(dns_getserver(i), &server) == 1);
    } else {
      fail_unless(ip_addr_isany(dns_getserver(i)));
    }
  }
}
END_TEST

#if LWIP_IPV4 && LWIP_IPV6  /* allow to build the unit tests without IPv6 support */

/* Test cases from RFC 6724 Examples 10.2, https://datatracker.ietf.org/doc/html/rfc6724#section-10.2 */

START_TEST(sort_dest_ex1_prefer_matching_scope_1)
{
  /* Candidate Source Addresses: 2001:db8:1::2 or fe80::1 or 169.254.13.78 */
  ip_addr_t cand_source_addr_value[] = {
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x2),
    IPADDR6_INIT_HOST(0xfe800000, 0x0, 0x0, 0x1),
    /* IPADDR6_INIT_HOST(0x0, 0x0, 0xFFFF, 0xA9FE0D4E) */
    IPADDR4_INIT_BYTES(169, 254, 13, 78)
  };
  ip_addr_t *cand_source_addr[] =
    { &cand_source_addr_value[0], &cand_source_addr_value[1], &cand_source_addr_value[2] };
  /* Destination Address List: 2001:db8:1::1 or 198.51.100.121 */
  ip_addr_t dest_addr[] = {
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x1),
    /* IPADDR6_INIT_HOST(0x0, 0x0, 0xFFFF, 0xC6336479) */
    IPADDR4_INIT_BYTES(198, 51, 100, 121)
  };
  ip_addr_t rev_dest_addr[] = { dest_addr[1], dest_addr[0] };
  /* Result: 2001:db8:1::1 (src 2001:db8:1::2) then 198.51.100.121 (src 169.254.13.78) (prefer matching scope) */
  const ip_addr_t addr_expected[] = {
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x1),
    IPADDR4_INIT_BYTES(198, 51, 100, 121)
  };

  lwip_sortdestinationaddresses(dest_addr, 2, cand_source_addr, 3);

  fail_unless(memcmp(&dest_addr[0], &addr_expected[0], 16) == 0);
  fail_unless(memcmp(&dest_addr[1], &addr_expected[1], 16) == 0);

  lwip_sortdestinationaddresses(rev_dest_addr, 2, cand_source_addr, 3);

  fail_unless(memcmp(&rev_dest_addr[0], &addr_expected[0], 16) == 0);
  fail_unless(memcmp(&rev_dest_addr[1], &addr_expected[1], 16) == 0);
}
END_TEST

START_TEST(sort_dest_ex2_prefer_matching_scope_2)
{
  /* Candidate Source Addresses: fe80::1 or 198.51.100.117 */
  ip_addr_t cand_source_addr_value[] = {
    IPADDR6_INIT_HOST(0xfe800000, 0x0, 0x0, 0x1),
    IPADDR4_INIT_BYTES(198, 51, 100, 117)
  };
  ip_addr_t *cand_source_addr[] =
    { &cand_source_addr_value[0], &cand_source_addr_value[1] };
  /* Destination Address List: 2001:db8:1::1 or 198.51.100.121 */
  ip_addr_t dest_addr[] = {
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x1),
    IPADDR4_INIT_BYTES(198, 51, 100, 121)
  };
  ip_addr_t rev_dest_addr[] = { dest_addr[1], dest_addr[0] };
  /* Result: 198.51.100.121 (src 198.51.100.117) then 2001:db8:1::1 (src fe80::1) (prefer matching scope) */
  const ip_addr_t addr_expected[] = {
    IPADDR4_INIT_BYTES(198, 51, 100, 121),
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x1)
  };

  lwip_sortdestinationaddresses(dest_addr, 2, cand_source_addr, 2);

  fail_unless(memcmp(&dest_addr[0], &addr_expected[0], 16) == 0);
  fail_unless(memcmp(&dest_addr[1], &addr_expected[1], 16) == 0);

  lwip_sortdestinationaddresses(rev_dest_addr, 2, cand_source_addr, 2);

  fail_unless(memcmp(&rev_dest_addr[0], &addr_expected[0], 16) == 0);
  fail_unless(memcmp(&rev_dest_addr[1], &addr_expected[1], 16) == 0);
}
END_TEST

START_TEST(sort_dest_ex3_prefer_higher_precedence_1)
{
  /* Candidate Source Addresses: 2001:db8:1::2 or fe80::1 or 10.1.2.4 */
  ip_addr_t cand_source_addr_value[] = {
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x2),
    IPADDR6_INIT_HOST(0xfe800000, 0x0, 0x0, 0x1),
    IPADDR4_INIT_BYTES(10, 1, 2, 4)
  };
  ip_addr_t *cand_source_addr[] =
    { &cand_source_addr_value[0], &cand_source_addr_value[1], &cand_source_addr_value[2]};
  /* Destination Address List: 2001:db8:1::1 or 10.1.2.3 */
  ip_addr_t dest_addr[] = {
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x1),
    IPADDR4_INIT_BYTES(10, 1, 2, 3)
  };
  ip_addr_t rev_dest_addr[] = { dest_addr[1], dest_addr[0] };
  /* Result: 2001:db8:1::1 (src 2001:db8:1::2) then 10.1.2.3 (src 10.1.2.4) (prefer higher precedence) */
  const ip_addr_t addr_expected[] = {
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x1),
    IPADDR4_INIT_BYTES(10, 1, 2, 3)
  };

  lwip_sortdestinationaddresses(dest_addr, 2, cand_source_addr, 3);

  fail_unless(memcmp(&dest_addr[0], &addr_expected[0], 16) == 0);
  fail_unless(memcmp(&dest_addr[1], &addr_expected[1], 16) == 0);

  lwip_sortdestinationaddresses(rev_dest_addr, 2, cand_source_addr, 3);

  fail_unless(memcmp(&rev_dest_addr[0], &addr_expected[0], 16) == 0);
  fail_unless(memcmp(&rev_dest_addr[1], &addr_expected[1], 16) == 0);
}
END_TEST

START_TEST(sort_dest_ex4_prefer_smaller_scope)
{
  /* Candidate Source Addresses: 2001:db8:1::2 or fe80::2 */
  ip_addr_t cand_source_addr_value[] = {
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x2),
    IPADDR6_INIT_HOST(0xfe800000, 0x0, 0x0, 0x2)
  };
  ip_addr_t *cand_source_addr[] =
    { &cand_source_addr_value[0], &cand_source_addr_value[1] };
  /* Destination Address List: 2001:db8:1::1 or fe80::1 */
  ip_addr_t dest_addr[] = {
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x1),
    IPADDR6_INIT_HOST(0xfe800000, 0x0, 0x0, 0x1)
  };
  ip_addr_t rev_dest_addr[] = { dest_addr[1], dest_addr[0] };
  /* Result: fe80::1 (src fe80::2) then 2001:db8:1::1 (src 2001:db8:1::2) (prefer smaller scope) */
  const ip_addr_t addr_expected[] = {
    IPADDR6_INIT_HOST(0xfe800000, 0x0, 0x0, 0x1),
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x1)
  };

  lwip_sortdestinationaddresses(dest_addr, 2, cand_source_addr, 2);

  fail_unless(memcmp(&dest_addr[0], &addr_expected[0], 16) == 0);
  fail_unless(memcmp(&dest_addr[1], &addr_expected[1], 16) == 0);

  lwip_sortdestinationaddresses(rev_dest_addr, 2, cand_source_addr, 2);

  fail_unless(memcmp(&rev_dest_addr[0], &addr_expected[0], 16) == 0);
  fail_unless(memcmp(&rev_dest_addr[1], &addr_expected[1], 16) == 0);
}
END_TEST

/* Example 5: Prefer home address -- not implemented */

/* Example 6: Avoid deprecated addresses -- not implemented */

/* Example 7: Longest matching prefix -- not implemented */

/* Example 8: Prefer matching label -- not fully implemented, only handles IPv4 label vs IPv6 */

START_TEST(sort_dest_ex9_prefer_higher_precedence_2)
{
  /* Candidate Source Addresses: 2002:c633:6401::2 or 2001:db8:1::2 or fe80::2 */
  ip_addr_t cand_source_addr_value[] = {
    IPADDR6_INIT_HOST(0x2002c633, 0x64010000, 0x0, 0x2),
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x2),
    IPADDR6_INIT_HOST(0xfe800000, 0x0, 0x0, 0x2)
  };
  ip_addr_t *cand_source_addr[] =
    { &cand_source_addr_value[0], &cand_source_addr_value[1], &cand_source_addr_value[2]};
  /* Destination Address List: 2002:c633:6401::1 or 2001:db8:1::1 */
  ip_addr_t dest_addr[] = {
    IPADDR6_INIT_HOST(0x2002c633, 0x64010000, 0x0, 0x1),
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x1)
  };
  ip_addr_t rev_dest_addr[] = { dest_addr[1], dest_addr[0] };
  /* Result: 2001:db8:1::1 (src 2001:db8:1::2) then 2002:c633:6401::1 (src 2002:c633:6401::2) (prefer higher precedence) */
  const ip_addr_t addr_expected[] = {
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x1),
    IPADDR6_INIT_HOST(0x2002c633, 0x64010000, 0x0, 0x1)
  };

  lwip_sortdestinationaddresses(dest_addr, 2, cand_source_addr, 3);

  fail_unless(memcmp(&dest_addr[0], &addr_expected[0], 16) == 0);
  fail_unless(memcmp(&dest_addr[1], &addr_expected[1], 16) == 0);

  lwip_sortdestinationaddresses(rev_dest_addr, 2, cand_source_addr, 3);

  fail_unless(memcmp(&rev_dest_addr[0], &addr_expected[0], 16) == 0);
  fail_unless(memcmp(&rev_dest_addr[1], &addr_expected[1], 16) == 0);
}
END_TEST

/* Test cases for bug #65583, https://savannah.nongnu.org/bugs/?65583 */

START_TEST(sort_dest_ipv6_source_dual_stack_destination)
{
  /* Only have IPv6 source addresses available (global and link-local) */
  ip_addr_t cand_source_addr_value[] = {
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x2),
    IPADDR6_INIT_HOST(0xfe800000, 0x0, 0x0, 0x2)
  };
  ip_addr_t *cand_source_addr[] =
    { &cand_source_addr_value[0], &cand_source_addr_value[1] };
  /* Destination is a dual stack host */
  ip_addr_t dest_addr[] = {
    IPADDR4_INIT_BYTES(198, 51, 100, 121),
    IPADDR6_INIT_HOST(0x20010db8, 0x20000, 0x0, 0x1)
  };
  ip_addr_t rev_dest_addr[] = { dest_addr[1], dest_addr[0] };
  /* Should return the IPv6 address as first result */
  const ip_addr_t addr_expected[] = {
    IPADDR6_INIT_HOST(0x20010db8, 0x20000, 0x0, 0x1),
    IPADDR4_INIT_BYTES(198, 51, 100, 121),
  };

  lwip_sortdestinationaddresses(dest_addr, 2, cand_source_addr, 2);

  fail_unless(memcmp(&dest_addr[0], &addr_expected[0], 16) == 0);
  fail_unless(memcmp(&dest_addr[1], &addr_expected[1], 16) == 0);

  lwip_sortdestinationaddresses(rev_dest_addr, 2, cand_source_addr, 2);

  fail_unless(memcmp(&rev_dest_addr[0], &addr_expected[0], 16) == 0);
  fail_unless(memcmp(&rev_dest_addr[1], &addr_expected[1], 16) == 0);
}
END_TEST

START_TEST(sort_dest_ipv6_source_nat64_destination)
{
  /* Only have IPv6 source addresses available (global and link-local) */
  ip_addr_t cand_source_addr_value[] = {
    IPADDR6_INIT_HOST(0x20010db8, 0x10000, 0x0, 0x2),
    IPADDR6_INIT_HOST(0xfe800000, 0x0, 0x0, 0x2)
  };
  ip_addr_t *cand_source_addr[] =
    { &cand_source_addr_value[0], &cand_source_addr_value[1] };
  /* Destination is an IPv4-only host, but have DNS64 so get a NAT64 result as well */
  ip_addr_t dest_addr[] = {
    IPADDR4_INIT_BYTES(198, 51, 100, 121),
    IPADDR6_INIT_HOST(0x64FF9B, 0x0, 0x0, 0xC6336479)
  };
  ip_addr_t rev_dest_addr[] = { dest_addr[1], dest_addr[0] };
  /* Should return the NAT64 address as first result */
  const ip_addr_t addr_expected[] = {
    IPADDR6_INIT_HOST(0x64FF9B, 0x0, 0x0, 0xC6336479),
    IPADDR4_INIT_BYTES(198, 51, 100, 121)
  };

  lwip_sortdestinationaddresses(dest_addr, 2, cand_source_addr, 2);

  fail_unless(memcmp(&dest_addr[0], &addr_expected[0], 16) == 0);
  fail_unless(memcmp(&dest_addr[1], &addr_expected[1], 16) == 0);

  lwip_sortdestinationaddresses(rev_dest_addr, 2, cand_source_addr, 2);

  fail_unless(memcmp(&rev_dest_addr[0], &addr_expected[0], 16) == 0);
  fail_unless(memcmp(&rev_dest_addr[1], &addr_expected[1], 16) == 0);
}
END_TEST

#endif /* LWIP_IPV4 && LWIP_IPV6 */

/** Create the suite including all tests for this module */
Suite *
dns_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_dns_set_get_server)
#if LWIP_IPV4 && LWIP_IPV6  /* allow to build the unit tests without IPv6 support */
    ,TESTFUNC(sort_dest_ex1_prefer_matching_scope_1)
    ,TESTFUNC(sort_dest_ex2_prefer_matching_scope_2)
    ,TESTFUNC(sort_dest_ex3_prefer_higher_precedence_1)
    ,TESTFUNC(sort_dest_ex4_prefer_smaller_scope)
    ,TESTFUNC(sort_dest_ex9_prefer_higher_precedence_2)
    ,TESTFUNC(sort_dest_ipv6_source_dual_stack_destination)
    ,TESTFUNC(sort_dest_ipv6_source_nat64_destination)
#endif /* LWIP_IPV4 && LWIP_IPV6 */
  };
  return create_suite("DNS", tests, sizeof(tests)/sizeof(testfunc), dns_setup, dns_teardown);
}
