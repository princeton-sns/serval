#ifndef _HASH_H_
#define _HASH_H_
/* Fast hashing routine for ints,  longs and pointers.
   (C) 2002 William Lee Irwin III, IBM */

/*
 * Knuth recommends primes in approximately golden ratio to the maximum
 * integer representable by a machine word for multiplicative hashing.
 * Chuck Lever verified the effectiveness of this technique:
 * http://www.citi.umich.edu/techreports/reports/citi-tr-00-1.pdf
 *
 * These primes are chosen to be bit-sparse, that is operations on
 * them can use shifts and additions instead of multiplications for
 * machines where multiplications are slow.
 */

/* Taken from linux kernel and slightly modified. */
#include "platform.h"
#include <stdint.h>

#if defined(__BIONIC__)
#if __SIZEOF_LONG__ == 8
#define __WORDSIZE 64
#elif __SIZEOF_LONG__ == 4
#define __WORDSIZE 32
#endif
#endif

/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define GOLDEN_RATIO_PRIME_32 0x9e370001UL
/*  2^63 + 2^61 - 2^57 + 2^54 - 2^51 - 2^18 + 1 */
#define GOLDEN_RATIO_PRIME_64 0x9e37fffffffc0001UL

#if __WORDSIZE == 32
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_PRIME_32
#define hash_long(val, bits) hash_32(val, bits)
#elif __WORDSIZE == 64
#define hash_long(val, bits) hash_64(val, bits)
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_PRIME_64
#else
#error Wordsize not 32 or 64
#endif

static inline u64 hash_64(u64 val, unsigned int bits)
{
	u64 hash = val;

	/*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
	u64 n = hash;
	n <<= 18;
	hash -= n;
	n <<= 33;
	hash -= n;
	n <<= 3;
	hash += n;
	n <<= 3;
	hash -= n;
	n <<= 4;
	hash += n;
	n <<= 2;
	hash += n;

	/* High bits are more random, so use them. */
	return hash >> (64 - bits);
}

static inline u32 hash_32(u32 val, unsigned int bits)
{
	/* On some cpus multiply is faster, on others gcc will do shifts */
	u32 hash = val * GOLDEN_RATIO_PRIME_32;

	/* High bits are more random, so use them. */
	return hash >> (32 - bits);
}

static inline unsigned long hash_ptr(void *ptr, unsigned int bits)
{
	return hash_long((unsigned long)ptr, bits);
}

/* Name hashing routines. Initial hash value */
/* Hash courtesy of the R5 hash in reiserfs modulo sign bits */
#define init_name_hash()		0

/* partial hash update function. Assume roughly 4 bits per character */
static inline unsigned long
partial_name_hash(unsigned long c, unsigned long prevhash)
{
	return (prevhash + (c << 4) + (c >> 4)) * 11;
}

/*
 * Finally: cut down the number of bits to a int value (and try to avoid
 * losing bits)
 */
static inline unsigned long end_name_hash(unsigned long hash)
{
	return (unsigned int) hash;
}

/* Compute the hash for a name string. */
static inline unsigned long
full_name_hash(const char *name, unsigned int len)
{
	unsigned long hash = init_name_hash();
	while (len--)
		hash = partial_name_hash(*name++, hash);
	return end_name_hash(hash);
}

/* Compute the hash for the bitprefix of a binary data structure. 
   The num_bits argument is the size of the prefix to use in bits. */
static inline unsigned long
full_bitstring_hash(const void *bits_in, unsigned int num_bits)
{
	const unsigned char *bits = (const unsigned char *)bits_in;
	unsigned int len = num_bits / 8;
	unsigned long hash = init_name_hash();
	
	/* Compute the number of bits in the last byte to hash */
	num_bits -= (len * 8);

	/* Hash up to the last byte. */
	while (len--)
		hash = partial_name_hash(*bits++, hash);
	
	/* Hash the bits of the last byte if necessary */
	if (num_bits) {
		/* We need to mask off the last bits to use and hash those */
		unsigned char last_bits = (0xff << (8 - num_bits)) & *bits;
		partial_name_hash(last_bits, hash);
	}
	return end_name_hash(hash);
}

#endif /* _HASH_H */
