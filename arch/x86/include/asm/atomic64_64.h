/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_ATOMIC64_64_H
#define _ASM_X86_ATOMIC64_64_H

#include <linux/types.h>
#include <asm/alternative.h>
#include <asm/cmpxchg.h>

/* The 64-bit atomic type */

#define ATOMIC64_INIT(i)	{ (i) }

/**
<<<<<<< HEAD
 * arch_atomic64_read - read atomic64 variable
=======
 * atomic64_read - read atomic64 variable
>>>>>>> v4.14.187
 * @v: pointer of type atomic64_t
 *
 * Atomically reads the value of @v.
 * Doesn't imply a read memory barrier.
 */
<<<<<<< HEAD
static inline long arch_atomic64_read(const atomic64_t *v)
=======
static inline long atomic64_read(const atomic64_t *v)
>>>>>>> v4.14.187
{
	return READ_ONCE((v)->counter);
}

/**
<<<<<<< HEAD
 * arch_atomic64_set - set atomic64 variable
=======
 * atomic64_set - set atomic64 variable
>>>>>>> v4.14.187
 * @v: pointer to type atomic64_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
<<<<<<< HEAD
static inline void arch_atomic64_set(atomic64_t *v, long i)
=======
static inline void atomic64_set(atomic64_t *v, long i)
>>>>>>> v4.14.187
{
	WRITE_ONCE(v->counter, i);
}

/**
<<<<<<< HEAD
 * arch_atomic64_add - add integer to atomic64 variable
=======
 * atomic64_add - add integer to atomic64 variable
>>>>>>> v4.14.187
 * @i: integer value to add
 * @v: pointer to type atomic64_t
 *
 * Atomically adds @i to @v.
 */
<<<<<<< HEAD
static __always_inline void arch_atomic64_add(long i, atomic64_t *v)
=======
static __always_inline void atomic64_add(long i, atomic64_t *v)
>>>>>>> v4.14.187
{
	asm volatile(LOCK_PREFIX "addq %1,%0"
		     : "=m" (v->counter)
		     : "er" (i), "m" (v->counter) : "memory");
}

/**
<<<<<<< HEAD
 * arch_atomic64_sub - subtract the atomic64 variable
=======
 * atomic64_sub - subtract the atomic64 variable
>>>>>>> v4.14.187
 * @i: integer value to subtract
 * @v: pointer to type atomic64_t
 *
 * Atomically subtracts @i from @v.
 */
<<<<<<< HEAD
static inline void arch_atomic64_sub(long i, atomic64_t *v)
=======
static inline void atomic64_sub(long i, atomic64_t *v)
>>>>>>> v4.14.187
{
	asm volatile(LOCK_PREFIX "subq %1,%0"
		     : "=m" (v->counter)
		     : "er" (i), "m" (v->counter) : "memory");
}

/**
<<<<<<< HEAD
 * arch_atomic64_sub_and_test - subtract value from variable and test result
=======
 * atomic64_sub_and_test - subtract value from variable and test result
>>>>>>> v4.14.187
 * @i: integer value to subtract
 * @v: pointer to type atomic64_t
 *
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
<<<<<<< HEAD
static inline bool arch_atomic64_sub_and_test(long i, atomic64_t *v)
=======
static inline bool atomic64_sub_and_test(long i, atomic64_t *v)
>>>>>>> v4.14.187
{
	GEN_BINARY_RMWcc(LOCK_PREFIX "subq", v->counter, "er", i, "%0", e);
}

/**
<<<<<<< HEAD
 * arch_atomic64_inc - increment atomic64 variable
=======
 * atomic64_inc - increment atomic64 variable
>>>>>>> v4.14.187
 * @v: pointer to type atomic64_t
 *
 * Atomically increments @v by 1.
 */
<<<<<<< HEAD
static __always_inline void arch_atomic64_inc(atomic64_t *v)
=======
static __always_inline void atomic64_inc(atomic64_t *v)
>>>>>>> v4.14.187
{
	asm volatile(LOCK_PREFIX "incq %0"
		     : "=m" (v->counter)
		     : "m" (v->counter) : "memory");
}

/**
<<<<<<< HEAD
 * arch_atomic64_dec - decrement atomic64 variable
=======
 * atomic64_dec - decrement atomic64 variable
>>>>>>> v4.14.187
 * @v: pointer to type atomic64_t
 *
 * Atomically decrements @v by 1.
 */
<<<<<<< HEAD
static __always_inline void arch_atomic64_dec(atomic64_t *v)
=======
static __always_inline void atomic64_dec(atomic64_t *v)
>>>>>>> v4.14.187
{
	asm volatile(LOCK_PREFIX "decq %0"
		     : "=m" (v->counter)
		     : "m" (v->counter) : "memory");
}

/**
<<<<<<< HEAD
 * arch_atomic64_dec_and_test - decrement and test
=======
 * atomic64_dec_and_test - decrement and test
>>>>>>> v4.14.187
 * @v: pointer to type atomic64_t
 *
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */
<<<<<<< HEAD
static inline bool arch_atomic64_dec_and_test(atomic64_t *v)
=======
static inline bool atomic64_dec_and_test(atomic64_t *v)
>>>>>>> v4.14.187
{
	GEN_UNARY_RMWcc(LOCK_PREFIX "decq", v->counter, "%0", e);
}

/**
<<<<<<< HEAD
 * arch_atomic64_inc_and_test - increment and test
=======
 * atomic64_inc_and_test - increment and test
>>>>>>> v4.14.187
 * @v: pointer to type atomic64_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
<<<<<<< HEAD
static inline bool arch_atomic64_inc_and_test(atomic64_t *v)
=======
static inline bool atomic64_inc_and_test(atomic64_t *v)
>>>>>>> v4.14.187
{
	GEN_UNARY_RMWcc(LOCK_PREFIX "incq", v->counter, "%0", e);
}

/**
<<<<<<< HEAD
 * arch_atomic64_add_negative - add and test if negative
=======
 * atomic64_add_negative - add and test if negative
>>>>>>> v4.14.187
 * @i: integer value to add
 * @v: pointer to type atomic64_t
 *
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.
 */
<<<<<<< HEAD
static inline bool arch_atomic64_add_negative(long i, atomic64_t *v)
=======
static inline bool atomic64_add_negative(long i, atomic64_t *v)
>>>>>>> v4.14.187
{
	GEN_BINARY_RMWcc(LOCK_PREFIX "addq", v->counter, "er", i, "%0", s);
}

/**
<<<<<<< HEAD
 * arch_atomic64_add_return - add and return
=======
 * atomic64_add_return - add and return
>>>>>>> v4.14.187
 * @i: integer value to add
 * @v: pointer to type atomic64_t
 *
 * Atomically adds @i to @v and returns @i + @v
 */
<<<<<<< HEAD
static __always_inline long arch_atomic64_add_return(long i, atomic64_t *v)
=======
static __always_inline long atomic64_add_return(long i, atomic64_t *v)
>>>>>>> v4.14.187
{
	return i + xadd(&v->counter, i);
}

<<<<<<< HEAD
static inline long arch_atomic64_sub_return(long i, atomic64_t *v)
{
	return arch_atomic64_add_return(-i, v);
}

static inline long arch_atomic64_fetch_add(long i, atomic64_t *v)
=======
static inline long atomic64_sub_return(long i, atomic64_t *v)
{
	return atomic64_add_return(-i, v);
}

static inline long atomic64_fetch_add(long i, atomic64_t *v)
>>>>>>> v4.14.187
{
	return xadd(&v->counter, i);
}

<<<<<<< HEAD
static inline long arch_atomic64_fetch_sub(long i, atomic64_t *v)
=======
static inline long atomic64_fetch_sub(long i, atomic64_t *v)
>>>>>>> v4.14.187
{
	return xadd(&v->counter, -i);
}

<<<<<<< HEAD
#define arch_atomic64_inc_return(v)  (arch_atomic64_add_return(1, (v)))
#define arch_atomic64_dec_return(v)  (arch_atomic64_sub_return(1, (v)))

static inline long arch_atomic64_cmpxchg(atomic64_t *v, long old, long new)
{
	return arch_cmpxchg(&v->counter, old, new);
}

#define arch_atomic64_try_cmpxchg arch_atomic64_try_cmpxchg
static __always_inline bool arch_atomic64_try_cmpxchg(atomic64_t *v, s64 *old, long new)
=======
#define atomic64_inc_return(v)  (atomic64_add_return(1, (v)))
#define atomic64_dec_return(v)  (atomic64_sub_return(1, (v)))

static inline long atomic64_cmpxchg(atomic64_t *v, long old, long new)
{
	return cmpxchg(&v->counter, old, new);
}

#define atomic64_try_cmpxchg atomic64_try_cmpxchg
static __always_inline bool atomic64_try_cmpxchg(atomic64_t *v, s64 *old, long new)
>>>>>>> v4.14.187
{
	return try_cmpxchg(&v->counter, old, new);
}

<<<<<<< HEAD
static inline long arch_atomic64_xchg(atomic64_t *v, long new)
{
	return arch_xchg(&v->counter, new);
}

/**
 * arch_atomic64_add_unless - add unless the number is a given value
=======
static inline long atomic64_xchg(atomic64_t *v, long new)
{
	return xchg(&v->counter, new);
}

/**
 * atomic64_add_unless - add unless the number is a given value
>>>>>>> v4.14.187
 * @v: pointer of type atomic64_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as it was not @u.
 * Returns the old value of @v.
 */
<<<<<<< HEAD
static inline bool arch_atomic64_add_unless(atomic64_t *v, long a, long u)
{
	s64 c = arch_atomic64_read(v);
	do {
		if (unlikely(c == u))
			return false;
	} while (!arch_atomic64_try_cmpxchg(v, &c, c + a));
	return true;
}

#define arch_atomic64_inc_not_zero(v) arch_atomic64_add_unless((v), 1, 0)

/*
 * arch_atomic64_dec_if_positive - decrement by 1 if old value positive
=======
static inline bool atomic64_add_unless(atomic64_t *v, long a, long u)
{
	s64 c = atomic64_read(v);
	do {
		if (unlikely(c == u))
			return false;
	} while (!atomic64_try_cmpxchg(v, &c, c + a));
	return true;
}

#define atomic64_inc_not_zero(v) atomic64_add_unless((v), 1, 0)

/*
 * atomic64_dec_if_positive - decrement by 1 if old value positive
>>>>>>> v4.14.187
 * @v: pointer of type atomic_t
 *
 * The function returns the old value of *v minus 1, even if
 * the atomic variable, v, was not decremented.
 */
<<<<<<< HEAD
static inline long arch_atomic64_dec_if_positive(atomic64_t *v)
{
	s64 dec, c = arch_atomic64_read(v);
=======
static inline long atomic64_dec_if_positive(atomic64_t *v)
{
	s64 dec, c = atomic64_read(v);
>>>>>>> v4.14.187
	do {
		dec = c - 1;
		if (unlikely(dec < 0))
			break;
<<<<<<< HEAD
	} while (!arch_atomic64_try_cmpxchg(v, &c, dec));
	return dec;
}

static inline void arch_atomic64_and(long i, atomic64_t *v)
=======
	} while (!atomic64_try_cmpxchg(v, &c, dec));
	return dec;
}

static inline void atomic64_and(long i, atomic64_t *v)
>>>>>>> v4.14.187
{
	asm volatile(LOCK_PREFIX "andq %1,%0"
			: "+m" (v->counter)
			: "er" (i)
			: "memory");
}

<<<<<<< HEAD
static inline long arch_atomic64_fetch_and(long i, atomic64_t *v)
{
	s64 val = arch_atomic64_read(v);

	do {
	} while (!arch_atomic64_try_cmpxchg(v, &val, val & i));
	return val;
}

static inline void arch_atomic64_or(long i, atomic64_t *v)
=======
static inline long atomic64_fetch_and(long i, atomic64_t *v)
{
	s64 val = atomic64_read(v);

	do {
	} while (!atomic64_try_cmpxchg(v, &val, val & i));
	return val;
}

static inline void atomic64_or(long i, atomic64_t *v)
>>>>>>> v4.14.187
{
	asm volatile(LOCK_PREFIX "orq %1,%0"
			: "+m" (v->counter)
			: "er" (i)
			: "memory");
}

<<<<<<< HEAD
static inline long arch_atomic64_fetch_or(long i, atomic64_t *v)
{
	s64 val = arch_atomic64_read(v);

	do {
	} while (!arch_atomic64_try_cmpxchg(v, &val, val | i));
	return val;
}

static inline void arch_atomic64_xor(long i, atomic64_t *v)
=======
static inline long atomic64_fetch_or(long i, atomic64_t *v)
{
	s64 val = atomic64_read(v);

	do {
	} while (!atomic64_try_cmpxchg(v, &val, val | i));
	return val;
}

static inline void atomic64_xor(long i, atomic64_t *v)
>>>>>>> v4.14.187
{
	asm volatile(LOCK_PREFIX "xorq %1,%0"
			: "+m" (v->counter)
			: "er" (i)
			: "memory");
}

<<<<<<< HEAD
static inline long arch_atomic64_fetch_xor(long i, atomic64_t *v)
{
	s64 val = arch_atomic64_read(v);

	do {
	} while (!arch_atomic64_try_cmpxchg(v, &val, val ^ i));
=======
static inline long atomic64_fetch_xor(long i, atomic64_t *v)
{
	s64 val = atomic64_read(v);

	do {
	} while (!atomic64_try_cmpxchg(v, &val, val ^ i));
>>>>>>> v4.14.187
	return val;
}

#endif /* _ASM_X86_ATOMIC64_64_H */
