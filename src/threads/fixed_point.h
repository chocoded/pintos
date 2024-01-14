/** This file is used to simulate fix point number operation.
 * Writing MACROS but not FUNCTIONS is to reduce function call,
 * while this could lead to more bugs, since we have no type check.
 * An xxx.h file requires no update in Makefile. This is quite nice:) */

#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

typedef long long fp_t;

/* Lower fractional bits */
#define FP_SHIFT_AMOUNT 14

/**
 * X is fixed-point
 * N is integer
 */

/* Convert between fp and int. */
#define INT2FP(N) ((fp_t)((N) << (FP_SHIFT_AMOUNT)))
#define FP2INT_ZERO(X) ((X) >> (FP_SHIFT_AMOUNT))
#define FP2INT_ROUND(X) ((X >= 0) ? (((X) + (1 << (FP_SHIFT_AMOUNT - 1))) >> (FP_SHIFT_AMOUNT)) : (((X) - (1 << (FP_SHIFT_AMOUNT - 1))) >> (FP_SHIFT_AMOUNT)))

/* Addition and subtraction. */
#define FP_ADD(X, Y) ((X) + (Y))
#define FP_SUB(X, Y) ((X) - (Y))
#define FP_ADD_INT(X, N) ((X) + ((N) << (FP_SHIFT_AMOUNT)))
#define FP_SUB_INT(X, N) ((X) - ((N) << (FP_SHIFT_AMOUNT)))

/* Multiplication and Division. */
#define FP_MULT(X, Y) (((fp_t)(X)) * (Y) >> (FP_SHIFT_AMOUNT))
#define FP_MULT_INT(X, N) ((X) * (N))
#define FP_DIV(X, Y) ((((fp_t)(X)) << (FP_SHIFT_AMOUNT)) / (Y))
#define FP_DIV_INT(X, N) ((X) / (N))

#endif